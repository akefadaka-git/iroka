//! Trusted server-side tenant directory and bounded application sessions.

use rusqlite::{params, Connection, OptionalExtension};
use std::sync::{Arc, Mutex};

use crate::{ConversationError, SessionGuard, TenantMembership};
use iroka_kernel::{RevocationChecker, SqliteSecurityStore, VerifiedPrincipal};

const MAX_MEMBERSHIP_AGE: u64 = 300;
const MAX_SESSION_TTL: u64 = 1_800;
type SessionRow = (String, String, String, String, String, u64, u64, u64, bool);

pub struct SqliteTenantDirectory {
    db: Mutex<Connection>,
}
impl SqliteTenantDirectory {
    pub fn open(path: &str) -> Result<Self, ConversationError> {
        let db = Connection::open(path).map_err(|_| ConversationError::StorageUnavailable)?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS tenant_memberships(
          subject TEXT NOT NULL,tenant_id TEXT NOT NULL,state TEXT NOT NULL,
          version INTEGER NOT NULL,checked_at INTEGER NOT NULL,
          PRIMARY KEY(subject,tenant_id));",
        )
        .map_err(|_| ConversationError::StorageUnavailable)?;
        Ok(Self { db: Mutex::new(db) })
    }
    pub fn open_in_memory() -> Result<Self, ConversationError> {
        let db = Connection::open_in_memory().map_err(|_| ConversationError::StorageUnavailable)?;
        db.execute_batch(
            "CREATE TABLE tenant_memberships(
          subject TEXT NOT NULL,tenant_id TEXT NOT NULL,state TEXT NOT NULL,
          version INTEGER NOT NULL,checked_at INTEGER NOT NULL,
          PRIMARY KEY(subject,tenant_id));",
        )
        .map_err(|_| ConversationError::StorageUnavailable)?;
        Ok(Self { db: Mutex::new(db) })
    }
    /// Provision/refresh from the authoritative membership source only.
    /// Never expose this operation to an HTTP request or model adapter.
    pub fn provision_membership(
        &self,
        subject: &str,
        tenant: &str,
        state: &str,
        version: u64,
        checked_at: u64,
    ) -> Result<(), ConversationError> {
        if subject.trim().is_empty()
            || tenant.trim().is_empty()
            || !["active", "suspended", "revoked"].contains(&state)
            || version == 0
        {
            return Err(ConversationError::InvalidInput);
        }
        let db = self
            .db
            .lock()
            .map_err(|_| ConversationError::StorageUnavailable)?;
        db.execute(
            "INSERT INTO tenant_memberships(subject,tenant_id,state,version,checked_at)
          VALUES(?1,?2,?3,?4,?5) ON CONFLICT(subject,tenant_id) DO UPDATE SET
          state=excluded.state,version=excluded.version,checked_at=excluded.checked_at",
            params![subject, tenant, state, version as i64, checked_at as i64],
        )
        .map_err(|_| ConversationError::StorageUnavailable)?;
        Ok(())
    }
}
impl TenantMembership for SqliteTenantDirectory {
    fn resolve_active_tenant(&self, subject: &str, now: u64) -> Result<String, ConversationError> {
        let db = self
            .db
            .lock()
            .map_err(|_| ConversationError::TenantUnavailable)?;
        let mut stmt = db
            .prepare("SELECT tenant_id,state,checked_at FROM tenant_memberships WHERE subject=?1")
            .map_err(|_| ConversationError::TenantUnavailable)?;
        let rows = stmt
            .query_map(params![subject], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)? as u64,
                ))
            })
            .map_err(|_| ConversationError::TenantUnavailable)?;
        let mut active = Vec::new();
        for row in rows {
            let (tenant, state, checked_at) =
                row.map_err(|_| ConversationError::TenantUnavailable)?;
            if state == "active" {
                if checked_at > now || now.saturating_sub(checked_at) > MAX_MEMBERSHIP_AGE {
                    return Err(ConversationError::TenantUnavailable);
                }
                active.push(tenant);
            }
        }
        if active.len() != 1 {
            return Err(ConversationError::MembershipDenied);
        }
        Ok(active.remove(0))
    }
}

pub trait CredentialStatus: Send + Sync {
    /// Must consult the Kernel-backed revocation source and reject unavailable,
    /// revoked or version-mismatched credential/session state.
    fn ensure_active(
        &self,
        issuer: &str,
        credential_id: &str,
        key_id: &str,
        revocation_version: u64,
        now: u64,
    ) -> Result<(), ConversationError>;
}

pub struct KernelCredentialStatus<R: RevocationChecker> {
    checker: R,
}
impl<R: RevocationChecker> KernelCredentialStatus<R> {
    pub fn new(checker: R) -> Self {
        Self { checker }
    }
}
impl<R: RevocationChecker> CredentialStatus for KernelCredentialStatus<R> {
    fn ensure_active(
        &self,
        issuer: &str,
        credential_id: &str,
        key_id: &str,
        revocation_version: u64,
        _now: u64,
    ) -> Result<(), ConversationError> {
        if issuer.trim().is_empty()
            || credential_id.trim().is_empty()
            || key_id.trim().is_empty()
            || revocation_version == 0
        {
            return Err(ConversationError::SessionInvalid);
        }
        let key_revoked = self
            .checker
            .key_revoked(issuer, key_id)
            .map_err(|_| ConversationError::SessionInvalid)?;
        let credential_revoked = self
            .checker
            .credential_revoked(issuer, credential_id)
            .map_err(|_| ConversationError::SessionInvalid)?;
        let current_version = self
            .checker
            .current_version(issuer)
            .map_err(|_| ConversationError::SessionInvalid)?;
        if key_revoked
            || credential_revoked
            || current_version == 0
            || current_version != revocation_version
        {
            return Err(ConversationError::SessionInvalid);
        }
        Ok(())
    }
}

fn ensure_session_key_column(db: &Connection) -> Result<(), ConversationError> {
    let mut statement = db
        .prepare("PRAGMA table_info(app_sessions)")
        .map_err(|_| ConversationError::StorageUnavailable)?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|_| ConversationError::StorageUnavailable)?;
    let mut found = false;
    for column in columns {
        if column.map_err(|_| ConversationError::StorageUnavailable)? == "key_id" {
            found = true;
            break;
        }
    }
    drop(statement);
    if !found {
        db.execute_batch("ALTER TABLE app_sessions ADD COLUMN key_id TEXT NOT NULL DEFAULT ''")
            .map_err(|_| ConversationError::StorageUnavailable)?;
    }
    Ok(())
}

pub struct SqliteSessionRegistry {
    db: Mutex<Connection>,
    credential_status: Arc<dyn CredentialStatus>,
}
impl SqliteSessionRegistry {
    pub fn open(
        path: &str,
        credential_status: Arc<dyn CredentialStatus>,
    ) -> Result<Self, ConversationError> {
        let db = Connection::open(path).map_err(|_| ConversationError::StorageUnavailable)?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS app_sessions(
          session_id TEXT PRIMARY KEY NOT NULL,subject TEXT NOT NULL,tenant_id TEXT NOT NULL,
          issuer TEXT NOT NULL,credential_id TEXT NOT NULL,key_id TEXT NOT NULL DEFAULT '',issued_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,
          revocation_version INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);",
        )
        .map_err(|_| ConversationError::StorageUnavailable)?;
        ensure_session_key_column(&db)?;
        Ok(Self {
            db: Mutex::new(db),
            credential_status,
        })
    }
    pub fn open_with_kernel_store(
        path: &str,
        security_store: Arc<SqliteSecurityStore>,
    ) -> Result<Self, ConversationError> {
        let status: Arc<dyn CredentialStatus> =
            Arc::new(KernelCredentialStatus::new(security_store));
        Self::open(path, status)
    }

    pub fn open_in_memory_with_kernel_store(
        security_store: Arc<SqliteSecurityStore>,
    ) -> Result<Self, ConversationError> {
        let status: Arc<dyn CredentialStatus> =
            Arc::new(KernelCredentialStatus::new(security_store));
        Self::open_in_memory(status)
    }

    pub fn open_in_memory(
        credential_status: Arc<dyn CredentialStatus>,
    ) -> Result<Self, ConversationError> {
        let db = Connection::open_in_memory().map_err(|_| ConversationError::StorageUnavailable)?;
        db.execute_batch(
            "CREATE TABLE app_sessions(
          session_id TEXT PRIMARY KEY NOT NULL,subject TEXT NOT NULL,tenant_id TEXT NOT NULL,
          issuer TEXT NOT NULL,credential_id TEXT NOT NULL,key_id TEXT NOT NULL DEFAULT '',issued_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,
          revocation_version INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);",
        )
        .map_err(|_| ConversationError::StorageUnavailable)?;
        ensure_session_key_column(&db)?;
        Ok(Self {
            db: Mutex::new(db),
            credential_status,
        })
    }
    /// Register a session ID minted by a trusted cryptographic session issuer.
    /// The caller must not accept caller-chosen IDs or extend a session beyond this cap.
    #[allow(clippy::too_many_arguments)] // Explicitly binds session identity and lifetime at provisioning.
    fn register_fields(
        &self,
        session_id: &str,
        subject: &str,
        tenant: &str,
        issuer: &str,
        credential_id: &str,
        key_id: &str,
        issued_at: u64,
        expires_at: u64,
        revocation_version: u64,
    ) -> Result<(), ConversationError> {
        if [session_id, subject, tenant, credential_id]
            .iter()
            .any(|v| v.trim().is_empty())
            || key_id.trim().is_empty()
            || expires_at <= issued_at
            || expires_at - issued_at > MAX_SESSION_TTL
            || revocation_version == 0
        {
            return Err(ConversationError::InvalidInput);
        }
        let db = self
            .db
            .lock()
            .map_err(|_| ConversationError::StorageUnavailable)?;
        db.execute(
            "INSERT INTO app_sessions(session_id,subject,tenant_id,issuer,credential_id,key_id,
          issued_at,expires_at,revocation_version,revoked) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,0)",
            params![
                session_id,
                subject,
                tenant,
                issuer,
                credential_id,
                key_id,
                issued_at as i64,
                expires_at as i64,
                revocation_version as i64
            ],
        )
        .map_err(|_| ConversationError::Conflict)?;
        Ok(())
    }
    /// Register a bounded application session only from a cryptographically verified G01 principal.
    /// The session identifier must be freshly minted by the trusted session issuer.
    pub fn register_verified(
        &self,
        principal: &VerifiedPrincipal,
        session_id: &str,
        tenant: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<(), ConversationError> {
        if issued_at < principal.issued_at() || expires_at > principal.expires_at() {
            return Err(ConversationError::InvalidInput);
        }
        self.register_fields(
            session_id,
            principal.subject(),
            tenant,
            principal.issuer(),
            principal.credential_id(),
            principal.key_id(),
            issued_at,
            expires_at,
            principal.revocation_version(),
        )
    }

    pub fn revoke(&self, session_id: &str) -> Result<(), ConversationError> {
        let db = self
            .db
            .lock()
            .map_err(|_| ConversationError::StorageUnavailable)?;
        let n = db
            .execute(
                "UPDATE app_sessions SET revoked=1 WHERE session_id=?1",
                params![session_id],
            )
            .map_err(|_| ConversationError::StorageUnavailable)?;
        if n == 0 {
            return Err(ConversationError::SessionInvalid);
        }
        Ok(())
    }
}
impl SessionGuard for SqliteSessionRegistry {
    fn validate(
        &self,
        subject: &str,
        issuer: &str,
        credential_id: &str,
        key_id: &str,
        revocation_version: u64,
        credential_issued_at: u64,
        credential_expires_at: u64,
        tenant: &str,
        session_id: &str,
        now: u64,
    ) -> Result<(), ConversationError> {
        let db = self
            .db
            .lock()
            .map_err(|_| ConversationError::SessionInvalid)?;
        let row: Option<SessionRow> = db
            .query_row(
                "SELECT subject,tenant_id,issuer,credential_id,key_id,issued_at,expires_at,revocation_version,revoked
                 FROM app_sessions WHERE session_id=?1",
                params![session_id],
                |r| Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get::<_, i64>(5)? as u64,
                    r.get::<_, i64>(6)? as u64,
                    r.get::<_, i64>(7)? as u64,
                    r.get::<_, i64>(8)? != 0,
                )),
            )
            .optional()
            .map_err(|_| ConversationError::SessionInvalid)?;
        drop(db);
        let Some((
            stored_subject,
            stored_tenant,
            stored_issuer,
            stored_credential,
            stored_key_id,
            issued,
            expires,
            version,
            revoked,
        )) = row
        else {
            return Err(ConversationError::SessionInvalid);
        };
        if stored_subject != subject
            || stored_tenant != tenant
            || stored_issuer != issuer
            || stored_credential != credential_id
            || stored_key_id != key_id
            || version != revocation_version
            || now < credential_issued_at
            || now >= credential_expires_at
            || issued < credential_issued_at
            || expires > credential_expires_at
            || revoked
            || expires <= issued
            || now < issued
            || now >= expires
            || expires - issued > MAX_SESSION_TTL
        {
            return Err(ConversationError::SessionInvalid);
        }
        self.credential_status
            .ensure_active(issuer, key_id, credential_id, version, now)
    }
}

#[cfg(test)]
struct AllowTestCredential;
#[cfg(test)]
impl CredentialStatus for AllowTestCredential {
    fn ensure_active(
        &self,
        issuer: &str,
        credential_id: &str,
        key_id: &str,
        revocation_version: u64,
        _now: u64,
    ) -> Result<(), ConversationError> {
        if issuer == "issuer:1"
            && credential_id == "cred:1"
            && key_id == "key:1"
            && revocation_version == 1
        {
            Ok(())
        } else {
            Err(ConversationError::SessionInvalid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tenant_resolution_requires_one_fresh_active_membership() {
        let directory = SqliteTenantDirectory::open_in_memory().unwrap();
        directory
            .provision_membership("subject:1", "tenant:a", "active", 1, 100)
            .unwrap();
        assert_eq!(
            directory.resolve_active_tenant("subject:1", 200),
            Ok("tenant:a".into())
        );
        assert_eq!(
            directory.resolve_active_tenant("subject:1", 500),
            Err(ConversationError::TenantUnavailable)
        );
        directory
            .provision_membership("subject:1", "tenant:b", "active", 2, 200)
            .unwrap();
        assert_eq!(
            directory.resolve_active_tenant("subject:1", 210),
            Err(ConversationError::MembershipDenied)
        );
    }
    #[test]
    fn sessions_are_bounded_and_revocable() {
        let sessions =
            SqliteSessionRegistry::open_in_memory(Arc::new(AllowTestCredential)).unwrap();
        assert_eq!(
            sessions.register_fields(
                "s1",
                "subject:1",
                "tenant:a",
                "issuer:1",
                "cred:1",
                "key:1",
                100,
                1_900,
                1
            ),
            Ok(())
        );
        assert_eq!(
            sessions.validate(
                "subject:1",
                "issuer:1",
                "cred:1",
                "key:1",
                1,
                100,
                3600,
                "tenant:a",
                "s1",
                200
            ),
            Ok(())
        );
        assert_eq!(
            sessions.validate(
                "subject:other",
                "issuer:1",
                "cred:1",
                "key:1",
                1,
                100,
                3600,
                "tenant:a",
                "s1",
                200
            ),
            Err(ConversationError::SessionInvalid)
        );
        assert_eq!(sessions.revoke("s1"), Ok(()));
        assert_eq!(
            sessions.validate(
                "subject:1",
                "issuer:1",
                "cred:1",
                "key:1",
                1,
                "tenant:a",
                "s1",
                200
            ),
            Err(ConversationError::SessionInvalid)
        );
        assert_eq!(
            sessions.register_fields(
                "s2",
                "subject:1",
                "tenant:a",
                "issuer:1",
                "cred:1",
                "key:1",
                100,
                5_000,
                1
            ),
            Err(ConversationError::InvalidInput)
        );
    }
}
