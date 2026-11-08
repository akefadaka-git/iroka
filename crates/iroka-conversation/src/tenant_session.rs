//! Trusted server-side tenant directory and bounded application sessions.

use rusqlite::{params, Connection, OptionalExtension};
use std::sync::Mutex;

use crate::{ConversationError, SessionGuard, TenantMembership};

const MAX_MEMBERSHIP_AGE: u64 = 300;
const MAX_SESSION_TTL: u64 = 1_800;

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

pub struct SqliteSessionRegistry {
    db: Mutex<Connection>,
}
impl SqliteSessionRegistry {
    pub fn open(path: &str) -> Result<Self, ConversationError> {
        let db = Connection::open(path).map_err(|_| ConversationError::StorageUnavailable)?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS app_sessions(
          session_id TEXT PRIMARY KEY NOT NULL,subject TEXT NOT NULL,tenant_id TEXT NOT NULL,
          credential_id TEXT NOT NULL,issued_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,
          revocation_version INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);",
        )
        .map_err(|_| ConversationError::StorageUnavailable)?;
        Ok(Self { db: Mutex::new(db) })
    }
    pub fn open_in_memory() -> Result<Self, ConversationError> {
        let db = Connection::open_in_memory().map_err(|_| ConversationError::StorageUnavailable)?;
        db.execute_batch(
            "CREATE TABLE app_sessions(
          session_id TEXT PRIMARY KEY NOT NULL,subject TEXT NOT NULL,tenant_id TEXT NOT NULL,
          credential_id TEXT NOT NULL,issued_at INTEGER NOT NULL,expires_at INTEGER NOT NULL,
          revocation_version INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);",
        )
        .map_err(|_| ConversationError::StorageUnavailable)?;
        Ok(Self { db: Mutex::new(db) })
    }
    /// Register a session ID minted by a trusted cryptographic session issuer.
    /// The caller must not accept caller-chosen IDs or extend a session beyond this cap.
    pub fn register(
        &self,
        session_id: &str,
        subject: &str,
        tenant: &str,
        credential_id: &str,
        issued_at: u64,
        expires_at: u64,
        revocation_version: u64,
    ) -> Result<(), ConversationError> {
        if [session_id, subject, tenant, credential_id]
            .iter()
            .any(|v| v.trim().is_empty())
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
            "INSERT INTO app_sessions(session_id,subject,tenant_id,credential_id,
          issued_at,expires_at,revocation_version,revoked) VALUES(?1,?2,?3,?4,?5,?6,?7,0)",
            params![
                session_id,
                subject,
                tenant,
                credential_id,
                issued_at as i64,
                expires_at as i64,
                revocation_version as i64
            ],
        )
        .map_err(|_| ConversationError::Conflict)?;
        Ok(())
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
        tenant: &str,
        session_id: &str,
        now: u64,
    ) -> Result<(), ConversationError> {
        let db = self
            .db
            .lock()
            .map_err(|_| ConversationError::SessionInvalid)?;
        let row:Option<(String,String,u64,u64,bool)>=db.query_row(
          "SELECT subject,tenant_id,issued_at,expires_at,revoked FROM app_sessions WHERE session_id=?1",
          params![session_id],|r|Ok((r.get(0)?,r.get(1)?,r.get::<_,i64>(2)? as u64,
             r.get::<_,i64>(3)? as u64,r.get::<_,i64>(4)?!=0)))
          .optional().map_err(|_|ConversationError::SessionInvalid)?;
        match row {
            Some((s, t, issued, expires, revoked))
                if s == subject
                    && t == tenant
                    && !revoked
                    && expires > issued
                    && now >= issued
                    && now < expires
                    && expires - issued <= MAX_SESSION_TTL =>
            {
                Ok(())
            }
            _ => Err(ConversationError::SessionInvalid),
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
        let sessions = SqliteSessionRegistry::open_in_memory().unwrap();
        assert_eq!(
            sessions.register("s1", "subject:1", "tenant:a", "cred:1", 100, 1_900, 1),
            Ok(())
        );
        assert_eq!(
            sessions.validate("subject:1", "tenant:a", "s1", 200),
            Ok(())
        );
        assert_eq!(
            sessions.validate("subject:other", "tenant:a", "s1", 200),
            Err(ConversationError::SessionInvalid)
        );
        assert_eq!(sessions.revoke("s1"), Ok(()));
        assert_eq!(
            sessions.validate("subject:1", "tenant:a", "s1", 200),
            Err(ConversationError::SessionInvalid)
        );
        assert_eq!(
            sessions.register("s2", "subject:1", "tenant:a", "cred:1", 100, 5_000, 1),
            Err(ConversationError::InvalidInput)
        );
    }
}
