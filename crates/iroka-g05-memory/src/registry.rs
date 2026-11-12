//! G05-owned episodic-consent persistence only.
//!
//! Organization reviewer designation, delegation, revocation and approval
//! authority are deliberately absent from this registry. Those decisions are
//! resolved by G02; cryptographic reviewer proof is verified by G01.
use crate::{EpisodicConsentAuthority, G05Error, Purpose};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct SqliteG05AuthorityRegistry {
    pub(crate) connection: Arc<Mutex<Connection>>,
}

impl SqliteG05AuthorityRegistry {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, G05Error> {
        let connection = Connection::open(path).map_err(|_| G05Error::AuthorityUnavailable)?;
        Self::from_connection(connection)
    }

    pub fn open_in_memory() -> Result<Self, G05Error> {
        let connection = Connection::open_in_memory().map_err(|_| G05Error::AuthorityUnavailable)?;
        Self::from_connection(connection)
    }

    fn from_connection(connection: Connection) -> Result<Self, G05Error> {
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON;
                 PRAGMA journal_mode=WAL;
                 PRAGMA synchronous=FULL;
                 CREATE TABLE IF NOT EXISTS g05_episodic_consents(
                   consent_ref TEXT PRIMARY KEY,
                   tenant_ref TEXT NOT NULL,
                   subject_ref TEXT NOT NULL,
                   purpose TEXT NOT NULL,
                   grant_issuer TEXT NOT NULL,
                   grant_credential_id TEXT NOT NULL,
                   granted_at INTEGER NOT NULL,
                   expires_at INTEGER NOT NULL,
                   revoked_at INTEGER,
                   version INTEGER NOT NULL CHECK(version>0),
                   action_ref TEXT NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS g05_consent_scope
                   ON g05_episodic_consents(tenant_ref,subject_ref,purpose);",
            )
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Store only G05-owned episodic opt-in. This API cannot create or alter
    /// organization roles, reviewer designations or delegations.
    #[allow(clippy::too_many_arguments)]
    pub fn grant_episodic_consent(
        &self,
        consent_ref: &str,
        tenant_ref: &str,
        subject_ref: &str,
        purpose: Purpose,
        issuer: &str,
        credential_id: &str,
        granted_at: u64,
        expires_at: u64,
        action_ref: &str,
    ) -> Result<(), G05Error> {
        if [consent_ref, tenant_ref, subject_ref, issuer, credential_id, action_ref]
            .iter()
            .any(|v| v.trim().is_empty() || v.len() > 512)
            || granted_at >= expires_at
        {
            return Err(G05Error::MalformedRecord);
        }
        let c = self.connection.lock().map_err(|_| G05Error::AuthorityUnavailable)?;
        c.execute(
            "INSERT INTO g05_episodic_consents
             (consent_ref,tenant_ref,subject_ref,purpose,grant_issuer,grant_credential_id,
              granted_at,expires_at,revoked_at,version,action_ref)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,NULL,1,?9)",
            params![consent_ref,tenant_ref,subject_ref,purpose_key(purpose),issuer,credential_id,
                to_i64(granted_at)?,to_i64(expires_at)?,action_ref],
        )
        .map_err(|_| G05Error::DuplicateRecord)?;
        Ok(())
    }

    pub fn revoke_episodic_consent(
        &self,
        consent_ref: &str,
        tenant_ref: &str,
        subject_ref: &str,
        now: u64,
    ) -> Result<(), G05Error> {
        let c = self.connection.lock().map_err(|_| G05Error::AuthorityUnavailable)?;
        let changed = c.execute(
            "UPDATE g05_episodic_consents SET revoked_at=?1,version=version+1
             WHERE consent_ref=?2 AND tenant_ref=?3 AND subject_ref=?4 AND revoked_at IS NULL",
            params![to_i64(now)?,consent_ref,tenant_ref,subject_ref],
        ).map_err(|_| G05Error::AuthorityUnavailable)?;
        if changed != 1 { return Err(G05Error::EpisodicOptInRequired); }
        Ok(())
    }
}

impl EpisodicConsentAuthority for SqliteG05AuthorityRegistry {
    fn verify_active_opt_in(
        &self,
        reference: &str,
        tenant: &str,
        subject: &str,
        purpose: Purpose,
        now: u64,
    ) -> Result<(), G05Error> {
        let c = self.connection.lock().map_err(|_| G05Error::AuthorityUnavailable)?;
        let row: Option<(String,String,String,i64,i64,Option<i64>)> = c.query_row(
            "SELECT tenant_ref,subject_ref,purpose,granted_at,expires_at,revoked_at
             FROM g05_episodic_consents WHERE consent_ref=?1",
            [reference],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
        ).optional().map_err(|_| G05Error::AuthorityUnavailable)?;
        let (t,s,p,g,e,revoked) = row.ok_or(G05Error::EpisodicOptInRequired)?;
        if t != tenant || s != subject || p != purpose_key(purpose) {
            return Err(G05Error::ConsentScopeMismatch);
        }
        if revoked.is_some() || now < from_i64(g)? || now >= from_i64(e)? {
            return Err(G05Error::EpisodicOptInRequired);
        }
        Ok(())
    }
}

fn purpose_key(p: Purpose) -> &'static str {
    match p {
        Purpose::TaskContinuity => "TASK_CONTINUITY",
        Purpose::UserPreference => "USER_PREFERENCE",
        Purpose::ProjectContext => "PROJECT_CONTEXT",
        Purpose::OrganizationalContext => "ORGANIZATIONAL_CONTEXT",
        Purpose::OperationalHistory => "OPERATIONAL_HISTORY",
        Purpose::AuthorizedSystemAssurance => "AUTHORIZED_SYSTEM_ASSURANCE",
    }
}
fn to_i64(v: u64) -> Result<i64, G05Error> {
    i64::try_from(v).map_err(|_| G05Error::MalformedRecord)
}
fn from_i64(v: i64) -> Result<u64, G05Error> {
    u64::try_from(v).map_err(|_| G05Error::AuthorityUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g05_registry_does_not_create_local_reviewer_authority() {
        let registry = SqliteG05AuthorityRegistry::open_in_memory().unwrap();
        let connection = registry.connection.lock().unwrap();
        let count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='g05_reviewer_designations'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 0);
    }
}
