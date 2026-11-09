//! Durable local security registry for trust rollback protection and revocation.
//! This SQLite adapter is intended for a single-node authority service. Multi-node
//! deployments must use a shared transactional database adapter with equivalent
//! uniqueness, durability and fail-closed semantics.

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::identity_crypto::{RevocationChecker, RevocationError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityStoreError {
    Unavailable,
    Rollback,
    ConflictingVersion,
    InvalidVersion,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApprovalConsumptionError {
    Store(SecurityStoreError),
    SigningKeyRevoked,
    ApprovalRevoked,
}

#[derive(Debug, Clone)]
pub(crate) enum RevocationTarget {
    Credential {
        issuer: String,
        credential_id: String,
        reason: String,
    },
    Key {
        issuer: String,
        key_id: String,
        reason: String,
    },
    Approval {
        approval_id: String,
        reason: String,
    },
    TenantMembership {
        subject: String,
        tenant_id: String,
        active: bool,
        version: u64,
        reason: String,
    },
}

pub(crate) struct ApprovalReceipt<'a> {
    pub approval_id: &'a str,
    pub payload_digest: &'a [u8],
    pub owner_subject: &'a str,
    pub signer_issuer: &'a str,
    pub signer_key_id: &'a str,
    pub request_subject: &'a str,
    pub capability: &'a str,
    pub resource: &'a str,
    pub policy_version: &'a str,
    pub issued_at: u64,
    pub expires_at: u64,
    pub consumed_at: u64,
}

pub struct SqliteSecurityStore {
    connection: Mutex<Connection>,
}

impl SqliteSecurityStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SecurityStoreError> {
        let path = path.as_ref();
        #[cfg(unix)]
        {
            use std::fs::{symlink_metadata, OpenOptions};
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            match symlink_metadata(path) {
                Ok(metadata) => {
                    if metadata.file_type().is_symlink()
                        || metadata.permissions().mode() & 0o077 != 0
                    {
                        return Err(SecurityStoreError::Unavailable);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path)
                        .map_err(|_| SecurityStoreError::Unavailable)?;
                }
                Err(_) => return Err(SecurityStoreError::Unavailable),
            }
        }
        let connection = Connection::open(path).map_err(|_| SecurityStoreError::Unavailable)?;
        Self::from_connection(connection)
    }

    pub fn open_in_memory() -> Result<Self, SecurityStoreError> {
        let connection =
            Connection::open_in_memory().map_err(|_| SecurityStoreError::Unavailable)?;
        Self::from_connection(connection)
    }

    fn from_connection(connection: Connection) -> Result<Self, SecurityStoreError> {
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|_| SecurityStoreError::Unavailable)?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             CREATE TABLE IF NOT EXISTS trust_bundle_history (
               version INTEGER PRIMARY KEY, digest BLOB NOT NULL, issued_at INTEGER NOT NULL,
               expires_at INTEGER NOT NULL, installed_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS security_command_log (
               command_id TEXT PRIMARY KEY, digest BLOB NOT NULL, owner_subject TEXT NOT NULL,
               signer_key_id TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
               reason TEXT NOT NULL, occurred_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS approval_receipts (
               approval_id TEXT PRIMARY KEY, payload_digest BLOB NOT NULL, owner_subject TEXT NOT NULL,
               signer_key_id TEXT NOT NULL, request_subject TEXT NOT NULL, capability TEXT NOT NULL,
               resource TEXT NOT NULL, policy_version TEXT NOT NULL, issued_at INTEGER NOT NULL,
               expires_at INTEGER NOT NULL, consumed_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS trust_bundle_state (
               singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
               version INTEGER NOT NULL,
               digest BLOB NOT NULL,
               issued_at INTEGER NOT NULL,
               expires_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS revoked_credentials (
               issuer TEXT NOT NULL, credential_id TEXT NOT NULL,
               revoked_at INTEGER NOT NULL, reason TEXT NOT NULL,
               PRIMARY KEY (issuer, credential_id)
             );
             CREATE TABLE IF NOT EXISTS revoked_keys (
               issuer TEXT NOT NULL, key_id TEXT NOT NULL,
               revoked_at INTEGER NOT NULL, reason TEXT NOT NULL,
               PRIMARY KEY (issuer, key_id)
             );
             CREATE TABLE IF NOT EXISTS revoked_approvals (
               approval_id TEXT PRIMARY KEY, revoked_at INTEGER NOT NULL, reason TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS approval_consumptions (
               approval_id TEXT PRIMARY KEY, scope_digest BLOB NOT NULL, consumed_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS tenant_memberships (
               subject TEXT NOT NULL, tenant_id TEXT NOT NULL,
               active INTEGER NOT NULL CHECK(active IN (0,1)),
               version INTEGER NOT NULL CHECK(version > 0),
               updated_at INTEGER NOT NULL, command_id TEXT NOT NULL,
               PRIMARY KEY(subject, tenant_id)
             );
             CREATE TABLE IF NOT EXISTS policy_snapshots (
               epoch INTEGER PRIMARY KEY CHECK(epoch > 0), digest BLOB NOT NULL CHECK(length(digest)=32),
               canonical_payload BLOB NOT NULL, signature BLOB NOT NULL,
               owner_subject TEXT NOT NULL, key_id TEXT NOT NULL, policy_version TEXT NOT NULL,
               issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
               emergency_stop_active INTEGER NOT NULL CHECK(emergency_stop_active IN (0,1)),
               state TEXT NOT NULL CHECK(state IN ('pending','active','superseded','revoked'))
             );
             CREATE TABLE IF NOT EXISTS policy_lifecycle_state (
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               highest_epoch INTEGER NOT NULL CHECK(highest_epoch >= 0),
               active_epoch INTEGER
             );
             INSERT OR IGNORE INTO policy_lifecycle_state(singleton,highest_epoch,active_epoch) VALUES(1,0,NULL);
             CREATE TABLE IF NOT EXISTS policy_revocations (
               policy_epoch INTEGER PRIMARY KEY, command_id TEXT NOT NULL UNIQUE,
               digest BLOB NOT NULL CHECK(length(digest)=32), owner_subject TEXT NOT NULL,
               key_id TEXT NOT NULL, reason TEXT NOT NULL, issued_at INTEGER NOT NULL,
               state TEXT NOT NULL CHECK(state IN ('pending','complete'))
             );"
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Persist the highest accepted, root-signed trust-bundle version.
    /// Same-version retries are idempotent only when the digest is identical.
    pub fn install_trust_bundle(
        &self,
        version: u64,
        digest: &[u8],
        issued_at: u64,
        expires_at: u64,
        installed_at: u64,
    ) -> Result<(), SecurityStoreError> {
        if version == 0 || issued_at >= expires_at || digest.len() != 32 {
            return Err(SecurityStoreError::InvalidVersion);
        }
        let version_i = i64::try_from(version).map_err(|_| SecurityStoreError::InvalidVersion)?;
        let issued_i = i64::try_from(issued_at).map_err(|_| SecurityStoreError::InvalidVersion)?;
        let expires_i =
            i64::try_from(expires_at).map_err(|_| SecurityStoreError::InvalidVersion)?;
        let installed_i =
            i64::try_from(installed_at).map_err(|_| SecurityStoreError::InvalidVersion)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let current: Option<(i64, Vec<u8>)> = tx
            .query_row(
                "SELECT version, digest FROM trust_bundle_state WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        match current {
            Some((current_version, _current_digest)) if version_i < current_version => {
                return Err(SecurityStoreError::Rollback)
            }
            Some((current_version, current_digest)) if version_i == current_version => {
                if current_digest != digest {
                    return Err(SecurityStoreError::ConflictingVersion);
                }
                tx.commit().map_err(|_| SecurityStoreError::Unavailable)?;
                return Ok(());
            }
            _ => {}
        }
        tx.execute(
            "INSERT INTO trust_bundle_state(singleton, version, digest, issued_at, expires_at)
             VALUES(1, ?1, ?2, ?3, ?4)
             ON CONFLICT(singleton) DO UPDATE SET version=excluded.version,
               digest=excluded.digest, issued_at=excluded.issued_at, expires_at=excluded.expires_at",
            params![version_i, digest, issued_i, expires_i]
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        tx.execute(
            "INSERT INTO trust_bundle_history(version, digest, issued_at, expires_at, installed_at) VALUES(?1, ?2, ?3, ?4, ?5)",
            params![version_i, digest, issued_i, expires_i, installed_i]
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        tx.commit().map_err(|_| SecurityStoreError::Unavailable)
    }

    pub fn trust_bundle_history_count(&self) -> Result<u64, SecurityStoreError> {
        let c = self
            .connection
            .lock()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let count: i64 = c
            .query_row("SELECT COUNT(*) FROM trust_bundle_history", [], |row| {
                row.get(0)
            })
            .map_err(|_| SecurityStoreError::Unavailable)?;
        u64::try_from(count).map_err(|_| SecurityStoreError::Unavailable)
    }

    pub fn highest_trust_bundle_version(&self) -> Result<Option<u64>, SecurityStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let version: Option<i64> = connection
            .query_row(
                "SELECT version FROM trust_bundle_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        version
            .map(|v| u64::try_from(v).map_err(|_| SecurityStoreError::Unavailable))
            .transpose()
    }

    #[cfg(test)]
    pub(crate) fn revoke_credential(
        &self,
        issuer: &str,
        credential_id: &str,
        at: u64,
        reason: &str,
    ) -> Result<(), SecurityStoreError> {
        if issuer.trim().is_empty() || credential_id.trim().is_empty() || reason.trim().is_empty() {
            return Err(SecurityStoreError::InvalidVersion);
        }
        let c = self
            .connection
            .lock()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        c.execute(
            "INSERT OR IGNORE INTO revoked_credentials VALUES(?1, ?2, ?3, ?4)",
            params![
                issuer,
                credential_id,
                i64::try_from(at).map_err(|_| SecurityStoreError::InvalidVersion)?,
                reason
            ],
        )
        .map(|_| ())
        .map_err(|_| SecurityStoreError::Unavailable)
    }

    #[cfg(test)]
    pub(crate) fn revoke_key(
        &self,
        issuer: &str,
        key_id: &str,
        at: u64,
        reason: &str,
    ) -> Result<(), SecurityStoreError> {
        if issuer.trim().is_empty() || key_id.trim().is_empty() || reason.trim().is_empty() {
            return Err(SecurityStoreError::InvalidVersion);
        }
        let c = self
            .connection
            .lock()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        c.execute(
            "INSERT OR IGNORE INTO revoked_keys VALUES(?1, ?2, ?3, ?4)",
            params![
                issuer,
                key_id,
                i64::try_from(at).map_err(|_| SecurityStoreError::InvalidVersion)?,
                reason
            ],
        )
        .map(|_| ())
        .map_err(|_| SecurityStoreError::Unavailable)
    }

    #[cfg(test)]
    pub(crate) fn revoke_approval(
        &self,
        approval_id: &str,
        at: u64,
        reason: &str,
    ) -> Result<(), SecurityStoreError> {
        if approval_id.trim().is_empty() || reason.trim().is_empty() {
            return Err(SecurityStoreError::InvalidVersion);
        }
        let c = self
            .connection
            .lock()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        c.execute(
            "INSERT OR IGNORE INTO revoked_approvals VALUES(?1, ?2, ?3)",
            params![
                approval_id,
                i64::try_from(at).map_err(|_| SecurityStoreError::InvalidVersion)?,
                reason
            ],
        )
        .map(|_| ())
        .map_err(|_| SecurityStoreError::Unavailable)
    }

    /// Atomically records a signed control command and its revocation effect.
    #[allow(clippy::too_many_arguments)] // Explicitly binds the signed command and target to one transaction.
    pub(crate) fn apply_signed_revocation(
        &self,
        command_id: &str,
        owner_subject: &str,
        signer_issuer: &str,
        signer_key_id: &str,
        digest: &[u8],
        at: u64,
        target: RevocationTarget,
    ) -> Result<bool, SecurityStoreError> {
        if command_id.trim().is_empty() || digest.len() != 32 {
            return Err(SecurityStoreError::InvalidVersion);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SecurityStoreError::Unavailable)?;
        // Serialize the final Owner-key revocation check with command consumption
        // and the protected mutation. A revocation racing this command must win
        // or follow a fully committed command; it cannot be bypassed by TOCTOU.
        let signer_revoked: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM revoked_keys WHERE issuer=?1 AND key_id=?2)",
                params![signer_issuer, signer_key_id],
                |row| row.get(0),
            )
            .map_err(|_| SecurityStoreError::Unavailable)?;
        if signer_revoked {
            return Err(SecurityStoreError::Revoked);
        }
        let changed = tx.execute(
            "INSERT OR IGNORE INTO approval_consumptions(approval_id, scope_digest, consumed_at) VALUES(?1, ?2, ?3)",
            params![format!("security-command:{command_id}"), digest, i64::try_from(at).map_err(|_| SecurityStoreError::InvalidVersion)?]
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        if changed == 0 {
            return Ok(false);
        }
        let (action_name, target_name, reason_text) = match &target {
            RevocationTarget::Credential {
                issuer,
                credential_id,
                reason,
            } => (
                "revoke_credential",
                format!("{issuer}:{credential_id}"),
                reason.clone(),
            ),
            RevocationTarget::Key {
                issuer,
                key_id,
                reason,
            } => (
                "revoke_signing_key",
                format!("{issuer}:{key_id}"),
                reason.clone(),
            ),
            RevocationTarget::Approval {
                approval_id,
                reason,
            } => ("revoke_approval", approval_id.clone(), reason.clone()),
            RevocationTarget::TenantMembership {
                subject,
                tenant_id,
                active,
                version,
                reason,
            } => (
                "set_tenant_membership",
                format!("{subject}:{tenant_id}:v{version}:active={active}"),
                reason.clone(),
            ),
        };
        match target {
            RevocationTarget::Credential {
                issuer,
                credential_id,
                reason,
            } => {
                tx.execute(
                    "INSERT OR IGNORE INTO revoked_credentials VALUES(?1, ?2, ?3, ?4)",
                    params![
                        issuer,
                        credential_id,
                        i64::try_from(at).map_err(|_| SecurityStoreError::InvalidVersion)?,
                        reason
                    ],
                )
                .map_err(|_| SecurityStoreError::Unavailable)?;
            }
            RevocationTarget::Key {
                issuer,
                key_id,
                reason,
            } => {
                tx.execute(
                    "INSERT OR IGNORE INTO revoked_keys VALUES(?1, ?2, ?3, ?4)",
                    params![
                        issuer,
                        key_id,
                        i64::try_from(at).map_err(|_| SecurityStoreError::InvalidVersion)?,
                        reason
                    ],
                )
                .map_err(|_| SecurityStoreError::Unavailable)?;
            }
            RevocationTarget::Approval {
                approval_id,
                reason,
            } => {
                tx.execute(
                    "INSERT OR IGNORE INTO revoked_approvals VALUES(?1, ?2, ?3)",
                    params![
                        approval_id,
                        i64::try_from(at).map_err(|_| SecurityStoreError::InvalidVersion)?,
                        reason
                    ],
                )
                .map_err(|_| SecurityStoreError::Unavailable)?;
            }
            RevocationTarget::TenantMembership {
                subject,
                tenant_id,
                active,
                version,
                reason: _,
            } => {
                let version_i =
                    i64::try_from(version).map_err(|_| SecurityStoreError::InvalidVersion)?;
                let current: Option<i64> = tx
                    .query_row(
                        "SELECT version FROM tenant_memberships WHERE subject=?1 AND tenant_id=?2",
                        params![subject, tenant_id],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|_| SecurityStoreError::Unavailable)?;
                if current.is_some_and(|current_version| version_i <= current_version) {
                    return Err(SecurityStoreError::Rollback);
                }
                tx.execute(
                    "INSERT INTO tenant_memberships(subject,tenant_id,active,version,updated_at,command_id)
                     VALUES(?1,?2,?3,?4,?5,?6)
                     ON CONFLICT(subject,tenant_id) DO UPDATE SET active=excluded.active,
                       version=excluded.version, updated_at=excluded.updated_at, command_id=excluded.command_id
                     WHERE excluded.version > tenant_memberships.version",
                    params![
                        subject,
                        tenant_id,
                        i64::from(active),
                        version_i,
                        i64::try_from(at).map_err(|_| SecurityStoreError::InvalidVersion)?,
                        command_id
                    ],
                )
                .map_err(|_| SecurityStoreError::Unavailable)?;
            }
        }
        tx.execute(
            "INSERT INTO security_command_log(command_id, digest, owner_subject, signer_key_id, action, target, reason, occurred_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![command_id, digest, owner_subject, signer_key_id, action_name, target_name, reason_text, i64::try_from(at).map_err(|_| SecurityStoreError::InvalidVersion)?]
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        tx.commit().map_err(|_| SecurityStoreError::Unavailable)?;
        Ok(true)
    }

    /// Persist a signed policy snapshot as pending. No policy becomes active here.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stage_policy_snapshot(
        &self, epoch: u64, digest: &[u8; 32], canonical_payload: &[u8], signature: &[u8],
        owner_subject: &str, key_id: &str, policy_version: &str,
        issued_at: u64, expires_at: u64, emergency_stop_active: bool,
    ) -> Result<(), SecurityStoreError> {
        if epoch == 0 || canonical_payload.is_empty() || signature.len() != 64
            || owner_subject.trim().is_empty() || key_id.trim().is_empty()
            || policy_version.trim().is_empty() || issued_at >= expires_at
        { return Err(SecurityStoreError::InvalidVersion); }
        let epoch_i = i64::try_from(epoch).map_err(|_| SecurityStoreError::InvalidVersion)?;
        let issued_i = i64::try_from(issued_at).map_err(|_| SecurityStoreError::InvalidVersion)?;
        let expires_i = i64::try_from(expires_at).map_err(|_| SecurityStoreError::InvalidVersion)?;
        let mut connection = self.connection.lock().map_err(|_| SecurityStoreError::Unavailable)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let revoked: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_keys WHERE issuer='iroka:owner-authority' AND key_id=?1)",
            [key_id], |row| row.get(0),
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        if revoked { return Err(SecurityStoreError::Revoked); }
        let highest: i64 = tx.query_row(
            "SELECT highest_epoch FROM policy_lifecycle_state WHERE singleton=1", [], |row| row.get(0),
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        if epoch_i < highest { return Err(SecurityStoreError::Rollback); }
        if epoch_i == highest {
            let existing: (Vec<u8>, String) = tx.query_row(
                "SELECT digest,state FROM policy_snapshots WHERE epoch=?1", [epoch_i],
                |row| Ok((row.get(0)?,row.get(1)?)),
            ).map_err(|_| SecurityStoreError::Unavailable)?;
            if existing.0.as_slice() != digest { return Err(SecurityStoreError::ConflictingVersion); }
            if existing.1 == "revoked" { return Err(SecurityStoreError::Revoked); }
            tx.commit().map_err(|_| SecurityStoreError::Unavailable)?;
            return Ok(());
        }
        let pending: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM policy_snapshots WHERE state='pending')", [], |row| row.get(0),
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        if pending { return Err(SecurityStoreError::ConflictingVersion); }
        tx.execute(
            "INSERT INTO policy_snapshots(epoch,digest,canonical_payload,signature,owner_subject,key_id,policy_version,issued_at,expires_at,emergency_stop_active,state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'pending')",
            params![epoch_i,digest.as_slice(),canonical_payload,signature,owner_subject,key_id,policy_version,issued_i,expires_i,i64::from(emergency_stop_active)],
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        tx.execute(
            "UPDATE policy_lifecycle_state SET highest_epoch=?1 WHERE singleton=1", [epoch_i],
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        tx.commit().map_err(|_| SecurityStoreError::Unavailable)
    }

    /// Make a pending snapshot active only after the caller has obtained G11 confirmation.
    pub(crate) fn activate_policy_snapshot(
        &self, epoch: u64, digest: &[u8; 32], _now: u64,
    ) -> Result<(), SecurityStoreError> {
        let epoch_i = i64::try_from(epoch).map_err(|_| SecurityStoreError::InvalidVersion)?;
        let mut connection = self.connection.lock().map_err(|_| SecurityStoreError::Unavailable)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let existing: (Vec<u8>, String, String) = tx.query_row(
            "SELECT digest,state,key_id FROM policy_snapshots WHERE epoch=?1", [epoch_i],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        if existing.0.as_slice() != digest { return Err(SecurityStoreError::ConflictingVersion); }
        let revoked: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_keys WHERE issuer='iroka:owner-authority' AND key_id=?1)",
            [&existing.2], |row| row.get(0),
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        if revoked { return Err(SecurityStoreError::Revoked); }
        if existing.1 == "active" {
            tx.commit().map_err(|_| SecurityStoreError::Unavailable)?;
            return Ok(());
        }
        if existing.1 != "pending" { return Err(SecurityStoreError::Rollback); }
        let active: Option<i64> = tx.query_row(
            "SELECT active_epoch FROM policy_lifecycle_state WHERE singleton=1", [], |row| row.get(0),
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        if active.is_some_and(|current| epoch_i <= current) { return Err(SecurityStoreError::Rollback); }
        tx.execute("UPDATE policy_snapshots SET state='superseded' WHERE state='active'", [])
            .map_err(|_| SecurityStoreError::Unavailable)?;
        tx.execute("UPDATE policy_snapshots SET state='active' WHERE epoch=?1 AND state='pending'", [epoch_i])
            .map_err(|_| SecurityStoreError::Unavailable)?;
        tx.execute("UPDATE policy_lifecycle_state SET active_epoch=?1 WHERE singleton=1", [epoch_i])
            .map_err(|_| SecurityStoreError::Unavailable)?;
        tx.commit().map_err(|_| SecurityStoreError::Unavailable)
    }

    /// Stage an Owner-signed policy revocation; it has no effect until G11 confirms it.
    pub(crate) fn stage_policy_revocation(
        &self, epoch: u64, command_id: &str, digest: &[u8; 32], owner_subject: &str,
        key_id: &str, reason: &str, issued_at: u64,
    ) -> Result<(), SecurityStoreError> {
        if epoch == 0 || command_id.trim().is_empty() || owner_subject.trim().is_empty()
            || key_id.trim().is_empty() || reason.trim().is_empty()
        { return Err(SecurityStoreError::InvalidVersion); }
        let epoch_i = i64::try_from(epoch).map_err(|_| SecurityStoreError::InvalidVersion)?;
        let issued_i = i64::try_from(issued_at).map_err(|_| SecurityStoreError::InvalidVersion)?;
        let mut connection = self.connection.lock().map_err(|_| SecurityStoreError::Unavailable)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let revoked: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_keys WHERE issuer='iroka:owner-authority' AND key_id=?1)",
            [key_id], |row| row.get(0),
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        if revoked { return Err(SecurityStoreError::Revoked); }
        let active: Option<i64> = tx.query_row(
            "SELECT active_epoch FROM policy_lifecycle_state WHERE singleton=1", [], |row| row.get(0),
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        if active != Some(epoch_i) { return Err(SecurityStoreError::Rollback); }
        let existing: Option<(i64,Vec<u8>,String)> = tx.query_row(
            "SELECT policy_epoch,digest,state FROM policy_revocations WHERE command_id=?1", [command_id],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).optional().map_err(|_| SecurityStoreError::Unavailable)?;
        if let Some((existing_epoch, existing_digest, _)) = existing {
            if existing_epoch != epoch_i || existing_digest.as_slice() != digest {
                return Err(SecurityStoreError::ConflictingVersion);
            }
            tx.commit().map_err(|_| SecurityStoreError::Unavailable)?;
            return Ok(());
        }
        tx.execute(
            "INSERT INTO policy_revocations(policy_epoch,command_id,digest,owner_subject,key_id,reason,issued_at,state) VALUES(?1,?2,?3,?4,?5,?6,?7,'pending')",
            params![epoch_i,command_id,digest.as_slice(),owner_subject,key_id,reason,issued_i],
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        tx.commit().map_err(|_| SecurityStoreError::Unavailable)
    }

    /// Complete a staged revocation only after the deterministic G11 event is confirmed.
    pub(crate) fn complete_policy_revocation(
        &self, epoch: u64, command_id: &str, digest: &[u8; 32],
    ) -> Result<(), SecurityStoreError> {
        let epoch_i = i64::try_from(epoch).map_err(|_| SecurityStoreError::InvalidVersion)?;
        let mut connection = self.connection.lock().map_err(|_| SecurityStoreError::Unavailable)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let (stored_digest,state): (Vec<u8>,String) = tx.query_row(
            "SELECT digest,state FROM policy_revocations WHERE policy_epoch=?1 AND command_id=?2",
            params![epoch_i,command_id], |row| Ok((row.get(0)?,row.get(1)?)),
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        if stored_digest.as_slice() != digest { return Err(SecurityStoreError::ConflictingVersion); }
        if state == "complete" {
            tx.commit().map_err(|_| SecurityStoreError::Unavailable)?;
            return Ok(());
        }
        let active: Option<i64> = tx.query_row(
            "SELECT active_epoch FROM policy_lifecycle_state WHERE singleton=1", [], |row| row.get(0),
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        if active != Some(epoch_i) { return Err(SecurityStoreError::Rollback); }
        tx.execute("UPDATE policy_snapshots SET state='revoked' WHERE epoch=?1 AND state='active'", [epoch_i])
            .map_err(|_| SecurityStoreError::Unavailable)?;
        tx.execute("UPDATE policy_lifecycle_state SET active_epoch=NULL WHERE singleton=1", [])
            .map_err(|_| SecurityStoreError::Unavailable)?;
        tx.execute("UPDATE policy_revocations SET state='complete' WHERE policy_epoch=?1", [epoch_i])
            .map_err(|_| SecurityStoreError::Unavailable)?;
        tx.commit().map_err(|_| SecurityStoreError::Unavailable)
    }

    pub(crate) fn active_policy_snapshot(
        &self,
    ) -> Result<Option<(u64, crate::SignedPolicySnapshot)>, SecurityStoreError> {
        let connection = self.connection.lock().map_err(|_| SecurityStoreError::Unavailable)?;
        let epoch: Option<i64> = connection.query_row(
            "SELECT active_epoch FROM policy_lifecycle_state WHERE singleton=1", [], |row| row.get(0),
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        let Some(epoch) = epoch else { return Ok(None); };
        let (payload_bytes, signature): (Vec<u8>, Vec<u8>) = connection.query_row(
            "SELECT canonical_payload,signature FROM policy_snapshots WHERE epoch=?1 AND state='active'", [epoch],
            |row| Ok((row.get(0)?,row.get(1)?)),
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        let payload: crate::PolicySnapshotPayload = serde_json::from_slice(&payload_bytes)
            .map_err(|_| SecurityStoreError::Unavailable)?;
        Ok(Some((u64::try_from(epoch).map_err(|_| SecurityStoreError::Unavailable)?,
            crate::SignedPolicySnapshot::from_signature(payload, signature))))
    }

    pub(crate) fn tenant_membership(
        &self,
        subject: &str,
        tenant_id: &str,
    ) -> Result<Option<(bool, u64, u64)>, SecurityStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let row: Option<(i64, i64, i64)> = connection
            .query_row(
                "SELECT active, version, updated_at FROM tenant_memberships WHERE subject=?1 AND tenant_id=?2",
                params![subject, tenant_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        row.map(|(active, version, updated_at)| {
            Ok((
                active == 1,
                u64::try_from(version).map_err(|_| SecurityStoreError::Unavailable)?,
                u64::try_from(updated_at).map_err(|_| SecurityStoreError::Unavailable)?,
            ))
        })
        .transpose()
    }

    pub fn security_command_count(&self) -> Result<u64, SecurityStoreError> {
        let c = self
            .connection
            .lock()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let count: i64 = c
            .query_row("SELECT COUNT(*) FROM security_command_log", [], |row| {
                row.get(0)
            })
            .map_err(|_| SecurityStoreError::Unavailable)?;
        u64::try_from(count).map_err(|_| SecurityStoreError::Unavailable)
    }

    pub fn approval_receipt_count(&self) -> Result<u64, SecurityStoreError> {
        let c = self
            .connection
            .lock()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let count: i64 = c
            .query_row("SELECT COUNT(*) FROM approval_receipts", [], |row| {
                row.get(0)
            })
            .map_err(|_| SecurityStoreError::Unavailable)?;
        u64::try_from(count).map_err(|_| SecurityStoreError::Unavailable)
    }

    pub fn approval_is_revoked(&self, approval_id: &str) -> Result<bool, SecurityStoreError> {
        let c = self
            .connection
            .lock()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        c.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_approvals WHERE approval_id=?1)",
            [approval_id],
            |row| row.get(0),
        )
        .map_err(|_| SecurityStoreError::Unavailable)
    }

    /// Atomically consume an approval identifier exactly once.
    pub(crate) fn consume_approval(
        &self,
        receipt: ApprovalReceipt<'_>,
    ) -> Result<bool, ApprovalConsumptionError> {
        if receipt.approval_id.trim().is_empty() || receipt.payload_digest.len() != 32 {
            return Err(ApprovalConsumptionError::Store(
                SecurityStoreError::InvalidVersion,
            ));
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ApprovalConsumptionError::Store(SecurityStoreError::Unavailable))?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ApprovalConsumptionError::Store(SecurityStoreError::Unavailable))?;

        // Serialize final revocation checks with the single-use approval insert.
        // A racing revocation either commits first and blocks consumption, or
        // commits after this transaction has legitimately consumed the approval.
        let signer_revoked: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM revoked_keys WHERE issuer=?1 AND key_id=?2)",
                params![receipt.signer_issuer, receipt.signer_key_id],
                |row| row.get(0),
            )
            .map_err(|_| ApprovalConsumptionError::Store(SecurityStoreError::Unavailable))?;
        if signer_revoked {
            return Err(ApprovalConsumptionError::SigningKeyRevoked);
        }
        let approval_revoked: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM revoked_approvals WHERE approval_id=?1)",
                [receipt.approval_id],
                |row| row.get(0),
            )
            .map_err(|_| ApprovalConsumptionError::Store(SecurityStoreError::Unavailable))?;
        if approval_revoked {
            return Err(ApprovalConsumptionError::ApprovalRevoked);
        }

        let consumed_at = i64::try_from(receipt.consumed_at)
            .map_err(|_| ApprovalConsumptionError::Store(SecurityStoreError::InvalidVersion))?;
        let issued_at = i64::try_from(receipt.issued_at)
            .map_err(|_| ApprovalConsumptionError::Store(SecurityStoreError::InvalidVersion))?;
        let expires_at = i64::try_from(receipt.expires_at)
            .map_err(|_| ApprovalConsumptionError::Store(SecurityStoreError::InvalidVersion))?;
        let changed = tx.execute(
            "INSERT OR IGNORE INTO approval_consumptions(approval_id, scope_digest, consumed_at) VALUES(?1, ?2, ?3)",
            params![receipt.approval_id, receipt.payload_digest, consumed_at]
        ).map_err(|_| ApprovalConsumptionError::Store(SecurityStoreError::Unavailable))?;
        if changed == 0 {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO approval_receipts(approval_id, payload_digest, owner_subject, signer_key_id, request_subject, capability, resource, policy_version, issued_at, expires_at, consumed_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                receipt.approval_id, receipt.payload_digest, receipt.owner_subject, receipt.signer_key_id,
                receipt.request_subject, receipt.capability, receipt.resource, receipt.policy_version,
                issued_at, expires_at, consumed_at
            ]
        ).map_err(|_| ApprovalConsumptionError::Store(SecurityStoreError::Unavailable))?;
        tx.commit()
            .map_err(|_| ApprovalConsumptionError::Store(SecurityStoreError::Unavailable))?;
        Ok(true)
    }
}

impl RevocationChecker for SqliteSecurityStore {
    fn credential_revoked(
        &self,
        issuer: &str,
        credential_id: &str,
    ) -> Result<bool, RevocationError> {
        let c = self
            .connection
            .lock()
            .map_err(|_| RevocationError::Unavailable)?;
        c.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_credentials WHERE issuer=?1 AND credential_id=?2)",
            params![issuer, credential_id],
            |row| row.get(0),
        )
        .map_err(|_| RevocationError::Unavailable)
    }

    fn key_revoked(&self, issuer: &str, key_id: &str) -> Result<bool, RevocationError> {
        let c = self
            .connection
            .lock()
            .map_err(|_| RevocationError::Unavailable)?;
        c.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_keys WHERE issuer=?1 AND key_id=?2)",
            params![issuer, key_id],
            |row| row.get(0),
        )
        .map_err(|_| RevocationError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_versions_are_monotonic_and_idempotent() {
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        assert_eq!(store.install_trust_bundle(1, &[1; 32], 10, 100, 11), Ok(()));
        assert_eq!(store.install_trust_bundle(1, &[1; 32], 10, 100, 11), Ok(()));
        assert_eq!(store.highest_trust_bundle_version(), Ok(Some(1)));
        assert_eq!(store.trust_bundle_history_count(), Ok(1));
        assert_eq!(
            store.install_trust_bundle(1, &[2; 32], 10, 100, 11),
            Err(SecurityStoreError::ConflictingVersion)
        );
        assert_eq!(
            store.install_trust_bundle(0, &[2; 32], 10, 100, 11),
            Err(SecurityStoreError::InvalidVersion)
        );
        assert_eq!(store.install_trust_bundle(2, &[2; 32], 20, 200, 21), Ok(()));
        assert_eq!(
            store.install_trust_bundle(1, &[1; 32], 10, 100, 11),
            Err(SecurityStoreError::Rollback)
        );
    }

    #[test]
    fn revocations_are_durable_and_scoped() {
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        store
            .revoke_credential("issuer:a", "cred:1", 10, "compromised")
            .unwrap();
        store
            .revoke_key("issuer:a", "key:1", 10, "compromised")
            .unwrap();
        assert_eq!(store.credential_revoked("issuer:a", "cred:1"), Ok(true));
        assert_eq!(store.credential_revoked("issuer:b", "cred:1"), Ok(false));
        assert_eq!(store.key_revoked("issuer:a", "key:1"), Ok(true));
    }

    #[test]
    fn approvals_are_single_use_and_revocable() {
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        assert_eq!(
            store.consume_approval(ApprovalReceipt {
                approval_id: "approval:1",
                payload_digest: &[3; 32],
                owner_subject: "owner:test",
                signer_issuer: "iroka:owner-authority",
                signer_key_id: "owner-key",
                request_subject: "principal:test",
                capability: "records.read",
                resource: "records:1",
                policy_version: "policy:v1",
                issued_at: 10,
                expires_at: 100,
                consumed_at: 20,
            }),
            Ok(true)
        );
        assert_eq!(
            store.consume_approval(ApprovalReceipt {
                approval_id: "approval:1",
                payload_digest: &[3; 32],
                owner_subject: "owner:test",
                signer_issuer: "iroka:owner-authority",
                signer_key_id: "owner-key",
                request_subject: "principal:test",
                capability: "records.read",
                resource: "records:1",
                policy_version: "policy:v1",
                issued_at: 10,
                expires_at: 100,
                consumed_at: 21,
            }),
            Ok(false)
        );
        assert_eq!(store.approval_receipt_count(), Ok(1));
        store
            .revoke_approval("approval:2", 22, "withdrawn")
            .unwrap();
        assert_eq!(store.approval_is_revoked("approval:2"), Ok(true));
    }
    #[test]
    fn approval_consumption_rechecks_signing_key_revocation_atomically() {
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        store
            .revoke_key("iroka:owner-authority", "owner-key", 19, "compromised")
            .unwrap();
        let result = store.consume_approval(ApprovalReceipt {
            approval_id: "approval:key-revoked",
            payload_digest: &[4; 32],
            owner_subject: "owner:test",
            signer_issuer: "iroka:owner-authority",
            signer_key_id: "owner-key",
            request_subject: "principal:test",
            capability: "records.read",
            resource: "records:1",
            policy_version: "policy:v1",
            issued_at: 10,
            expires_at: 100,
            consumed_at: 20,
        });
        assert_eq!(result, Err(ApprovalConsumptionError::SigningKeyRevoked));
        assert_eq!(store.approval_receipt_count(), Ok(0));
    }

    #[test]
    fn approval_consumption_rechecks_approval_revocation_atomically() {
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        store
            .revoke_approval("approval:revoked", 19, "withdrawn")
            .unwrap();
        let result = store.consume_approval(ApprovalReceipt {
            approval_id: "approval:revoked",
            payload_digest: &[5; 32],
            owner_subject: "owner:test",
            signer_issuer: "iroka:owner-authority",
            signer_key_id: "owner-key",
            request_subject: "principal:test",
            capability: "records.read",
            resource: "records:1",
            policy_version: "policy:v1",
            issued_at: 10,
            expires_at: 100,
            consumed_at: 20,
        });
        assert_eq!(result, Err(ApprovalConsumptionError::ApprovalRevoked));
        assert_eq!(store.approval_receipt_count(), Ok(0));
    }

    #[test]
    fn concurrent_key_revocation_and_approval_consumption_are_serializable() {
        use std::fs;
        use std::sync::{Arc, Barrier};
        use std::thread;

        let path =
            std::env::temp_dir().join(format!("iroka-security-race-{}.sqlite", std::process::id()));
        let _ = fs::remove_file(&path);
        let revoker = SqliteSecurityStore::open(&path).unwrap();
        let consumer = SqliteSecurityStore::open(&path).unwrap();
        let barrier = Arc::new(Barrier::new(3));

        let revoke_barrier = Arc::clone(&barrier);
        let revoke_thread = thread::spawn(move || {
            revoke_barrier.wait();
            revoker.revoke_key(
                "iroka:owner-authority",
                "owner-key-race",
                19,
                "concurrent compromise",
            )
        });

        let consume_barrier = Arc::clone(&barrier);
        let consume_thread = thread::spawn(move || {
            consume_barrier.wait();
            consumer.consume_approval(ApprovalReceipt {
                approval_id: "approval:concurrent-race",
                payload_digest: &[6; 32],
                owner_subject: "owner:test",
                signer_issuer: "iroka:owner-authority",
                signer_key_id: "owner-key-race",
                request_subject: "principal:test",
                capability: "records.read",
                resource: "records:1",
                policy_version: "policy:v1",
                issued_at: 10,
                expires_at: 100,
                consumed_at: 20,
            })
        });

        barrier.wait();
        revoke_thread.join().unwrap().unwrap();
        let consumption = consume_thread.join().unwrap();

        let verifier = SqliteSecurityStore::open(&path).unwrap();
        assert_eq!(
            verifier.key_revoked("iroka:owner-authority", "owner-key-race"),
            Ok(true)
        );
        match consumption {
            Ok(true) => assert_eq!(verifier.approval_receipt_count(), Ok(1)),
            Err(ApprovalConsumptionError::SigningKeyRevoked) => {
                assert_eq!(verifier.approval_receipt_count(), Ok(0));
            }
            other => panic!("unexpected concurrent consumption result: {other:?}"),
        }

        drop(verifier);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[test]
    fn file_store_reopens_with_revocations_and_private_permissions() {
        use std::fs;
        let path = std::env::temp_dir().join(format!(
            "iroka-security-store-{}.sqlite",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        {
            let store = SqliteSecurityStore::open(&path).unwrap();
            store
                .revoke_credential("issuer:persist", "cred:persist", 50, "persisted")
                .unwrap();
            assert_eq!(
                store.credential_revoked("issuer:persist", "cred:persist"),
                Ok(true)
            );
        }
        {
            let store = SqliteSecurityStore::open(&path).unwrap();
            assert_eq!(
                store.credential_revoked("issuer:persist", "cred:persist"),
                Ok(true)
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[test]
    fn busy_lock_exhaustion_fails_closed_without_partial_trust_write() {
        use std::fs;

        let path =
            std::env::temp_dir().join(format!("iroka-security-busy-{}.sqlite", std::process::id()));
        let _ = fs::remove_file(&path);
        let store = SqliteSecurityStore::open(&path).unwrap();
        let blocker = Connection::open(&path).unwrap();
        blocker.execute_batch("BEGIN IMMEDIATE;").unwrap();

        assert_eq!(
            store.install_trust_bundle(1, &[7; 32], 10, 100, 11),
            Err(SecurityStoreError::Unavailable)
        );
        assert_eq!(store.highest_trust_bundle_version(), Ok(None));
        assert_eq!(store.trust_bundle_history_count(), Ok(0));

        blocker.execute_batch("ROLLBACK;").unwrap();
        drop(blocker);
        drop(store);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[test]
    fn injected_storage_write_failure_rolls_back_all_trust_state() {
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        {
            let connection = store.connection.lock().unwrap();
            connection
                .execute_batch(
                    "CREATE TRIGGER reject_trust_history
                 BEFORE INSERT ON trust_bundle_history
                 BEGIN SELECT RAISE(ABORT, 'injected storage write failure'); END;",
                )
                .unwrap();
        }

        assert_eq!(
            store.install_trust_bundle(1, &[8; 32], 10, 100, 11),
            Err(SecurityStoreError::Unavailable)
        );
        assert_eq!(store.highest_trust_bundle_version(), Ok(None));
        assert_eq!(store.trust_bundle_history_count(), Ok(0));
    }

    #[test]
    fn deferred_constraint_commit_failure_rolls_back_trust_state() {
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        {
            let connection = store.connection.lock().unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE commit_guard_parent(id INTEGER PRIMARY KEY);
                 CREATE TABLE commit_guard_child(
                   parent_id INTEGER REFERENCES commit_guard_parent(id)
                   DEFERRABLE INITIALLY DEFERRED
                 );
                 CREATE TRIGGER inject_deferred_commit_failure
                 AFTER INSERT ON trust_bundle_history
                 BEGIN
                   INSERT INTO commit_guard_child(parent_id) VALUES(999);
                 END;",
                )
                .unwrap();
        }

        assert_eq!(
            store.install_trust_bundle(1, &[9; 32], 10, 100, 11),
            Err(SecurityStoreError::Unavailable)
        );
        assert_eq!(store.highest_trust_bundle_version(), Ok(None));
        assert_eq!(store.trust_bundle_history_count(), Ok(0));
    }

    #[test]
    fn abrupt_process_exit_recovers_wal_without_uncommitted_trust_state() {
        use std::fs;
        use std::process::Command;

        const CHILD_PATH_ENV: &str = "IROKA_TEST_CRASH_DURING_TRUST_TX_PATH";
        if let Ok(child_path) = std::env::var(CHILD_PATH_ENV) {
            let store = SqliteSecurityStore::open(child_path).unwrap();
            let mut connection = store.connection.lock().unwrap();
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            tx.execute(
                "INSERT INTO trust_bundle_state(singleton, version, digest, issued_at, expires_at)
                 VALUES(1, 77, ?1, 10, 100)",
                params![&[10u8; 32][..]],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO trust_bundle_history(version, digest, issued_at, expires_at, installed_at)
                 VALUES(77, ?1, 10, 100, 11)",
                params![&[10u8; 32][..]],
            ).unwrap();
            // Simulate abrupt process termination: no Rust destructors run and
            // the SQLite transaction is left for WAL crash recovery.
            std::process::exit(73);
        }

        let path = std::env::temp_dir().join(format!(
            "iroka-security-crash-{}.sqlite",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let output = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("security_store::tests::abrupt_process_exit_recovers_wal_without_uncommitted_trust_state")
            .arg("--nocapture")
            .env(CHILD_PATH_ENV, &path)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(73),
            "child did not terminate at the injected transaction point; stdout: {}; stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let recovered = SqliteSecurityStore::open(&path).unwrap();
        assert_eq!(recovered.highest_trust_bundle_version(), Ok(None));
        assert_eq!(recovered.trust_bundle_history_count(), Ok(0));
        drop(recovered);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[test]
    fn sqlite_page_limit_disk_full_fails_closed_without_advancing_trust_state() {
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        let before_count;
        {
            let connection = store.connection.lock().unwrap();
            let page_count: i64 = connection
                .query_row("PRAGMA page_count", [], |row| row.get(0))
                .unwrap();
            let page_limit = page_count + 2;
            connection
                .execute_batch(&format!("PRAGMA max_page_count = {page_limit};"))
                .unwrap();

            let mut inserted = 0i64;
            let mut reached_disk_full = false;
            for version in 1..100_000i64 {
                match connection.execute(
                    "INSERT INTO trust_bundle_history(version, digest, issued_at, expires_at, installed_at)
                     VALUES(?1, ?2, 10, 100, 11)",
                    params![version, &[11u8; 32][..]],
                ) {
                    Ok(_) => inserted += 1,
                    Err(rusqlite::Error::SqliteFailure(error, _))
                        if error.code == rusqlite::ErrorCode::DiskFull =>
                    {
                        reached_disk_full = true;
                        break;
                    }
                    Err(error) => panic!("unexpected page-limit injection error: {error}"),
                }
            }
            assert!(
                reached_disk_full,
                "SQLite page limit did not produce SQLITE_FULL"
            );
            assert!(inserted > 0);
            before_count = u64::try_from(inserted).unwrap();
        }

        assert_eq!(
            store.install_trust_bundle(200_000, &[12; 32], 10, 100, 11),
            Err(SecurityStoreError::Unavailable)
        );
        assert_eq!(store.highest_trust_bundle_version(), Ok(None));
        assert_eq!(store.trust_bundle_history_count(), Ok(before_count));
    }
}
