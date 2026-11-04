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
}

pub(crate) struct ApprovalReceipt<'a> {
    pub approval_id: &'a str,
    pub payload_digest: &'a [u8],
    pub owner_subject: &'a str,
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
    pub(crate) fn apply_signed_revocation(
        &self,
        command_id: &str,
        owner_subject: &str,
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
        }
        tx.execute(
            "INSERT INTO security_command_log(command_id, digest, owner_subject, signer_key_id, action, target, reason, occurred_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![command_id, digest, owner_subject, signer_key_id, action_name, target_name, reason_text, i64::try_from(at).map_err(|_| SecurityStoreError::InvalidVersion)?]
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        tx.commit().map_err(|_| SecurityStoreError::Unavailable)?;
        Ok(true)
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
    ) -> Result<bool, SecurityStoreError> {
        if receipt.approval_id.trim().is_empty() || receipt.payload_digest.len() != 32 {
            return Err(SecurityStoreError::InvalidVersion);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let consumed_at =
            i64::try_from(receipt.consumed_at).map_err(|_| SecurityStoreError::InvalidVersion)?;
        let changed = tx.execute(
            "INSERT OR IGNORE INTO approval_consumptions(approval_id, scope_digest, consumed_at) VALUES(?1, ?2, ?3)",
            params![receipt.approval_id, receipt.payload_digest, consumed_at]
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        if changed == 0 {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO approval_receipts(approval_id, payload_digest, owner_subject, signer_key_id, request_subject, capability, resource, policy_version, issued_at, expires_at, consumed_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                receipt.approval_id, receipt.payload_digest, receipt.owner_subject, receipt.signer_key_id,
                receipt.request_subject, receipt.capability, receipt.resource, receipt.policy_version,
                i64::try_from(receipt.issued_at).map_err(|_| SecurityStoreError::InvalidVersion)?,
                i64::try_from(receipt.expires_at).map_err(|_| SecurityStoreError::InvalidVersion)?,
                consumed_at
            ]
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        tx.commit().map_err(|_| SecurityStoreError::Unavailable)?;
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
}
