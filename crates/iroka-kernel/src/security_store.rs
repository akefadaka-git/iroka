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

pub(crate) struct SecurityCommandReceipt<'a> {
    pub command_id: &'a str,
    pub owner_subject: &'a str,
    pub signer_issuer: &'a str,
    pub signer_key_id: &'a str,
    pub digest: &'a [u8],
    pub at: u64,
}

pub(crate) enum OrganizationMutation {
    CreateOrganization {
        organization_id: String,
        tenant_id: String,
        version: u64,
        reason: String,
    },
    SetOrganizationActive {
        organization_id: String,
        tenant_id: String,
        active: bool,
        version: u64,
        reason: String,
    },
    SetDesignation {
        organization_id: String,
        tenant_id: String,
        principal: String,
        designation_id: String,
        active: bool,
        capabilities_json: String,
        version: u64,
        reason: String,
    },
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
             CREATE TABLE IF NOT EXISTS organizations (
               organization_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
               active INTEGER NOT NULL CHECK(active IN (0,1)),
               version INTEGER NOT NULL CHECK(version > 0), updated_at INTEGER NOT NULL,
               command_id TEXT NOT NULL, digest BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS organization_designations (
               organization_id TEXT NOT NULL, principal TEXT NOT NULL,
               designation_id TEXT NOT NULL UNIQUE, tenant_id TEXT NOT NULL,
               active INTEGER NOT NULL CHECK(active IN (0,1)),
               capabilities_json TEXT NOT NULL,
               version INTEGER NOT NULL CHECK(version > 0), updated_at INTEGER NOT NULL,
               command_id TEXT NOT NULL, digest BLOB NOT NULL,
               PRIMARY KEY(organization_id, principal),
               FOREIGN KEY(organization_id) REFERENCES organizations(organization_id)
             );
             CREATE TABLE IF NOT EXISTS tenant_memberships (
               subject TEXT NOT NULL, tenant_id TEXT NOT NULL,
               active INTEGER NOT NULL CHECK(active IN (0,1)),
               version INTEGER NOT NULL CHECK(version > 0),
               updated_at INTEGER NOT NULL, command_id TEXT NOT NULL,
               PRIMARY KEY(subject, tenant_id)
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
        receipt: SecurityCommandReceipt<'_>,
        target: RevocationTarget,
    ) -> Result<bool, SecurityStoreError> {
        let SecurityCommandReceipt {
            command_id,
            owner_subject,
            signer_issuer,
            signer_key_id,
            digest,
            at,
        } = receipt;
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
                        if active { 1_i64 } else { 0_i64 },
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

    /// Atomically consume a G02 Owner command and mutate the canonical organization
    /// and designation tables. The caller verifies the dedicated G02 signature domain.
    pub(crate) fn apply_organization_mutation(
        &self,
        receipt: SecurityCommandReceipt<'_>,
        mutation: OrganizationMutation,
    ) -> Result<bool, SecurityStoreError> {
        let SecurityCommandReceipt {
            command_id,
            owner_subject,
            signer_issuer,
            signer_key_id,
            digest,
            at,
        } = receipt;
        if command_id.trim().is_empty() || digest.len() != 32 {
            return Err(SecurityStoreError::InvalidVersion);
        }
        let at_i = i64::try_from(at).map_err(|_| SecurityStoreError::InvalidVersion)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let revoked: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM revoked_keys WHERE issuer=?1 AND key_id=?2)",
                params![signer_issuer, signer_key_id],
                |row| row.get(0),
            )
            .map_err(|_| SecurityStoreError::Unavailable)?;
        if revoked {
            return Err(SecurityStoreError::Revoked);
        }
        let consumed = tx.execute(
            "INSERT OR IGNORE INTO approval_consumptions(approval_id,scope_digest,consumed_at) VALUES(?1,?2,?3)",
            params![format!("security-command:{command_id}"), digest, at_i]
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        if consumed == 0 {
            return Ok(false);
        }

        let (action, target, reason) = match mutation {
            OrganizationMutation::CreateOrganization {
                organization_id,
                tenant_id,
                version,
                reason,
            } => {
                if version == 0 {
                    return Err(SecurityStoreError::InvalidVersion);
                }
                let version_i =
                    i64::try_from(version).map_err(|_| SecurityStoreError::InvalidVersion)?;
                tx.execute(
                    "INSERT INTO organizations(organization_id,tenant_id,active,version,updated_at,command_id,digest) VALUES(?1,?2,1,?3,?4,?5,?6)",
                    params![organization_id,tenant_id,version_i,at_i,command_id,digest]
                ).map_err(|_| SecurityStoreError::ConflictingVersion)?;
                ("create_organization".to_owned(), organization_id, reason)
            }
            OrganizationMutation::SetOrganizationActive {
                organization_id,
                tenant_id,
                active,
                version,
                reason,
            } => {
                if version == 0 {
                    return Err(SecurityStoreError::InvalidVersion);
                }
                let version_i =
                    i64::try_from(version).map_err(|_| SecurityStoreError::InvalidVersion)?;
                let current: Option<(String,i64,Vec<u8>)> = tx.query_row(
                    "SELECT tenant_id,version,digest FROM organizations WHERE organization_id=?1",
                    [&organization_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))
                ).optional().map_err(|_| SecurityStoreError::Unavailable)?;
                let (bound_tenant, current_version, current_digest) =
                    current.ok_or(SecurityStoreError::InvalidVersion)?;
                if bound_tenant != tenant_id {
                    return Err(SecurityStoreError::ConflictingVersion);
                }
                if version_i < current_version {
                    return Err(SecurityStoreError::Rollback);
                }
                if version_i == current_version {
                    return if current_digest == digest {
                        Ok(false)
                    } else {
                        Err(SecurityStoreError::ConflictingVersion)
                    };
                }
                tx.execute(
                    "UPDATE organizations SET active=?2,version=?3,updated_at=?4,command_id=?5,digest=?6 WHERE organization_id=?1",
                    params![organization_id,if active { 1_i64 } else { 0_i64 },version_i,at_i,command_id,digest]
                ).map_err(|_| SecurityStoreError::Unavailable)?;
                (
                    "set_organization_active".to_owned(),
                    organization_id,
                    reason,
                )
            }
            OrganizationMutation::SetDesignation {
                organization_id,
                tenant_id,
                principal,
                designation_id,
                active,
                capabilities_json,
                version,
                reason,
            } => {
                if version == 0 {
                    return Err(SecurityStoreError::InvalidVersion);
                }
                let version_i =
                    i64::try_from(version).map_err(|_| SecurityStoreError::InvalidVersion)?;
                let org: Option<String> = tx
                    .query_row(
                        "SELECT tenant_id FROM organizations WHERE organization_id=?1",
                        [&organization_id],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(|_| SecurityStoreError::Unavailable)?;
                if org.as_deref() != Some(tenant_id.as_str()) {
                    return Err(SecurityStoreError::ConflictingVersion);
                }
                let current: Option<(String,i64,Vec<u8>)> = tx.query_row(
                    "SELECT designation_id,version,digest FROM organization_designations WHERE organization_id=?1 AND principal=?2",
                    params![organization_id,principal], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))
                ).optional().map_err(|_| SecurityStoreError::Unavailable)?;
                if !active
                    && current
                        .as_ref()
                        .map_or(true, |(current_id, _, _)| current_id != &designation_id)
                {
                    return Err(SecurityStoreError::ConflictingVersion);
                }
                if let Some((_, v, d)) = current {
                    if version_i < v {
                        return Err(SecurityStoreError::Rollback);
                    }
                    if version_i == v {
                        return if d == digest {
                            Ok(false)
                        } else {
                            Err(SecurityStoreError::ConflictingVersion)
                        };
                    }
                } else if !active {
                    return Err(SecurityStoreError::InvalidVersion);
                }
                tx.execute(
                    "INSERT INTO organization_designations(organization_id,principal,designation_id,tenant_id,active,capabilities_json,version,updated_at,command_id,digest) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(organization_id,principal) DO UPDATE SET designation_id=excluded.designation_id,tenant_id=excluded.tenant_id,active=excluded.active,capabilities_json=excluded.capabilities_json,version=excluded.version,updated_at=excluded.updated_at,command_id=excluded.command_id,digest=excluded.digest",
                    params![organization_id,principal,designation_id,tenant_id,if active { 1_i64 } else { 0_i64 },capabilities_json,version_i,at_i,command_id,digest]
                ).map_err(|_| SecurityStoreError::ConflictingVersion)?;
                (
                    "set_designation".to_owned(),
                    format!("{organization_id}:{principal}:{designation_id}"),
                    reason,
                )
            }
        };
        tx.execute(
            "INSERT INTO security_command_log(command_id,digest,owner_subject,signer_key_id,action,target,reason,occurred_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![command_id,digest,owner_subject,signer_key_id,action,target,reason,at_i]
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        tx.commit().map_err(|_| SecurityStoreError::Unavailable)?;
        Ok(true)
    }

    pub(crate) fn organization_state(
        &self,
        organization_id: &str,
    ) -> Result<Option<(String, bool, u64, u64)>, SecurityStoreError> {
        let c = self
            .connection
            .lock()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let row: Option<(String,i64,i64,i64)> = c.query_row(
            "SELECT tenant_id,active,version,updated_at FROM organizations WHERE organization_id=?1",
            [organization_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))
        ).optional().map_err(|_| SecurityStoreError::Unavailable)?;
        row.map(|(tenant, active, version, updated)| {
            Ok((
                tenant,
                active == 1,
                u64::try_from(version).map_err(|_| SecurityStoreError::Unavailable)?,
                u64::try_from(updated).map_err(|_| SecurityStoreError::Unavailable)?,
            ))
        })
        .transpose()
    }

    pub(crate) fn organization_designation(
        &self,
        organization_id: &str,
        principal: &str,
    ) -> Result<Option<(String, bool, String, u64, u64)>, SecurityStoreError> {
        let c = self
            .connection
            .lock()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let row: Option<(String,i64,String,i64,i64)> = c.query_row(
            "SELECT designation_id,active,capabilities_json,version,updated_at FROM organization_designations WHERE organization_id=?1 AND principal=?2",
            params![organization_id,principal], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))
        ).optional().map_err(|_| SecurityStoreError::Unavailable)?;
        row.map(|(id, active, caps, version, updated)| {
            Ok((
                id,
                active == 1,
                caps,
                u64::try_from(version).map_err(|_| SecurityStoreError::Unavailable)?,
                u64::try_from(updated).map_err(|_| SecurityStoreError::Unavailable)?,
            ))
        })
        .transpose()
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
