//! Durable local security registry for trust rollback protection and revocation.
//! This SQLite adapter is intended for a single-node authority service. Multi-node
//! deployments must use a shared transactional database adapter with equivalent
//! uniqueness, durability and fail-closed semantics.

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::identity_crypto::{RevocationChecker, RevocationError};
use crate::version_lineage::{
    LineageRegistryError, RegisteredLineageArtifact, RegisteredMutationRecord,
    VersionLineageRecord, VersionLineageRegistry,
};

type LineageArtifactRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
);
type LineageMutationRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    i64,
    String,
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityStoreError {
    Unavailable,
    Rollback,
    ConflictingVersion,
    InvalidVersion,
    EvidenceReplay,
    RevokedEvidenceKey,
    RevocationFloorRollback,
    ConflictingRevocationFloor,
    AuthorityCheckpointRollback,
    AuthorityCheckpointConflict,
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

    /// Advance a monotonic checkpoint held in this security database, which MUST
    /// be provisioned and backed up independently from the authority-registry database.
    pub(crate) fn advance_authority_checkpoint(
        &self,
        registry: &str,
        revision: u64,
        digest: &[u8],
    ) -> Result<(), SecurityStoreError> {
        if !matches!(registry, "identity_roots" | "identity_succession" | "compatibility")
            || revision == 0
            || digest.len() != 32
        {
            return Err(SecurityStoreError::InvalidVersion);
        }
        let revision = i64::try_from(revision).map_err(|_| SecurityStoreError::InvalidVersion)?;
        let mut connection = self.connection.lock().map_err(|_| SecurityStoreError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let current: Option<(i64, Vec<u8>)> = transaction
            .query_row(
                "SELECT revision,digest FROM authority_registry_checkpoints WHERE registry=?1",
                params![registry],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        if let Some((old_revision, old_digest)) = current {
            if revision < old_revision {
                return Err(SecurityStoreError::AuthorityCheckpointRollback);
            }
            if revision == old_revision {
                if old_digest.as_slice() != digest {
                    return Err(SecurityStoreError::AuthorityCheckpointConflict);
                }
                transaction.commit().map_err(|_| SecurityStoreError::Unavailable)?;
                return Ok(());
            }
        }
        transaction.execute(
            "INSERT INTO authority_registry_checkpoints(registry,revision,digest)
             VALUES(?1,?2,?3)
             ON CONFLICT(registry) DO UPDATE SET revision=excluded.revision,digest=excluded.digest",
            params![registry, revision, digest],
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        transaction.commit().map_err(|_| SecurityStoreError::Unavailable)
    }

    /// Require exact agreement with the independently stored monotonic checkpoint.
    pub(crate) fn verify_authority_checkpoint(
        &self,
        registry: &str,
        revision: u64,
        digest: &[u8],
    ) -> Result<(), SecurityStoreError> {
        if !matches!(registry, "identity_roots" | "identity_succession" | "compatibility")
            || revision == 0
            || digest.len() != 32
        {
            return Err(SecurityStoreError::InvalidVersion);
        }
        let connection = self.connection.lock().map_err(|_| SecurityStoreError::Unavailable)?;
        let current: Option<(i64, Vec<u8>)> = connection
            .query_row(
                "SELECT revision,digest FROM authority_registry_checkpoints WHERE registry=?1",
                params![registry],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        match current {
            Some((stored_revision, stored_digest))
                if stored_revision == i64::try_from(revision).map_err(|_| SecurityStoreError::InvalidVersion)?
                    && stored_digest.as_slice() == digest => Ok(()),
            Some((stored_revision, _)) if stored_revision > i64::try_from(revision).map_err(|_| SecurityStoreError::InvalidVersion)? =>
                Err(SecurityStoreError::AuthorityCheckpointRollback),
            Some(_) => Err(SecurityStoreError::AuthorityCheckpointConflict),
            None => Err(SecurityStoreError::Unavailable),
        }
    }

    /// Run SQLite's full integrity checker before security state is trusted on recovery.
    pub fn integrity_check(&self) -> Result<(), SecurityStoreError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let mut statement = connection
            .prepare("PRAGMA integrity_check")
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let results = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        if results.len() == 1 && results[0] == "ok" {
            Ok(())
        } else {
            Err(SecurityStoreError::Unavailable)
        }
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
             CREATE TABLE IF NOT EXISTS trust_bundle_documents (
               version INTEGER PRIMARY KEY,
               bundle_json TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS trust_bundle_state (
               singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
               version INTEGER NOT NULL,
               digest BLOB NOT NULL,
               issued_at INTEGER NOT NULL,
               expires_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS authority_registry_checkpoints (
               registry TEXT PRIMARY KEY,
               revision INTEGER NOT NULL CHECK(revision > 0),
               digest BLOB NOT NULL CHECK(length(digest) = 32)
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
             CREATE TABLE IF NOT EXISTS rollback_evidence_nonces (
               issuer TEXT NOT NULL, key_id TEXT NOT NULL, nonce TEXT NOT NULL,
               expires_at INTEGER NOT NULL,
               PRIMARY KEY (issuer, key_id, nonce)
             );
             CREATE TABLE IF NOT EXISTS rollback_evidence_policy_state (
               singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
               version INTEGER NOT NULL CHECK(version > 0),
               digest BLOB NOT NULL CHECK(length(digest) = 32),
               expires_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS rollback_evidence_policy_documents (
               version INTEGER PRIMARY KEY,
               policy_json TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS rollback_revocation_floor (
               singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
               floor INTEGER NOT NULL, revision INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS version_lineage_registry_meta (
               singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
               revision INTEGER NOT NULL CHECK(revision >= 0)
             );
             INSERT OR IGNORE INTO version_lineage_registry_meta(singleton, revision) VALUES(1, 0);
             CREATE TABLE IF NOT EXISTS version_lineage_registry_history (
               revision INTEGER PRIMARY KEY CHECK(revision > 0),
               digest BLOB NOT NULL CHECK(length(digest) = 32),
               snapshot_json TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS version_lineage_artifacts (
               gene_id TEXT NOT NULL, version TEXT NOT NULL, artifact_digest TEXT NOT NULL,
               artifact_json TEXT NOT NULL, parent_version TEXT, parent_digest TEXT,
               mutation_id TEXT, epoch INTEGER NOT NULL CHECK(epoch >= 0),
               PRIMARY KEY(gene_id, version, artifact_digest), UNIQUE(gene_id, version),
               CHECK(
                 (parent_version IS NULL AND parent_digest IS NULL AND mutation_id IS NULL AND epoch = 0)
                 OR
                 (parent_version IS NOT NULL AND parent_digest IS NOT NULL AND mutation_id IS NOT NULL)
               )
             );
             CREATE TABLE IF NOT EXISTS version_lineage_mutations (
               mutation_ref TEXT PRIMARY KEY, mutation_id TEXT NOT NULL UNIQUE,
               source_version TEXT NOT NULL, source_digest TEXT NOT NULL,
               target_version TEXT NOT NULL, target_digest TEXT NOT NULL,
               approved INTEGER NOT NULL CHECK(approved IN (0, 1)),
               gates_passed INTEGER NOT NULL CHECK(gates_passed IN (0, 1)),
               approval_commitment TEXT NOT NULL,
               UNIQUE(target_version, target_digest)
             );"
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Atomically consume a signed rollback-evidence nonce after signature
    /// verification. Key revocation is rechecked inside the same transaction.
    pub(crate) fn consume_rollback_evidence_nonce(
        &self,
        issuer: &str,
        key_id: &str,
        nonce: &str,
        expires_at: u64,
        now: u64,
    ) -> Result<(), SecurityStoreError> {
        if issuer.trim().is_empty()
            || key_id.trim().is_empty()
            || nonce.trim().len() < 16
            || expires_at <= now
        {
            return Err(SecurityStoreError::InvalidVersion);
        }
        let expires_i =
            i64::try_from(expires_at).map_err(|_| SecurityStoreError::InvalidVersion)?;
        let now_i = i64::try_from(now).map_err(|_| SecurityStoreError::InvalidVersion)?;
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
                params![issuer, key_id],
                |row| row.get(0),
            )
            .map_err(|_| SecurityStoreError::Unavailable)?;
        if revoked {
            return Err(SecurityStoreError::RevokedEvidenceKey);
        }
        tx.execute(
            "DELETE FROM rollback_evidence_nonces WHERE expires_at <= ?1",
            params![now_i],
        )
        .map_err(|_| SecurityStoreError::Unavailable)?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO rollback_evidence_nonces(issuer, key_id, nonce, expires_at) VALUES(?1, ?2, ?3, ?4)",
            params![issuer, key_id, nonce, expires_i],
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        if inserted == 0 {
            return Err(SecurityStoreError::EvidenceReplay);
        }
        tx.commit().map_err(|_| SecurityStoreError::Unavailable)
    }

    /// Persist an authoritative monotonic revocation-floor high-water mark.
    /// A higher revision may never lower the floor; an equal revision must be identical.
    pub(crate) fn advance_rollback_revocation_floor(
        &self,
        floor: u64,
        revision: u64,
    ) -> Result<(), SecurityStoreError> {
        let floor_i = i64::try_from(floor).map_err(|_| SecurityStoreError::InvalidVersion)?;
        let revision_i = i64::try_from(revision).map_err(|_| SecurityStoreError::InvalidVersion)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let current: Option<(i64, i64)> = tx
            .query_row(
                "SELECT floor, revision FROM rollback_revocation_floor WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| SecurityStoreError::Unavailable)?;
        match current {
            Some((_old_floor, old_revision)) if revision_i < old_revision => {
                return Err(SecurityStoreError::RevocationFloorRollback);
            }
            Some((old_floor, old_revision))
                if revision_i == old_revision && floor_i != old_floor =>
            {
                return Err(SecurityStoreError::ConflictingRevocationFloor);
            }
            Some((old_floor, old_revision)) if revision_i > old_revision && floor_i < old_floor => {
                return Err(SecurityStoreError::RevocationFloorRollback);
            }
            Some((old_floor, old_revision))
                if revision_i == old_revision && floor_i == old_floor =>
            {
                tx.commit().map_err(|_| SecurityStoreError::Unavailable)?;
                return Ok(());
            }
            _ => {}
        }
        tx.execute(
            "INSERT INTO rollback_revocation_floor(singleton, floor, revision) VALUES(1, ?1, ?2)
             ON CONFLICT(singleton) DO UPDATE SET floor=excluded.floor, revision=excluded.revision",
            params![floor_i, revision_i],
        )
        .map_err(|_| SecurityStoreError::Unavailable)?;
        tx.commit().map_err(|_| SecurityStoreError::Unavailable)
    }

    /// Persist the highest accepted, root-signed trust-bundle version.
    /// Same-version retries are idempotent only when the digest is identical.
    #[rustfmt::skip]
    pub fn install_trust_bundle(
        &self,
        version: u64,
        digest: &[u8],
        issued_at: u64,
        expires_at: u64,
        installed_at: u64,
    ) -> Result<(), SecurityStoreError> {
        self.install_trust_bundle_with_document(version, digest, issued_at, expires_at, installed_at, None)
    }

    /// Atomically persist the anti-rollback high-water mark and the complete
    /// root-signed bundle needed to reconstruct a trust snapshot after restart.
    #[rustfmt::skip]
    pub(crate) fn install_trust_bundle_with_document(
        &self,
        version: u64,
        digest: &[u8],
        issued_at: u64,
        expires_at: u64,
        installed_at: u64,
        bundle_json: Option<&str>,
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
                if let Some(document) = bundle_json {
                    tx.execute(
                        "INSERT OR IGNORE INTO trust_bundle_documents(version, bundle_json) VALUES(?1, ?2)",
                        params![version_i, document],
                    ).map_err(|_| SecurityStoreError::Unavailable)?;
                    let stored: String = tx.query_row(
                        "SELECT bundle_json FROM trust_bundle_documents WHERE version=?1",
                        params![version_i],
                        |row| row.get(0),
                    ).map_err(|_| SecurityStoreError::Unavailable)?;
                    if stored != document {
                        return Err(SecurityStoreError::ConflictingVersion);
                    }
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
        if let Some(document) = bundle_json {
            tx.execute(
                "INSERT INTO trust_bundle_documents(version, bundle_json) VALUES(?1, ?2)",
                params![version_i, document],
            ).map_err(|_| SecurityStoreError::Unavailable)?;
        }
        tx.commit().map_err(|_| SecurityStoreError::Unavailable)
    }

    #[rustfmt::skip]
    pub(crate) fn latest_trust_bundle_document(&self) -> Result<Option<String>, SecurityStoreError> {
        let connection = self.connection.lock().map_err(|_| SecurityStoreError::Unavailable)?;
        connection.query_row(
            "SELECT d.bundle_json FROM trust_bundle_documents d
             JOIN trust_bundle_state s ON s.version=d.version
             WHERE s.singleton=1",
            [],
            |row| row.get(0),
        ).optional().map_err(|_| SecurityStoreError::Unavailable)
    }

    /// Atomically persist a root-signed, versioned issuer policy after its
    /// signature and semantic validation have succeeded.
    #[rustfmt::skip]
    pub(crate) fn install_rollback_evidence_policy(
        &self,
        version: u64,
        digest: &[u8],
        expires_at: u64,
        policy_json: &str,
    ) -> Result<(), SecurityStoreError> {
        if version == 0 || digest.len() != 32 || policy_json.trim().is_empty() {
            return Err(SecurityStoreError::InvalidVersion);
        }
        let version_i = i64::try_from(version).map_err(|_| SecurityStoreError::InvalidVersion)?;
        let expires_i = i64::try_from(expires_at).map_err(|_| SecurityStoreError::InvalidVersion)?;
        let mut connection = self.connection.lock().map_err(|_| SecurityStoreError::Unavailable)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let current: Option<(i64, Vec<u8>)> = tx.query_row(
            "SELECT version, digest FROM rollback_evidence_policy_state WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(|_| SecurityStoreError::Unavailable)?;
        match current {
            Some((old, _)) if version_i < old => return Err(SecurityStoreError::Rollback),
            Some((old, old_digest)) if version_i == old => {
                if old_digest != digest { return Err(SecurityStoreError::ConflictingVersion); }
                let stored: String = tx.query_row(
                    "SELECT policy_json FROM rollback_evidence_policy_documents WHERE version=?1",
                    params![version_i],
                    |row| row.get(0),
                ).optional().map_err(|_| SecurityStoreError::Unavailable)?
                 .ok_or(SecurityStoreError::Unavailable)?;
                if stored != policy_json { return Err(SecurityStoreError::ConflictingVersion); }
                tx.commit().map_err(|_| SecurityStoreError::Unavailable)?;
                return Ok(());
            }
            _ => {}
        }
        tx.execute(
            "INSERT INTO rollback_evidence_policy_state(singleton, version, digest, expires_at)
             VALUES(1, ?1, ?2, ?3)
             ON CONFLICT(singleton) DO UPDATE SET version=excluded.version, digest=excluded.digest, expires_at=excluded.expires_at",
            params![version_i, digest, expires_i],
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        tx.execute(
            "INSERT INTO rollback_evidence_policy_documents(version, policy_json) VALUES(?1, ?2)",
            params![version_i, policy_json],
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        tx.commit().map_err(|_| SecurityStoreError::Unavailable)
    }

    #[rustfmt::skip]
    pub(crate) fn latest_rollback_evidence_policy_document(
        &self,
    ) -> Result<Option<String>, SecurityStoreError> {
        let connection = self.connection.lock().map_err(|_| SecurityStoreError::Unavailable)?;
        connection.query_row(
            "SELECT d.policy_json FROM rollback_evidence_policy_documents d
             JOIN rollback_evidence_policy_state s ON s.version=d.version
             WHERE s.singleton=1",
            [],
            |row| row.get(0),
        ).optional().map_err(|_| SecurityStoreError::Unavailable)
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

#[rustfmt::skip]
impl SqliteSecurityStore {
    /// Replace the active lineage registry as one immutable, monotonic snapshot.
    /// Callers must verify the root signature and all snapshot invariants first.
    pub(crate) fn install_version_lineage_snapshot(
        &self,
        revision: u64,
        digest: &[u8],
        snapshot_json: &str,
        artifacts: &[RegisteredLineageArtifact],
        mutations: &[RegisteredMutationRecord],
    ) -> Result<(), SecurityStoreError> {
        if revision == 0 || digest.len() != 32 || snapshot_json.trim().is_empty() || artifacts.is_empty() {
            return Err(SecurityStoreError::InvalidVersion);
        }
        let revision_i = i64::try_from(revision).map_err(|_| SecurityStoreError::InvalidVersion)?;
        let mut connection = self.connection.lock().map_err(|_| SecurityStoreError::Unavailable)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| SecurityStoreError::Unavailable)?;
        let current: i64 = tx.query_row(
            "SELECT revision FROM version_lineage_registry_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        if revision_i < current {
            return Err(SecurityStoreError::Rollback);
        }
        if revision_i == current {
            if current == 0 {
                return Err(SecurityStoreError::ConflictingVersion);
            }
            let existing: Option<(Vec<u8>, String)> = tx.query_row(
                "SELECT digest, snapshot_json FROM version_lineage_registry_history WHERE revision=?1",
                params![revision_i],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional().map_err(|_| SecurityStoreError::Unavailable)?;
            return match existing {
                Some((old_digest, old_json)) if old_digest == digest && old_json == snapshot_json => {
                    tx.commit().map_err(|_| SecurityStoreError::Unavailable)?;
                    Ok(())
                }
                _ => Err(SecurityStoreError::ConflictingVersion),
            };
        }
        tx.execute("DELETE FROM version_lineage_artifacts WHERE gene_id='g12.version-lineage'", [])
            .map_err(|_| SecurityStoreError::Unavailable)?;
        tx.execute("DELETE FROM version_lineage_mutations", [])
            .map_err(|_| SecurityStoreError::Unavailable)?;
        for artifact in artifacts {
            if artifact.gene_id != "g12.version-lineage" || artifact.version.trim().is_empty()
                || artifact.artifact_digest.len() != 64 || artifact.epoch > i64::MAX as u64
            {
                return Err(SecurityStoreError::InvalidVersion);
            }
            let artifact_json = serde_json::to_string(&artifact.artifact)
                .map_err(|_| SecurityStoreError::InvalidVersion)?;
            tx.execute(
                "INSERT INTO version_lineage_artifacts(
                    gene_id, version, artifact_digest, artifact_json, parent_version,
                    parent_digest, mutation_id, epoch
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    artifact.gene_id, artifact.version, artifact.artifact_digest,
                    artifact_json, artifact.parent_version, artifact.parent_digest,
                    artifact.mutation_id, i64::try_from(artifact.epoch).map_err(|_| SecurityStoreError::InvalidVersion)?
                ],
            ).map_err(|_| SecurityStoreError::ConflictingVersion)?;
        }
        for mutation in mutations {
            if mutation.mutation_ref.trim().is_empty() || mutation.mutation_id.trim().is_empty()
                || mutation.source_version.as_deref().unwrap_or("").trim().is_empty()
                || mutation.source_digest.as_deref().unwrap_or("").len() != 64
                || mutation.target_version.trim().is_empty() || mutation.target_digest.len() != 64
                || mutation.approval_commitment.len() != 64
            {
                return Err(SecurityStoreError::InvalidVersion);
            }
            tx.execute(
                "INSERT INTO version_lineage_mutations(
                    mutation_ref, mutation_id, source_version, source_digest,
                    target_version, target_digest, approved, gates_passed, approval_commitment
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    mutation.mutation_ref, mutation.mutation_id,
                    mutation.source_version.as_deref().unwrap_or(""),
                    mutation.source_digest.as_deref().unwrap_or(""),
                    mutation.target_version, mutation.target_digest,
                    if mutation.approved { 1i64 } else { 0i64 }, if mutation.gates_passed { 1i64 } else { 0i64 },
                    mutation.approval_commitment
                ],
            ).map_err(|_| SecurityStoreError::ConflictingVersion)?;
        }
        tx.execute(
            "UPDATE version_lineage_registry_meta SET revision=?1 WHERE singleton=1",
            params![revision_i],
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        tx.execute(
            "INSERT INTO version_lineage_registry_history(revision, digest, snapshot_json) VALUES(?1, ?2, ?3)",
            params![revision_i, digest, snapshot_json],
        ).map_err(|_| SecurityStoreError::Unavailable)?;
        tx.commit().map_err(|_| SecurityStoreError::Unavailable)
    }

    pub(crate) fn latest_version_lineage_snapshot_document(
        &self,
    ) -> Result<Option<String>, SecurityStoreError> {
        let connection = self.connection.lock().map_err(|_| SecurityStoreError::Unavailable)?;
        connection.query_row(
            "SELECT snapshot_json FROM version_lineage_registry_history
             WHERE revision=(SELECT revision FROM version_lineage_registry_meta WHERE singleton=1)",
            [],
            |row| row.get(0),
        ).optional().map_err(|_| SecurityStoreError::Unavailable)
    }
}

impl VersionLineageRegistry for SqliteSecurityStore {
    fn resolve_lineage(
        &self,
        candidate_version: &str,
        candidate_digest: &str,
    ) -> Result<VersionLineageRecord, LineageRegistryError> {
        const GENE_ID: &str = "g12.version-lineage";
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| LineageRegistryError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| LineageRegistryError::Unavailable)?;
        let revision: i64 = transaction
            .query_row(
                "SELECT revision FROM version_lineage_registry_meta WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| LineageRegistryError::Unavailable)?;
        if revision < 0 {
            return Err(LineageRegistryError::IntegrityFailure);
        }

        fn load_artifact(
            connection: &Connection,
            gene_id: &str,
            version: &str,
            digest: &str,
        ) -> Result<RegisteredLineageArtifact, LineageRegistryError> {
            let row: Option<LineageArtifactRow> = connection
                .query_row(
                    "SELECT gene_id, version, artifact_digest, artifact_json,
                            parent_version, parent_digest, mutation_id, epoch
                     FROM version_lineage_artifacts
                     WHERE gene_id=?1 AND version=?2 AND artifact_digest=?3",
                    params![gene_id, version, digest],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                            row.get(7)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| LineageRegistryError::Unavailable)?;
            let Some((
                gene_id,
                version,
                artifact_digest,
                artifact_json,
                parent_version,
                parent_digest,
                mutation_id,
                epoch,
            )) = row
            else {
                return Err(LineageRegistryError::UnknownVersion);
            };
            let artifact = serde_json::from_str(&artifact_json)
                .map_err(|_| LineageRegistryError::IntegrityFailure)?;
            let epoch = u64::try_from(epoch).map_err(|_| LineageRegistryError::IntegrityFailure)?;
            Ok(RegisteredLineageArtifact {
                gene_id,
                version,
                artifact_digest,
                artifact,
                parent_version,
                parent_digest,
                mutation_id,
                epoch,
            })
        }

        let mut current =
            load_artifact(&transaction, GENE_ID, candidate_version, candidate_digest)?;
        let mut ancestry = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        loop {
            if !seen.insert(current.artifact_digest.clone()) || ancestry.len() >= 128 {
                return Err(LineageRegistryError::IntegrityFailure);
            }
            let parent_version = current.parent_version.clone();
            let parent_digest = current.parent_digest.clone();
            ancestry.push(current);
            match (parent_version, parent_digest) {
                (None, None) => break,
                (Some(version), Some(digest)) => {
                    current = load_artifact(&transaction, GENE_ID, &version, &digest)?;
                }
                _ => return Err(LineageRegistryError::IntegrityFailure),
            }
        }
        ancestry.reverse();

        let candidate = ancestry
            .last()
            .ok_or(LineageRegistryError::IntegrityFailure)?;
        let mutation = if let Some(mutation_id) = candidate.mutation_id.as_deref() {
            let row: Option<LineageMutationRow> = transaction
                .query_row(
                    "SELECT mutation_ref, mutation_id, source_version, source_digest,
                            target_version, target_digest, approved, gates_passed,
                            approval_commitment
                     FROM version_lineage_mutations
                     WHERE mutation_id=?1 AND target_version=?2 AND target_digest=?3",
                    params![mutation_id, candidate.version, candidate.artifact_digest],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                            row.get(7)?,
                            row.get(8)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| LineageRegistryError::Unavailable)?;
            let Some((
                mutation_ref,
                mutation_id,
                source_version,
                source_digest,
                target_version,
                target_digest,
                approved,
                gates_passed,
                approval_commitment,
            )) = row
            else {
                return Err(LineageRegistryError::IntegrityFailure);
            };
            Some(RegisteredMutationRecord {
                mutation_ref,
                mutation_id,
                source_version: Some(source_version),
                source_digest: Some(source_digest),
                target_version,
                target_digest,
                approved: approved == 1,
                gates_passed: gates_passed == 1,
                approval_commitment,
            })
        } else {
            None
        };

        let record = VersionLineageRecord {
            ancestry,
            mutation,
            registry_revision: u64::try_from(revision)
                .map_err(|_| LineageRegistryError::IntegrityFailure)?,
        };
        transaction
            .commit()
            .map_err(|_| LineageRegistryError::Unavailable)?;
        Ok(record)
    }
}

impl RevocationChecker for std::sync::Arc<SqliteSecurityStore> {
    fn credential_revoked(
        &self,
        issuer: &str,
        credential_id: &str,
    ) -> Result<bool, RevocationError> {
        self.as_ref().credential_revoked(issuer, credential_id)
    }
    fn key_revoked(&self, issuer: &str, key_id: &str) -> Result<bool, RevocationError> {
        self.as_ref().key_revoked(issuer, key_id)
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
    fn rollback_nonce_and_revocation_floor_survive_file_store_reopen() {
        use std::fs;
        let path = std::env::temp_dir().join(format!(
            "iroka-rollback-state-recovery-{}.sqlite",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        {
            let store = SqliteSecurityStore::open(&path).unwrap();
            store
                .consume_rollback_evidence_nonce(
                    "issuer:persist",
                    "key:persist",
                    "nonce-persisted-evidence-proof-0001",
                    500,
                    100,
                )
                .unwrap();
            store.advance_rollback_revocation_floor(20, 7).unwrap();
        }
        {
            let store = SqliteSecurityStore::open(&path).unwrap();
            assert_eq!(
                store.consume_rollback_evidence_nonce(
                    "issuer:persist",
                    "key:persist",
                    "nonce-persisted-evidence-proof-0001",
                    500,
                    101,
                ),
                Err(SecurityStoreError::EvidenceReplay)
            );
            assert_eq!(
                store.advance_rollback_revocation_floor(19, 8),
                Err(SecurityStoreError::RevocationFloorRollback)
            );
            assert_eq!(store.advance_rollback_revocation_floor(20, 7), Ok(()));
            assert_eq!(store.integrity_check(), Ok(()));
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

    #[test]
    fn rollback_evidence_nonces_are_single_use_and_key_revocation_is_rechecked() {
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        assert_eq!(
            store.consume_rollback_evidence_nonce(
                "issuer:test",
                "key:test",
                "nonce-evidence-proof-0001",
                200,
                100
            ),
            Ok(())
        );
        assert_eq!(
            store.consume_rollback_evidence_nonce(
                "issuer:test",
                "key:test",
                "nonce-evidence-proof-0001",
                200,
                101
            ),
            Err(SecurityStoreError::EvidenceReplay)
        );
        store
            .revoke_key("issuer:test", "key:test", 102, "compromised")
            .unwrap();
        assert_eq!(
            store.consume_rollback_evidence_nonce(
                "issuer:test",
                "key:test",
                "nonce-evidence-proof-0002",
                200,
                103
            ),
            Err(SecurityStoreError::RevokedEvidenceKey)
        );
    }

    #[test]
    fn rollback_evidence_nonce_is_atomically_single_use_under_concurrency() {
        let store = std::sync::Arc::new(SqliteSecurityStore::open_in_memory().unwrap());
        let workers = (0..8)
            .map(|_| {
                let store = std::sync::Arc::clone(&store);
                std::thread::spawn(move || {
                    store.consume_rollback_evidence_nonce(
                        "issuer:concurrent",
                        "key:concurrent",
                        "nonce-concurrent-evidence-proof-0001",
                        500,
                        100,
                    )
                })
            })
            .collect::<Vec<_>>();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            results.iter().filter(|result| **result == Ok(())).count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(SecurityStoreError::EvidenceReplay))
                .count(),
            7
        );
    }

    #[test]
    fn expired_rollback_evidence_nonce_can_be_reissued_after_expiry() {
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        assert_eq!(
            store.consume_rollback_evidence_nonce(
                "issuer:expiry",
                "key:expiry",
                "nonce-expiring-evidence-proof-0001",
                200,
                100,
            ),
            Ok(())
        );
        assert_eq!(
            store.consume_rollback_evidence_nonce(
                "issuer:expiry",
                "key:expiry",
                "nonce-expiring-evidence-proof-0001",
                300,
                200,
            ),
            Ok(())
        );
    }

    #[test]
    fn rollback_revocation_floor_is_monotonic_and_revision_bound() {
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        assert_eq!(store.advance_rollback_revocation_floor(10, 5), Ok(()));
        assert_eq!(store.advance_rollback_revocation_floor(10, 5), Ok(()));
        assert_eq!(
            store.advance_rollback_revocation_floor(9, 6),
            Err(SecurityStoreError::RevocationFloorRollback)
        );
        assert_eq!(
            store.advance_rollback_revocation_floor(11, 5),
            Err(SecurityStoreError::ConflictingRevocationFloor)
        );
        assert_eq!(store.advance_rollback_revocation_floor(11, 6), Ok(()));
        assert_eq!(
            store.advance_rollback_revocation_floor(10, 7),
            Err(SecurityStoreError::RevocationFloorRollback)
        );
    }

    fn artifact_digest(value: &serde_json::Value) -> String {
        use sha2::{Digest, Sha256};
        let bytes = crate::canonical_json(value).unwrap();
        format!("{:x}", Sha256::digest(bytes))
    }

    fn insert_lineage_artifact(
        store: &SqliteSecurityStore,
        version: &str,
        value: &serde_json::Value,
        parent_version: Option<&str>,
        parent_digest: Option<&str>,
        mutation_id: Option<&str>,
        epoch: i64,
    ) -> String {
        let digest = artifact_digest(value);
        let connection = store.connection.lock().unwrap();
        connection
            .execute(
                "INSERT INTO version_lineage_artifacts(
                    gene_id, version, artifact_digest, artifact_json,
                    parent_version, parent_digest, mutation_id, epoch
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    "g12.version-lineage",
                    version,
                    digest,
                    serde_json::to_string(value).unwrap(),
                    parent_version,
                    parent_digest,
                    mutation_id,
                    epoch
                ],
            )
            .unwrap();
        digest
    }

    #[test]
    fn sqlite_version_lineage_registry_resolves_immutable_chain_and_mutation() {
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        let root_value = serde_json::json!({"version":1});
        let middle_value = serde_json::json!({"version":2});
        let candidate_value = serde_json::json!({"version":3});
        let root_digest =
            insert_lineage_artifact(&store, "1.0.0", &root_value, None, None, None, 0);
        let middle_digest = insert_lineage_artifact(
            &store,
            "1.1.0",
            &middle_value,
            Some("1.0.0"),
            Some(&root_digest),
            Some("mutation-1"),
            1,
        );
        let candidate_digest = insert_lineage_artifact(
            &store,
            "1.2.0",
            &candidate_value,
            Some("1.1.0"),
            Some(&middle_digest),
            Some("mutation-2"),
            2,
        );
        {
            let connection = store.connection.lock().unwrap();
            connection
                .execute(
                    "INSERT INTO version_lineage_mutations(
                        mutation_ref, mutation_id, source_version, source_digest,
                        target_version, target_digest, approved, gates_passed, approval_commitment
                     ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 1, 1, ?7)",
                    params![
                        "mutation-ref-2",
                        "mutation-2",
                        "1.1.0",
                        middle_digest,
                        "1.2.0",
                        candidate_digest,
                        "a".repeat(64)
                    ],
                )
                .unwrap();
            connection
                .execute(
                    "UPDATE version_lineage_registry_meta SET revision=42 WHERE singleton=1",
                    [],
                )
                .unwrap();
        }

        let record = store.resolve_lineage("1.2.0", &candidate_digest).unwrap();
        assert_eq!(record.ancestry.len(), 3);
        assert_eq!(record.ancestry[0].version, "1.0.0");
        assert_eq!(record.ancestry[1].version, "1.1.0");
        assert_eq!(record.ancestry[2].version, "1.2.0");
        assert_eq!(record.registry_revision, 42);
        assert_eq!(
            record
                .mutation
                .as_ref()
                .map(|mutation| mutation.mutation_ref.as_str()),
            Some("mutation-ref-2")
        );
        assert!(record.mutation.as_ref().unwrap().approved);
        assert!(record.mutation.as_ref().unwrap().gates_passed);
    }

    #[test]
    fn sqlite_version_lineage_registry_rejects_unknown_and_cyclic_ancestry() {
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        assert_eq!(
            store.resolve_lineage("9.9.9", &"a".repeat(64)),
            Err(LineageRegistryError::UnknownVersion)
        );

        let value_a = serde_json::json!({"node":"a"});
        let value_b = serde_json::json!({"node":"b"});
        let digest_a = artifact_digest(&value_a);
        let digest_b = artifact_digest(&value_b);
        {
            let connection = store.connection.lock().unwrap();
            connection
                .execute(
                    "INSERT INTO version_lineage_artifacts(
                        gene_id, version, artifact_digest, artifact_json,
                        parent_version, parent_digest, mutation_id, epoch
                     ) VALUES(?1, '1.0.0', ?2, ?3, '1.1.0', ?4, 'mutation-a', 1)",
                    params![
                        "g12.version-lineage",
                        digest_a,
                        serde_json::to_string(&value_a).unwrap(),
                        digest_b
                    ],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO version_lineage_artifacts(
                        gene_id, version, artifact_digest, artifact_json,
                        parent_version, parent_digest, mutation_id, epoch
                     ) VALUES(?1, '1.1.0', ?2, ?3, '1.0.0', ?4, 'mutation-b', 2)",
                    params![
                        "g12.version-lineage",
                        digest_b,
                        serde_json::to_string(&value_b).unwrap(),
                        digest_a
                    ],
                )
                .unwrap();
        }
        assert_eq!(
            store.resolve_lineage("1.1.0", &digest_b),
            Err(LineageRegistryError::IntegrityFailure)
        );
    }
}
