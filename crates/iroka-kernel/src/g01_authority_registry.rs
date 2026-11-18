//! Owner-authorized, root-signed G01 authority registries.
//!
//! A single canonical snapshot carries three independent registries: identity roots,
//! identity succession proofs, and compatibility contracts/policies. Snapshots are
//! signed by an out-of-band TrustRoot, monotonic, expiry-bounded and durably retained.
//! The G12 artifact lineage registry is deliberately not reused here.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Mutex,
    time::Duration,
};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    g01_identity_root::{
        AlgorithmPolicyEvidence, IdentityRootError, IdentityRootInput, IdentityRootRegistry,
        IdentityRootRegistryRecord, IssuerLinkEvidence, RootStatus,
    },
    RevocationChecker, SqliteSecurityStore, TrustRootSet, TrustStore,
};

const MAX_SNAPSHOT_LIFETIME: u64 = 31_536_000;
const MAX_CLOCK_SKEW: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedG01AuthoritySnapshot {
    pub root_key_id: String,
    pub revision: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub identity_roots: Vec<IdentityRootRecord>,
    pub succession_proofs: Vec<IdentitySuccessionProof>,
    pub contracts: Vec<CompatibilityContract>,
    pub compatibility_policies: Vec<CompatibilityPolicy>,
    pub algorithm_policies: Vec<AlgorithmPolicyRecord>,
    pub signature: Vec<u8>,
}

impl SignedG01AuthoritySnapshot {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, G01RegistryError> {
        #[derive(Serialize)]
        struct Envelope<'a> {
            root_key_id: &'a str,
            revision: u64,
            issued_at: u64,
            expires_at: u64,
            identity_roots: &'a [IdentityRootRecord],
            succession_proofs: &'a [IdentitySuccessionProof],
            contracts: &'a [CompatibilityContract],
            compatibility_policies: &'a [CompatibilityPolicy],
            algorithm_policies: &'a [AlgorithmPolicyRecord],
        }
        serde_json::to_vec(&Envelope {
            root_key_id: &self.root_key_id,
            revision: self.revision,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            identity_roots: &self.identity_roots,
            succession_proofs: &self.succession_proofs,
            contracts: &self.contracts,
            compatibility_policies: &self.compatibility_policies,
            algorithm_policies: &self.algorithm_policies,
        })
        .map_err(|_| G01RegistryError::Malformed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityRootRecord {
    pub root_id: String,
    pub issuer_id: String,
    pub key_id: String,
    pub key_material_ref: String,
    pub key_fingerprint: String,
    pub algorithm: String,
    pub algorithm_policy_id: String,
    pub algorithm_policy_version: String,
    pub activation_epoch: u64,
    pub status: RootStatus,
    pub key_status: RootStatus,
    pub issuer_chain: Vec<IssuerLinkEvidence>,
    pub provenance: serde_json::Value,
    pub version_bound_evidence: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AlgorithmPolicyRecord {
    pub policy_id: String,
    pub version: String,
    pub allowed_algorithms: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentitySuccessionProof {
    pub proof_id: String,
    pub predecessor_identity: String,
    pub successor_identity: String,
    pub issuer_id: String,
    pub signing_key_id: String,
    pub proof_digest: String,
    pub issued_epoch: u64,
    pub effective_epoch: u64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityContract {
    pub contract_id: String,
    pub version: String,
    pub digest: String,
    pub issuer_id: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityPolicy {
    pub policy_id: String,
    pub version: String,
    pub issuer_id: String,
    pub contract_id: String,
    pub contract_version: String,
    pub contract_digest: String,
    pub compatible_contracts: BTreeMap<String, String>,
    pub migration_required: bool,
    pub migration_ref: Option<String>,
    pub migration_digest: Option<String>,
    pub valid_from: u64,
    pub valid_until: u64,
}

/// Independently signed identity-root registry envelope. Its revision and
/// signature are independent of succession and compatibility registries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedIdentityRootRegistryEnvelope {
    pub root_key_id: String,
    pub revision: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub identity_roots: Vec<IdentityRootRecord>,
    pub algorithm_policies: Vec<AlgorithmPolicyRecord>,
    pub signature: Vec<u8>,
}

impl SignedIdentityRootRegistryEnvelope {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, G01RegistryError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            registry: &'static str,
            root_key_id: &'a str,
            revision: u64,
            issued_at: u64,
            expires_at: u64,
            identity_roots: &'a [IdentityRootRecord],
            algorithm_policies: &'a [AlgorithmPolicyRecord],
        }
        serde_jcs::to_vec(&Payload {
            registry: "g01.identity_roots",
            root_key_id: &self.root_key_id,
            revision: self.revision,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            identity_roots: &self.identity_roots,
            algorithm_policies: &self.algorithm_policies,
        })
        .map_err(|_| G01RegistryError::Malformed)
    }
}

/// Issuer-signed succession proof. The proof digest commits to the canonical
/// payload (excluding the digest and signature fields).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedIdentitySuccessionProof {
    pub proof: IdentitySuccessionProof,
    pub signature: Vec<u8>,
}

impl SignedIdentitySuccessionProof {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, G01RegistryError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            proof_id: &'a str,
            predecessor_identity: &'a str,
            successor_identity: &'a str,
            issuer_id: &'a str,
            signing_key_id: &'a str,
            issued_epoch: u64,
            effective_epoch: u64,
            status: &'a str,
        }
        serde_jcs::to_vec(&Payload {
            proof_id: &self.proof.proof_id,
            predecessor_identity: &self.proof.predecessor_identity,
            successor_identity: &self.proof.successor_identity,
            issuer_id: &self.proof.issuer_id,
            signing_key_id: &self.proof.signing_key_id,
            issued_epoch: self.proof.issued_epoch,
            effective_epoch: self.proof.effective_epoch,
            status: &self.proof.status,
        })
        .map_err(|_| G01RegistryError::Malformed)
    }

    pub fn verify(&self, trust: &TrustStore, now: u64) -> Result<(), G01RegistryError> {
        let bytes = self.signing_bytes()?;
        let digest = Sha256::digest(&bytes);
        if self.proof.proof_digest != format!("sha256:{digest:x}") {
            return Err(G01RegistryError::InvalidSuccessionDigest);
        }
        let public_key = trust
            .trusted_public_key(
                &self.proof.issuer_id,
                &self.proof.signing_key_id,
                now,
            )
            .map_err(|_| G01RegistryError::UnknownIssuerKey)?;
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| G01RegistryError::UnknownIssuerKey)?;
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| G01RegistryError::Malformed)?;
        key.verify(&bytes, &signature)
            .map_err(|_| G01RegistryError::InvalidSuccessionSignature)
    }
}

/// Independently signed succession registry envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedSuccessionRegistryEnvelope {
    pub root_key_id: String,
    pub revision: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub proofs: Vec<SignedIdentitySuccessionProof>,
    pub signature: Vec<u8>,
}

impl SignedSuccessionRegistryEnvelope {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, G01RegistryError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            registry: &'static str,
            root_key_id: &'a str,
            revision: u64,
            issued_at: u64,
            expires_at: u64,
            proofs: &'a [SignedIdentitySuccessionProof],
        }
        serde_jcs::to_vec(&Payload {
            registry: "g01.identity_succession",
            root_key_id: &self.root_key_id,
            revision: self.revision,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            proofs: &self.proofs,
        })
        .map_err(|_| G01RegistryError::Malformed)
    }
}

/// Independently signed compatibility and migration registry envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedCompatibilityRegistryEnvelope {
    pub root_key_id: String,
    pub revision: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub contracts: Vec<CompatibilityContract>,
    pub policies: Vec<CompatibilityPolicy>,
    pub signature: Vec<u8>,
}

impl SignedCompatibilityRegistryEnvelope {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, G01RegistryError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            registry: &'static str,
            root_key_id: &'a str,
            revision: u64,
            issued_at: u64,
            expires_at: u64,
            contracts: &'a [CompatibilityContract],
            policies: &'a [CompatibilityPolicy],
        }
        serde_jcs::to_vec(&Payload {
            registry: "g01.compatibility",
            root_key_id: &self.root_key_id,
            revision: self.revision,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            contracts: &self.contracts,
            policies: &self.policies,
        })
        .map_err(|_| G01RegistryError::Malformed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationArtifactError {
    Unavailable,
}

/// Resolves immutable migration artifact bytes by authenticated content reference.
/// Implementations must not silently substitute mutable "latest" artifacts.
pub trait MigrationArtifactResolver {
    fn resolve_immutable(&self, reference: &str) -> Result<Vec<u8>, MigrationArtifactError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum G01RegistryError {
    Malformed,
    UnknownRoot,
    InvalidRootSignature,
    Expired,
    NotYetValid,
    ExcessiveLifetime,
    Rollback,
    ConflictingRevision,
    InvalidSnapshot,
    StoreUnavailable,
    UnknownIdentity,
    UnknownProof,
    UnknownContract,
    UnknownPolicy,
    RevokedKey,
    RevocationUnavailable,
    InvalidSuccessionDigest,
    InvalidSuccessionSignature,
    UnknownIssuerKey,
    MigrationArtifactUnavailable,
    MigrationArtifactMismatch,
}

pub struct SqliteG01AuthorityStore {
    connection: Mutex<Connection>,
}

impl SqliteG01AuthorityStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, G01RegistryError> {
        let connection = Connection::open(path).map_err(|_| G01RegistryError::StoreUnavailable)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(|_| G01RegistryError::StoreUnavailable)?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS g01_authority_snapshot(
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               revision INTEGER NOT NULL CHECK(revision>0),
               digest BLOB NOT NULL CHECK(length(digest)=32),
               expires_at INTEGER NOT NULL,
               document TEXT NOT NULL
             );",
            )
            .map_err(|_| G01RegistryError::StoreUnavailable)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn open_in_memory() -> Result<Self, G01RegistryError> {
        let connection =
            Connection::open_in_memory().map_err(|_| G01RegistryError::StoreUnavailable)?;
        connection
            .execute_batch(
                "CREATE TABLE g01_authority_snapshot(
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               revision INTEGER NOT NULL CHECK(revision>0),
               digest BLOB NOT NULL CHECK(length(digest)=32),
               expires_at INTEGER NOT NULL,
               document TEXT NOT NULL
             );",
            )
            .map_err(|_| G01RegistryError::StoreUnavailable)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn install_signed_snapshot(
        &self,
        signed: &SignedG01AuthoritySnapshot,
        roots: &TrustRootSet,
        now: u64,
    ) -> Result<(), G01RegistryError> {
        let root = roots
            .get(&signed.root_key_id)
            .map_err(|_| G01RegistryError::UnknownRoot)?;
        if now < root.not_before {
            return Err(G01RegistryError::NotYetValid);
        }
        if now >= root.not_after {
            return Err(G01RegistryError::Expired);
        }
        if signed.revision == 0
            || signed.issued_at >= signed.expires_at
            || signed.issued_at > now.saturating_add(MAX_CLOCK_SKEW)
            || signed.expires_at <= now.saturating_sub(MAX_CLOCK_SKEW)
        {
            return Err(G01RegistryError::Expired);
        }
        if signed.expires_at - signed.issued_at > MAX_SNAPSHOT_LIFETIME {
            return Err(G01RegistryError::ExcessiveLifetime);
        }
        validate_snapshot(signed)?;
        let key = VerifyingKey::from_bytes(&root.public_key)
            .map_err(|_| G01RegistryError::UnknownRoot)?;
        let bytes = signed.signing_bytes()?;
        let signature =
            Signature::from_slice(&signed.signature).map_err(|_| G01RegistryError::Malformed)?;
        key.verify(&bytes, &signature)
            .map_err(|_| G01RegistryError::InvalidRootSignature)?;
        let digest = Sha256::digest(&bytes);
        let document = serde_json::to_string(signed).map_err(|_| G01RegistryError::Malformed)?;
        let revision = i64::try_from(signed.revision).map_err(|_| G01RegistryError::Malformed)?;
        let expires = i64::try_from(signed.expires_at).map_err(|_| G01RegistryError::Malformed)?;
        let mut conn = self
            .connection
            .lock()
            .map_err(|_| G01RegistryError::StoreUnavailable)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| G01RegistryError::StoreUnavailable)?;
        let old: Option<(i64, Vec<u8>, String)> = tx
            .query_row(
                "SELECT revision,digest,document FROM g01_authority_snapshot WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| G01RegistryError::StoreUnavailable)?;
        if let Some((old_revision, old_digest, old_doc)) = old {
            if revision < old_revision {
                return Err(G01RegistryError::Rollback);
            }
            if revision == old_revision {
                if old_digest.as_slice() != digest.as_slice() || old_doc != document {
                    return Err(G01RegistryError::ConflictingRevision);
                }
                tx.commit()
                    .map_err(|_| G01RegistryError::StoreUnavailable)?;
                return Ok(());
            }
        }
        tx.execute(
            "INSERT INTO g01_authority_snapshot(singleton,revision,digest,expires_at,document)
             VALUES(1,?1,?2,?3,?4)
             ON CONFLICT(singleton) DO UPDATE SET revision=excluded.revision,
             digest=excluded.digest,expires_at=excluded.expires_at,document=excluded.document",
            params![revision, digest.as_slice(), expires, document],
        )
        .map_err(|_| G01RegistryError::StoreUnavailable)?;
        tx.commit().map_err(|_| G01RegistryError::StoreUnavailable)
    }

    fn latest_snapshot(&self) -> Result<SignedG01AuthoritySnapshot, G01RegistryError> {
        let conn = self
            .connection
            .lock()
            .map_err(|_| G01RegistryError::StoreUnavailable)?;
        let doc: String = conn
            .query_row(
                "SELECT document FROM g01_authority_snapshot WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| G01RegistryError::StoreUnavailable)?
            .ok_or(G01RegistryError::StoreUnavailable)?;
        serde_json::from_str(&doc).map_err(|_| G01RegistryError::Malformed)
    }

    fn active_snapshot(&self, now: u64) -> Result<SignedG01AuthoritySnapshot, G01RegistryError> {
        let snapshot = self.latest_snapshot()?;
        if now < snapshot.issued_at || now >= snapshot.expires_at {
            return Err(G01RegistryError::Expired);
        }
        Ok(snapshot)
    }

    fn active_verified_snapshot(
        &self,
        roots: &TrustRootSet,
        now: u64,
    ) -> Result<SignedG01AuthoritySnapshot, G01RegistryError> {
        let snapshot = self.active_snapshot(now)?;
        let root = roots
            .get(&snapshot.root_key_id)
            .map_err(|_| G01RegistryError::UnknownRoot)?;
        if now < root.not_before || now >= root.not_after {
            return Err(G01RegistryError::Expired);
        }
        validate_snapshot(&snapshot)?;
        let key = VerifyingKey::from_bytes(&root.public_key)
            .map_err(|_| G01RegistryError::UnknownRoot)?;
        let bytes = snapshot.signing_bytes()?;
        let signature =
            Signature::from_slice(&snapshot.signature).map_err(|_| G01RegistryError::Malformed)?;
        key.verify(&bytes, &signature)
            .map_err(|_| G01RegistryError::InvalidRootSignature)?;
        Ok(snapshot)
    }

    pub fn resolve_succession(
        &self,
        proof_id: &str,
        roots: &TrustRootSet,
        now: u64,
    ) -> Result<IdentitySuccessionProof, G01RegistryError> {
        let snapshot = self.active_verified_snapshot(roots, now)?;
        snapshot
            .succession_proofs
            .into_iter()
            .find(|p| p.proof_id == proof_id)
            .ok_or(G01RegistryError::UnknownProof)
    }

    pub fn resolve_compatibility(
        &self,
        policy_id: &str,
        version: &str,
        roots: &TrustRootSet,
        now: u64,
    ) -> Result<(CompatibilityContract, CompatibilityPolicy), G01RegistryError> {
        let snapshot = self.active_verified_snapshot(roots, now)?;
        let policy = snapshot
            .compatibility_policies
            .into_iter()
            .find(|p| p.policy_id == policy_id && p.version == version)
            .ok_or(G01RegistryError::UnknownPolicy)?;
        if now < policy.valid_from || now >= policy.valid_until {
            return Err(G01RegistryError::Expired);
        }
        let contract = snapshot
            .contracts
            .into_iter()
            .find(|c| {
                c.contract_id == policy.contract_id
                    && c.version == policy.contract_version
                    && c.digest == policy.contract_digest
            })
            .ok_or(G01RegistryError::UnknownContract)?;
        Ok((contract, policy))
    }

    pub fn revision(&self) -> Result<u64, G01RegistryError> {
        let conn = self
            .connection
            .lock()
            .map_err(|_| G01RegistryError::StoreUnavailable)?;
        let revision: Option<i64> = conn
            .query_row(
                "SELECT revision FROM g01_authority_snapshot WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| G01RegistryError::StoreUnavailable)?;
        revision
            .map(|v| u64::try_from(v).map_err(|_| G01RegistryError::Malformed))
            .transpose()?
            .ok_or(G01RegistryError::StoreUnavailable)
    }
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn validate_snapshot(s: &SignedG01AuthoritySnapshot) -> Result<(), G01RegistryError> {
    if s.identity_roots.is_empty()
        || s.contracts.is_empty()
        || s.compatibility_policies.is_empty()
        || s.algorithm_policies.is_empty()
        || s.identity_roots.len() > 4096
        || s.succession_proofs.len() > 100_000
        || s.contracts.len() > 10_000
        || s.compatibility_policies.len() > 10_000
        || s.algorithm_policies.len() > 10_000
    {
        return Err(G01RegistryError::InvalidSnapshot);
    }
    let mut ids = BTreeSet::new();
    for r in &s.identity_roots {
        if r.root_id.trim().is_empty()
            || r.issuer_id.trim().is_empty()
            || r.key_id.trim().is_empty()
            || r.key_material_ref.trim().is_empty()
            || !valid_sha256(&r.key_fingerprint)
            || r.algorithm.trim().is_empty()
            || r.algorithm_policy_id.trim().is_empty()
            || r.algorithm_policy_version.trim().is_empty()
            || r.issuer_chain.is_empty()
            || !r.provenance.is_object()
            || !r.version_bound_evidence.is_object()
            || !ids.insert(r.root_id.clone())
        {
            return Err(G01RegistryError::InvalidSnapshot);
        }
    }
    ids.clear();
    for p in &s.algorithm_policies {
        if p.policy_id.trim().is_empty()
            || p.version.trim().is_empty()
            || p.allowed_algorithms.is_empty()
            || p.allowed_algorithms
                .iter()
                .any(|algorithm| algorithm.trim().is_empty())
            || !ids.insert(format!("{}@{}", p.policy_id, p.version))
        {
            return Err(G01RegistryError::InvalidSnapshot);
        }
    }
    for root in &s.identity_roots {
        if !s.algorithm_policies.iter().any(|policy| {
            policy.policy_id == root.algorithm_policy_id
                && policy.version == root.algorithm_policy_version
        }) {
            return Err(G01RegistryError::InvalidSnapshot);
        }
    }
    ids.clear();
    for p in &s.succession_proofs {
        if p.proof_id.trim().is_empty()
            || p.predecessor_identity.trim().is_empty()
            || p.successor_identity.trim().is_empty()
            || p.predecessor_identity == p.successor_identity
            || p.issuer_id.trim().is_empty()
            || p.signing_key_id.trim().is_empty()
            || !valid_sha256(&p.proof_digest)
            || p.effective_epoch < p.issued_epoch
            || p.status != "active"
            || !ids.insert(p.proof_id.clone())
        {
            return Err(G01RegistryError::InvalidSnapshot);
        }
    }
    ids.clear();
    for c in &s.contracts {
        if c.contract_id.trim().is_empty()
            || c.version.trim().is_empty()
            || !valid_sha256(&c.digest)
            || c.issuer_id.trim().is_empty()
            || c.status != "active"
            || !ids.insert(format!("{}@{}", c.contract_id, c.version))
        {
            return Err(G01RegistryError::InvalidSnapshot);
        }
    }
    ids.clear();
    for p in &s.compatibility_policies {
        if p.policy_id.trim().is_empty()
            || p.version.trim().is_empty()
            || p.issuer_id.trim().is_empty()
            || p.contract_id.trim().is_empty()
            || p.contract_version.trim().is_empty()
            || !valid_sha256(&p.contract_digest)
            || p.valid_from >= p.valid_until
            || !ids.insert(format!("{}@{}", p.policy_id, p.version))
        {
            return Err(G01RegistryError::InvalidSnapshot);
        }
        match (
            p.migration_required,
            p.migration_ref.as_deref(),
            p.migration_digest.as_deref(),
        ) {
            (true, Some(r), Some(d)) if !r.trim().is_empty() && valid_sha256(d) => {}
            (false, None, None) => {}
            _ => return Err(G01RegistryError::InvalidSnapshot),
        }
        if p.compatible_contracts.values().any(|d| !valid_sha256(d)) {
            return Err(G01RegistryError::InvalidSnapshot);
        }
    }
    Ok(())
}

impl IdentityRootRegistry for SqliteG01AuthorityStore {
    fn resolve_root(
        &self,
        input: &IdentityRootInput,
    ) -> Result<IdentityRootRegistryRecord, IdentityRootError> {
        let snapshot = self
            .latest_snapshot()
            .map_err(|_| IdentityRootError::RegistryUnavailable)?;
        let record = snapshot
            .identity_roots
            .into_iter()
            .find(|r| r.root_id == input.root_id)
            .ok_or(IdentityRootError::UnknownRoot)?;
        if record.issuer_id != input.issuer_id {
            return Err(IdentityRootError::UnknownIssuer);
        }
        if record.key_material_ref != input.key_material_ref {
            return Err(IdentityRootError::KeyMaterialUnavailable);
        }
        if record.key_fingerprint != input.key_fingerprint {
            return Err(IdentityRootError::FingerprintMismatch);
        }
        if record.algorithm_policy_id != input.algorithm_policy_id
            || record.algorithm_policy_version != input.algorithm_policy_version
            || record.algorithm != input.algorithm
        {
            return Err(IdentityRootError::PolicyVersionMismatch);
        }
        if record.activation_epoch != input.activation_epoch
            || record.status != input.status
            || record.provenance != input.provenance
            || record.version_bound_evidence != input.version_bound_evidence
        {
            return Err(IdentityRootError::RootRecordMismatch);
        }
        let chain = record.issuer_chain.clone();
        if chain.last().map(|x| x.issuer_id.as_str()) != Some(record.issuer_id.as_str()) {
            return Err(IdentityRootError::UnknownIssuer);
        }
        let policy_record = snapshot
            .algorithm_policies
            .iter()
            .find(|p| {
                p.policy_id == record.algorithm_policy_id
                    && p.version == record.algorithm_policy_version
            })
            .ok_or(IdentityRootError::PolicyUnavailable)?;
        let algorithm_allowed = policy_record.allowed_algorithms.contains(&record.algorithm);
        let policy = AlgorithmPolicyEvidence {
            policy_id: record.algorithm_policy_id.clone(),
            policy_version: record.algorithm_policy_version.clone(),
            algorithm: record.algorithm.clone(),
            allowed: algorithm_allowed,
        };
        Ok(IdentityRootRegistryRecord {
            root_id: record.root_id,
            issuer_id: record.issuer_id,
            key_fingerprint: record.key_fingerprint,
            key_material_ref: record.key_material_ref,
            algorithm: record.algorithm,
            algorithm_policy: policy,
            activation_epoch: record.activation_epoch,
            status: record.status,
            key_status: record.key_status,
            issuer_chain: chain,
            provenance_verified: true,
            version_evidence_verified: true,
        })
    }
}

/// Production gate combining the root-signed canonical registry, the verified
/// signed trust bundle, and live revocation state. Public keys are never accepted
/// from caller input; the fingerprint and key binding must match the active trust
/// snapshot, and a revoked/unavailable revocation store cannot yield trust.
pub fn evaluate_identity_root_production(
    registry: &SqliteG01AuthorityStore,
    trust: &TrustStore,
    roots: &TrustRootSet,
    revocations: &SqliteSecurityStore,
    input: &IdentityRootInput,
    evaluated_epoch: u64,
    now_unix: u64,
) -> Result<crate::g01_identity_root::IdentityRootOutput, IdentityRootError> {
    let snapshot = registry
        .active_verified_snapshot(roots, now_unix)
        .map_err(|_| IdentityRootError::RegistryUnavailable)?;
    let record = snapshot
        .identity_roots
        .iter()
        .find(|r| r.root_id == input.root_id)
        .ok_or(IdentityRootError::UnknownRoot)?;
    let public_key = trust
        .trusted_public_key(&record.issuer_id, &record.key_id, now_unix)
        .map_err(|_| IdentityRootError::KeyMaterialUnavailable)?;
    let digest = Sha256::digest(public_key);
    let fingerprint = format!("sha256:{digest:x}");
    if fingerprint != record.key_fingerprint || fingerprint != input.key_fingerprint {
        return Err(IdentityRootError::FingerprintMismatch);
    }
    if record.issuer_id != input.issuer_id
        || record.key_material_ref != input.key_material_ref
        || record.algorithm != input.algorithm
        || record.algorithm_policy_id != input.algorithm_policy_id
        || record.algorithm_policy_version != input.algorithm_policy_version
        || record.activation_epoch != input.activation_epoch
        || record.status != input.status
        || record.provenance != input.provenance
        || record.version_bound_evidence != input.version_bound_evidence
    {
        return Err(IdentityRootError::RootRecordMismatch);
    }
    let revoked = revocations
        .key_revoked(&record.issuer_id, &record.key_id)
        .map_err(|_| IdentityRootError::RegistryUnavailable)?;
    let mut adapter = record.clone();
    if revoked {
        adapter.key_status = RootStatus::Revoked;
    }
    let registry_record = IdentityRootRegistryRecord {
        root_id: adapter.root_id.clone(),
        issuer_id: adapter.issuer_id.clone(),
        key_fingerprint: adapter.key_fingerprint.clone(),
        key_material_ref: adapter.key_material_ref.clone(),
        algorithm: adapter.algorithm.clone(),
        algorithm_policy: {
            let p = snapshot
                .algorithm_policies
                .iter()
                .find(|p| {
                    p.policy_id == adapter.algorithm_policy_id
                        && p.version == adapter.algorithm_policy_version
                })
                .ok_or(IdentityRootError::PolicyUnavailable)?;
            AlgorithmPolicyEvidence {
                policy_id: adapter.algorithm_policy_id.clone(),
                policy_version: adapter.algorithm_policy_version.clone(),
                algorithm: adapter.algorithm.clone(),
                allowed: p.allowed_algorithms.contains(&adapter.algorithm),
            }
        },
        activation_epoch: adapter.activation_epoch,
        status: adapter.status,
        key_status: adapter.key_status,
        issuer_chain: adapter.issuer_chain.clone(),
        provenance_verified: true,
        version_evidence_verified: true,
    };
    struct Bound(IdentityRootRegistryRecord);
    impl IdentityRootRegistry for Bound {
        fn resolve_root(
            &self,
            _: &IdentityRootInput,
        ) -> Result<IdentityRootRegistryRecord, IdentityRootError> {
            Ok(self.0.clone())
        }
    }
    let bound = Bound(registry_record);
    crate::g01_identity_root::evaluate_identity_root(&bound, input, evaluated_epoch)
}
