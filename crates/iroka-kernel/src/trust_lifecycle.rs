//! Root-signed trust-bundle lifecycle: verification, expiry and rollback protection.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, RwLock};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    canonical_json, RegisteredLineageArtifact, RegisteredMutationRecord,
    RollbackEvidenceTrustPolicy, SecurityStoreError, SignedVersionLineageRegistrySnapshot,
    SqliteSecurityStore, TrustConfigError, TrustStore, TrustedKey,
};

const MAX_BUNDLE_LIFETIME_SECS: u64 = 31_536_000;
const MAX_CLOCK_SKEW_SECS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustBundlePayload {
    pub version: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub trusted_issuers: Vec<String>,
    pub keys: Vec<TrustedKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedTrustBundle {
    pub root_key_id: String,
    pub payload: TrustBundlePayload,
    pub signature: Vec<u8>,
}

impl SignedTrustBundle {
    pub fn from_signature(
        root_key_id: impl Into<String>,
        payload: TrustBundlePayload,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            root_key_id: root_key_id.into(),
            payload,
            signature,
        }
    }

    pub fn signing_bytes_for(
        root_key_id: &str,
        payload: &TrustBundlePayload,
    ) -> Result<Vec<u8>, TrustBundleError> {
        #[derive(Serialize)]
        struct Envelope<'a> {
            root_key_id: &'a str,
            payload: &'a TrustBundlePayload,
        }
        serde_json::to_vec(&Envelope {
            root_key_id,
            payload,
        })
        .map_err(|_| TrustBundleError::Malformed)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, TrustBundleError> {
        Self::signing_bytes_for(&self.root_key_id, &self.payload)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RollbackEvidencePolicyPayload {
    pub version: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub allowed_issuers: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedRollbackEvidencePolicy {
    pub root_key_id: String,
    pub payload: RollbackEvidencePolicyPayload,
    pub signature: Vec<u8>,
}

#[rustfmt::skip]
impl SignedRollbackEvidencePolicy {
    pub fn from_signature(
        root_key_id: impl Into<String>,
        payload: RollbackEvidencePolicyPayload,
        signature: Vec<u8>,
    ) -> Self {
        Self { root_key_id: root_key_id.into(), payload, signature }
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, TrustBundleError> {
        #[derive(Serialize)]
        struct Envelope<'a> {
            root_key_id: &'a str,
            payload: &'a RollbackEvidencePolicyPayload,
        }
        serde_json::to_vec(&Envelope { root_key_id: &self.root_key_id, payload: &self.payload })
            .map_err(|_| TrustBundleError::Malformed)
    }
}

#[derive(Debug, Clone)]
pub struct TrustRoot {
    pub key_id: String,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    /// Owner-controlled provenance record for this offline root ceremony.
    pub provenance_ref: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustBundleError {
    Malformed,
    InvalidRoot,
    RootOutsideValidity,
    InvalidSignature,
    NotYetValid,
    Expired,
    ExcessiveLifetime,
    NonCanonicalOrdering,
    InvalidTrustConfiguration,
    Rollback,
    StoreUnavailable,
}

impl From<TrustConfigError> for TrustBundleError {
    fn from(_: TrustConfigError) -> Self {
        Self::InvalidTrustConfiguration
    }
}

impl From<SecurityStoreError> for TrustBundleError {
    fn from(error: SecurityStoreError) -> Self {
        match error {
            SecurityStoreError::Rollback | SecurityStoreError::ConflictingVersion => Self::Rollback,
            _ => Self::StoreUnavailable,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrustRootSet {
    roots: HashMap<String, TrustRoot>,
}

impl TrustRootSet {
    pub fn new(roots: Vec<TrustRoot>) -> Result<Self, TrustBundleError> {
        if roots.is_empty() {
            return Err(TrustBundleError::InvalidRoot);
        }
        let mut indexed = HashMap::new();
        for root in roots {
            if root.key_id.trim().is_empty()
                || root.not_before >= root.not_after
                || root.provenance_ref.trim().is_empty()
                || VerifyingKey::from_bytes(&root.public_key).is_err()
                || indexed.insert(root.key_id.clone(), root).is_some()
            {
                return Err(TrustBundleError::InvalidRoot);
            }
        }
        Ok(Self { roots: indexed })
    }

    pub(crate) fn get(&self, key_id: &str) -> Result<&TrustRoot, TrustBundleError> {
        self.roots.get(key_id).ok_or(TrustBundleError::InvalidRoot)
    }
}

/// Verify a bundle signed by the out-of-band trust root, persist anti-rollback
/// state, and return a validated immutable trust snapshot for atomic publication.
/// The caller must only swap the active snapshot after this function succeeds.
pub fn verify_and_install_trust_bundle(
    bundle: &SignedTrustBundle,
    root: &TrustRoot,
    store: &SqliteSecurityStore,
    now: u64,
) -> Result<TrustStore, TrustBundleError> {
    if root.key_id.trim().is_empty()
        || root.key_id != bundle.root_key_id
        || root.not_before >= root.not_after
        || root.provenance_ref.trim().is_empty()
        || VerifyingKey::from_bytes(&root.public_key).is_err()
    {
        return Err(TrustBundleError::InvalidRoot);
    }
    if now < root.not_before || now >= root.not_after {
        return Err(TrustBundleError::RootOutsideValidity);
    }
    let p = &bundle.payload;
    if p.version == 0
        || p.issued_at >= p.expires_at
        || p.trusted_issuers.is_empty()
        || p.keys.is_empty()
    {
        return Err(TrustBundleError::Malformed);
    }
    if p.issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(TrustBundleError::NotYetValid);
    }
    if p.expires_at <= now.saturating_sub(MAX_CLOCK_SKEW_SECS) {
        return Err(TrustBundleError::Expired);
    }
    if p.expires_at - p.issued_at > MAX_BUNDLE_LIFETIME_SECS {
        return Err(TrustBundleError::ExcessiveLifetime);
    }
    if p.trusted_issuers.windows(2).any(|w| w[0] >= w[1])
        || p.keys.windows(2).any(|w| {
            (w[0].issuer.as_str(), w[0].key_id.as_str())
                >= (w[1].issuer.as_str(), w[1].key_id.as_str())
        })
    {
        return Err(TrustBundleError::NonCanonicalOrdering);
    }
    if p.keys.iter().any(|key| key.not_after > p.expires_at) {
        return Err(TrustBundleError::Malformed);
    }

    let root_key =
        VerifyingKey::from_bytes(&root.public_key).map_err(|_| TrustBundleError::InvalidRoot)?;
    let signature =
        Signature::from_slice(&bundle.signature).map_err(|_| TrustBundleError::Malformed)?;
    let signing_bytes = bundle.signing_bytes()?;
    root_key
        .verify(&signing_bytes, &signature)
        .map_err(|_| TrustBundleError::InvalidSignature)?;

    let trust = TrustStore::new(p.trusted_issuers.clone(), p.keys.clone())?;
    let digest = Sha256::digest(&signing_bytes);
    let bundle_json = serde_json::to_string(bundle).map_err(|_| TrustBundleError::Malformed)?;
    store.install_trust_bundle_with_document(
        p.version,
        digest.as_slice(),
        p.issued_at,
        p.expires_at,
        now,
        Some(&bundle_json),
    )?;
    Ok(trust)
}

/// Verify and persist a root-signed subject-to-issuer policy. The root set
/// is provisioned out of band by the Owner; policy updates are monotonic and
/// only become active after durable storage succeeds.
#[rustfmt::skip]
pub fn verify_and_install_rollback_evidence_policy(
    signed: &SignedRollbackEvidencePolicy,
    roots: &TrustRootSet,
    store: &SqliteSecurityStore,
    now: u64,
) -> Result<RollbackEvidenceTrustPolicy, TrustBundleError> {
    let root = roots.get(&signed.root_key_id)?;
    if now < root.not_before || now >= root.not_after {
        return Err(TrustBundleError::RootOutsideValidity);
    }
    let payload = &signed.payload;
    if payload.version == 0
        || payload.issued_at >= payload.expires_at
        || payload.issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS)
        || payload.expires_at <= now.saturating_sub(MAX_CLOCK_SKEW_SECS)
        || payload.expires_at - payload.issued_at > MAX_BUNDLE_LIFETIME_SECS
    {
        return Err(TrustBundleError::Malformed);
    }
    let policy = RollbackEvidenceTrustPolicy::new(payload.allowed_issuers.clone())
        .map_err(|_| TrustBundleError::InvalidTrustConfiguration)?;
    let root_key = VerifyingKey::from_bytes(&root.public_key).map_err(|_| TrustBundleError::InvalidRoot)?;
    let signature = Signature::from_slice(&signed.signature).map_err(|_| TrustBundleError::Malformed)?;
    let signing_bytes = signed.signing_bytes()?;
    root_key.verify(&signing_bytes, &signature).map_err(|_| TrustBundleError::InvalidSignature)?;
    let digest = Sha256::digest(&signing_bytes);
    let document = serde_json::to_string(signed).map_err(|_| TrustBundleError::Malformed)?;
    store.install_rollback_evidence_policy(
        payload.version,
        digest.as_slice(),
        payload.expires_at,
        &document,
    )?;
    Ok(policy)
}

/// Rebuild the issuer policy after restart only from a persisted, root-signed
/// document that is revalidated against the current out-of-band root set.
#[rustfmt::skip]
pub fn restore_rollback_evidence_policy_with_roots(
    roots: &TrustRootSet,
    store: &SqliteSecurityStore,
    now: u64,
) -> Result<RollbackEvidenceTrustPolicy, TrustBundleError> {
    let document = store.latest_rollback_evidence_policy_document()?
        .ok_or(TrustBundleError::StoreUnavailable)?;
    let signed: SignedRollbackEvidencePolicy =
        serde_json::from_str(&document).map_err(|_| TrustBundleError::Malformed)?;
    verify_and_install_rollback_evidence_policy(&signed, roots, store, now)
}

#[rustfmt::skip]
fn validate_lineage_snapshot(
    payload: &crate::VersionLineageRegistrySnapshotPayload,
) -> Result<(), TrustBundleError> {
    use std::collections::{BTreeMap, BTreeSet};
    if payload.revision == 0 || payload.artifacts.is_empty() || payload.artifacts.len() > 10_000
        || payload.mutations.len() > 10_000
    {
        return Err(TrustBundleError::Malformed);
    }
    fn parse_version(value: &str) -> Option<(u64, u64, u64)> {
        let mut parts = value.split('.');
        let parse = |part: &str| {
            if part.is_empty()
                || (part.len() > 1 && part.starts_with('0'))
                || !part.bytes().all(|byte| byte.is_ascii_digit())
            {
                return None;
            }
            part.parse::<u64>().ok()
        };
        let major = parse(parts.next()?)?;
        let minor = parse(parts.next()?)?;
        let patch = parse(parts.next()?)?;
        if parts.next().is_some() { return None; }
        Some((major, minor, patch))
    }
    fn valid_digest(value: &str) -> bool {
        value.len() == 64
            && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }
    let mut by_version = BTreeMap::<String, &RegisteredLineageArtifact>::new();
    let mut artifact_digests = BTreeSet::new();
    let mut roots = 0usize;
    let mut referenced_mutations = BTreeSet::new();
    for artifact in &payload.artifacts {
        if artifact.gene_id != "g12.version-lineage"
            || parse_version(&artifact.version).is_none()
            || !valid_digest(&artifact.artifact_digest)
        {
            return Err(TrustBundleError::Malformed);
        }
        let canonical = canonical_json(&artifact.artifact).map_err(|_| TrustBundleError::Malformed)?;
        let digest = Sha256::digest(canonical);
        if format!("{digest:x}") != artifact.artifact_digest
            || !artifact_digests.insert(artifact.artifact_digest.clone())
        {
            return Err(TrustBundleError::Malformed);
        }
        if by_version.insert(artifact.version.clone(), artifact).is_some() {
            return Err(TrustBundleError::Malformed);
        }
        match (&artifact.parent_version, &artifact.parent_digest, &artifact.mutation_id) {
            (None, None, None) if artifact.epoch == 0 => roots += 1,
            (Some(parent_version), Some(parent_digest), Some(mutation_id))
                if parse_version(parent_version).is_some()
                    && valid_digest(parent_digest)
                    && !mutation_id.is_empty() =>
            {
                referenced_mutations.insert(mutation_id.clone());
            }
            _ => return Err(TrustBundleError::Malformed),
        }
    }
    if roots != 1 { return Err(TrustBundleError::Malformed); }
    let mut mutation_by_id = BTreeMap::<String, &RegisteredMutationRecord>::new();
    for mutation in &payload.mutations {
        if !mutation.approved || !mutation.gates_passed
            || mutation.mutation_ref.trim().is_empty()
            || mutation.mutation_id.trim().is_empty()
            || parse_version(mutation.source_version.as_deref().unwrap_or("")).is_none()
            || !valid_digest(mutation.source_digest.as_deref().unwrap_or(""))
            || parse_version(&mutation.target_version).is_none()
            || !valid_digest(&mutation.target_digest)
            || !valid_digest(&mutation.approval_commitment)
            || mutation_by_id.insert(mutation.mutation_id.clone(), mutation).is_some()
        {
            return Err(TrustBundleError::Malformed);
        }
    }
    if referenced_mutations.len() != mutation_by_id.len()
        || referenced_mutations.iter().any(|id| !mutation_by_id.contains_key(id))
    {
        return Err(TrustBundleError::Malformed);
    }
    for artifact in &payload.artifacts {
        if let (Some(parent_version), Some(parent_digest), Some(mutation_id)) =
            (&artifact.parent_version, &artifact.parent_digest, &artifact.mutation_id)
        {
            let parent = by_version.get(parent_version).ok_or(TrustBundleError::Malformed)?;
            if parent.artifact_digest != *parent_digest
                || artifact.epoch <= parent.epoch
                || parse_version(&artifact.version) <= parse_version(&parent.version)
            {
                return Err(TrustBundleError::Malformed);
            }
            let mutation = mutation_by_id.get(mutation_id).ok_or(TrustBundleError::Malformed)?;
            if mutation.source_version.as_deref() != Some(parent.version.as_str())
                || mutation.source_digest.as_deref() != Some(parent.artifact_digest.as_str())
                || mutation.target_version != artifact.version
                || mutation.target_digest != artifact.artifact_digest
            {
                return Err(TrustBundleError::Malformed);
            }
        }
    }
    Ok(())
}

/// Verify, validate and atomically provision a root-signed immutable G12 lineage
/// registry snapshot. No direct unsigned write path is exposed to callers.
#[rustfmt::skip]
pub fn verify_and_install_version_lineage_snapshot(
    signed: &SignedVersionLineageRegistrySnapshot,
    roots: &TrustRootSet,
    store: &SqliteSecurityStore,
    now: u64,
) -> Result<u64, TrustBundleError> {
    let root = roots.get(&signed.root_key_id)?;
    if now < root.not_before || now >= root.not_after {
        return Err(TrustBundleError::RootOutsideValidity);
    }
    let payload = &signed.payload;
    if payload.issued_at >= payload.expires_at
        || payload.issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS)
        || payload.expires_at <= now.saturating_sub(MAX_CLOCK_SKEW_SECS)
        || payload.expires_at - payload.issued_at > MAX_BUNDLE_LIFETIME_SECS
    {
        return Err(TrustBundleError::Malformed);
    }
    validate_lineage_snapshot(payload)?;
    let root_key = VerifyingKey::from_bytes(&root.public_key).map_err(|_| TrustBundleError::InvalidRoot)?;
    let signature = Signature::from_slice(&signed.signature).map_err(|_| TrustBundleError::Malformed)?;
    let signing_bytes = signed.signing_bytes().map_err(|_| TrustBundleError::Malformed)?;
    root_key.verify(&signing_bytes, &signature).map_err(|_| TrustBundleError::InvalidSignature)?;
    let digest = Sha256::digest(&signing_bytes);
    let document = serde_json::to_string(signed).map_err(|_| TrustBundleError::Malformed)?;
    store.install_version_lineage_snapshot(
        payload.revision,
        digest.as_slice(),
        &document,
        &payload.artifacts,
        &payload.mutations,
    )?;
    Ok(payload.revision)
}

/// Restore the authoritative registry only from the persisted signed snapshot,
/// rechecking root signature, validity, revision and all lineage invariants.
#[rustfmt::skip]
pub fn restore_version_lineage_snapshot_with_roots(
    roots: &TrustRootSet,
    store: &SqliteSecurityStore,
    now: u64,
) -> Result<u64, TrustBundleError> {
    let document = store.latest_version_lineage_snapshot_document()?
        .ok_or(TrustBundleError::StoreUnavailable)?;
    let signed: SignedVersionLineageRegistrySnapshot =
        serde_json::from_str(&document).map_err(|_| TrustBundleError::Malformed)?;
    verify_and_install_version_lineage_snapshot(&signed, roots, store, now)
}

/// Select the signing root by key ID from an explicitly provisioned overlapping
/// root set. Root-set updates themselves remain an out-of-band Owner ceremony.
pub fn verify_and_install_trust_bundle_with_roots(
    bundle: &SignedTrustBundle,
    roots: &TrustRootSet,
    store: &SqliteSecurityStore,
    now: u64,
) -> Result<TrustStore, TrustBundleError> {
    let root = roots.get(&bundle.root_key_id)?;
    verify_and_install_trust_bundle(bundle, root, store, now)
}

/// Thread-safe in-process trust snapshot publisher. Validation and durable
/// anti-rollback persistence complete before the active snapshot is replaced.
pub struct TrustSnapshotManager {
    // Serialize verification, durable anti-rollback persistence and publication
    // as one manager operation. The database high-water mark and active snapshot
    // must never be published in different orders.
    installation: Mutex<()>,
    current: RwLock<Arc<TrustStore>>,
}

impl TrustSnapshotManager {
    pub fn new(initial: TrustStore) -> Self {
        Self {
            installation: Mutex::new(()),
            current: RwLock::new(Arc::new(initial)),
        }
    }

    /// Recover the last persisted signed snapshot. The configured out-of-band
    /// root set is still authoritative; missing, expired, tampered or rolled-back
    /// persisted material fails closed and never falls back to an empty trust set.
    pub fn restore_with_roots(
        roots: &TrustRootSet,
        store: &SqliteSecurityStore,
        now: u64,
    ) -> Result<Self, TrustBundleError> {
        let document = store
            .latest_trust_bundle_document()?
            .ok_or(TrustBundleError::StoreUnavailable)?;
        let bundle: SignedTrustBundle =
            serde_json::from_str(&document).map_err(|_| TrustBundleError::Malformed)?;
        let trust = verify_and_install_trust_bundle_with_roots(&bundle, roots, store, now)?;
        Ok(Self::new(trust))
    }

    pub fn snapshot(&self) -> Result<Arc<TrustStore>, TrustBundleError> {
        self.current
            .read()
            .map(|snapshot| Arc::clone(&snapshot))
            .map_err(|_| TrustBundleError::StoreUnavailable)
    }

    fn install_using<F>(&self, version: u64, install: F) -> Result<u64, TrustBundleError>
    where
        F: FnOnce() -> Result<TrustStore, TrustBundleError>,
    {
        // Keep this guard through both the durable anti-rollback write and the
        // in-memory swap. Releasing it between those operations permits stale
        // installers to overwrite a newer snapshot.
        let _installation = self
            .installation
            .lock()
            .map_err(|_| TrustBundleError::StoreUnavailable)?;
        let next = install()?;
        let mut current = self
            .current
            .write()
            .map_err(|_| TrustBundleError::StoreUnavailable)?;
        *current = Arc::new(next);
        Ok(version)
    }

    pub fn install(
        &self,
        bundle: &SignedTrustBundle,
        root: &TrustRoot,
        store: &SqliteSecurityStore,
        now: u64,
    ) -> Result<u64, TrustBundleError> {
        self.install_using(bundle.payload.version, || {
            verify_and_install_trust_bundle(bundle, root, store, now)
        })
    }

    pub fn install_with_roots(
        &self,
        bundle: &SignedTrustBundle,
        roots: &TrustRootSet,
        store: &SqliteSecurityStore,
        now: u64,
    ) -> Result<u64, TrustBundleError> {
        self.install_using(bundle.payload.version, || {
            verify_and_install_trust_bundle_with_roots(bundle, roots, store, now)
        })
    }
}

/// Recovered, mutually consistent G12 security runtime. Startup fails closed
/// unless all three signed operational documents are present, current and valid.
pub struct G12SecurityRuntime {
    trust_snapshots: TrustSnapshotManager,
    evidence_verifier: crate::Ed25519RollbackEvidenceVerifier<Arc<SqliteSecurityStore>>,
    store: Arc<SqliteSecurityStore>,
}

impl G12SecurityRuntime {
    pub fn restore(
        roots: &TrustRootSet,
        store: Arc<SqliteSecurityStore>,
        now: u64,
    ) -> Result<Self, TrustBundleError> {
        store
            .integrity_check()
            .map_err(|_| TrustBundleError::StoreUnavailable)?;
        let trust_snapshots = TrustSnapshotManager::restore_with_roots(roots, &store, now)?;
        let issuer_policy = restore_rollback_evidence_policy_with_roots(roots, &store, now)?;
        restore_version_lineage_snapshot_with_roots(roots, &store, now)?;
        let trust_snapshot = trust_snapshots.snapshot()?;
        let credentials = crate::Ed25519CredentialVerifier::from_verified_trust_snapshot(
            trust_snapshot.as_ref(),
            Arc::clone(&store),
        );
        let evidence_verifier = crate::Ed25519RollbackEvidenceVerifier::new(
            credentials,
            Arc::clone(&store),
            issuer_policy,
        );
        Ok(Self {
            trust_snapshots,
            evidence_verifier,
            store,
        })
    }

    pub fn evidence_verifier(&self) -> &dyn crate::RollbackEvidenceVerifier {
        &self.evidence_verifier
    }

    pub fn lineage_registry(&self) -> &SqliteSecurityStore {
        &self.store
    }

    pub fn trust_snapshots(&self) -> &TrustSnapshotManager {
        &self.trust_snapshots
    }
}

#[rustfmt::skip]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::VersionLineageRegistry;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture(version: u64) -> (SigningKey, TrustRoot, SignedTrustBundle) {
        let root_signer = SigningKey::from_bytes(&[31u8; 32]);
        let issuer_signer = SigningKey::from_bytes(&[41u8; 32]);
        let root = TrustRoot {
            key_id: "offline-root-2026".into(),
            public_key: root_signer.verifying_key().to_bytes(),
            not_before: 900,
            not_after: 10_000,
            provenance_ref: "fixture-root-provenance".into(),
        };
        let payload = TrustBundlePayload {
            version,
            issued_at: 1_000,
            expires_at: 5_000,
            trusted_issuers: vec!["issuer:iroka-test".into()],
            keys: vec![TrustedKey {
                issuer: "issuer:iroka-test".into(),
                key_id: format!("issuer-key-{version}"),
                public_key: issuer_signer.verifying_key().to_bytes(),
                not_before: 1_000,
                not_after: 5_000,
            }],
        };
        let signing_bytes = SignedTrustBundle::signing_bytes_for(&root.key_id, &payload).unwrap();
        let signature = root_signer.sign(&signing_bytes).to_bytes().to_vec();
        let root_key_id = root.key_id.clone();
        (
            root_signer,
            root,
            SignedTrustBundle::from_signature(root_key_id, payload, signature),
        )
    }

    #[test]
    fn accepts_root_signed_bundle_and_persists_version() {
        let (_, root, bundle) = fixture(1);
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        assert!(verify_and_install_trust_bundle(&bundle, &root, &store, 1_100).is_ok());
        assert_eq!(store.highest_trust_bundle_version(), Ok(Some(1)));
    }

    #[test]
    fn rejects_tampering_wrong_root_and_expired_bundle() {
        let (signer, root, mut bundle) = fixture(1);
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        bundle.payload.version = 2;
        assert_eq!(
            verify_and_install_trust_bundle(&bundle, &root, &store, 1_100).unwrap_err(),
            TrustBundleError::InvalidSignature
        );

        let (_, _, expired) = fixture(2);
        let wrong_root = TrustRoot {
            public_key: SigningKey::from_bytes(&[99u8; 32])
                .verifying_key()
                .to_bytes(),
            ..root.clone()
        };
        assert_eq!(
            verify_and_install_trust_bundle(&expired, &wrong_root, &store, 1_100).unwrap_err(),
            TrustBundleError::InvalidSignature
        );
        assert_eq!(
            verify_and_install_trust_bundle(&expired, &root, &store, 5_100).unwrap_err(),
            TrustBundleError::Expired
        );
        let _ = signer;
    }

    #[test]
    fn rejects_unprovenanced_root_on_direct_bundle_install_path() {
        let (_, mut root, bundle) = fixture(1);
        root.provenance_ref.clear();
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        assert_eq!(
            verify_and_install_trust_bundle(&bundle, &root, &store, 1_100).unwrap_err(),
            TrustBundleError::InvalidRoot
        );
    }

    #[test]
    fn rejects_bundle_version_rollback() {
        let (_, root, first) = fixture(2);
        let (_, _, older) = fixture(1);
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        verify_and_install_trust_bundle(&first, &root, &store, 1_100).unwrap();
        assert_eq!(
            verify_and_install_trust_bundle(&older, &root, &store, 1_100).unwrap_err(),
            TrustBundleError::Rollback
        );
    }

    #[test]
    fn rejects_noncanonical_bundle_order() {
        let (signer, root, mut bundle) = fixture(1);
        bundle.payload.trusted_issuers = vec!["issuer:z".into(), "issuer:a".into()];
        bundle.signature = signer
            .sign(&bundle.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        assert_eq!(
            verify_and_install_trust_bundle(&bundle, &root, &store, 1_100).unwrap_err(),
            TrustBundleError::NonCanonicalOrdering
        );
    }

    fn signed_policy_fixture(
        signer: &ed25519_dalek::SigningKey,
        root: &TrustRoot,
        version: u64,
    ) -> SignedRollbackEvidencePolicy {
        use ed25519_dalek::Signer;
        let allowed_issuers = BTreeMap::from([
            ("current_state".into(), BTreeSet::from(["issuer:state".into()])),
            ("candidate_state".into(), BTreeSet::from(["issuer:candidate".into()])),
            ("revocation_floor".into(), BTreeSet::from(["issuer:revocation".into()])),
            ("policy_version".into(), BTreeSet::from(["issuer:policy".into()])),
            ("lineage:artifact:*".into(), BTreeSet::from(["issuer:lineage".into()])),
            ("lineage:mutation:*".into(), BTreeSet::from(["issuer:lineage".into()])),
            ("lineage:registry".into(), BTreeSet::from(["issuer:registry".into()])),
        ]);
        let payload = RollbackEvidencePolicyPayload {
            version,
            issued_at: 1_000,
            expires_at: 5_000,
            allowed_issuers,
        };
        let unsigned = SignedRollbackEvidencePolicy::from_signature(
            root.key_id.clone(), payload, Vec::new()
        );
        let signature = signer.sign(&unsigned.signing_bytes().unwrap()).to_bytes().to_vec();
        SignedRollbackEvidencePolicy::from_signature(root.key_id.clone(), unsigned.payload, signature)
    }

    #[test]
    fn signed_issuer_policy_is_persisted_and_recovered_after_restart() {
        use std::fs;
        let (signer, root, _) = fixture(1);
        let roots = TrustRootSet::new(vec![root.clone()]).unwrap();
        let signed = signed_policy_fixture(&signer, &root, 3);
        let path = std::env::temp_dir().join(format!(
            "iroka-rollback-policy-recovery-{}.sqlite",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        {
            let store = SqliteSecurityStore::open(&path).unwrap();
            let policy = verify_and_install_rollback_evidence_policy(&signed, &roots, &store, 1_100).unwrap();
            assert!(policy.allows("lineage:artifact:abc", "issuer:lineage"));
            assert!(!policy.allows("lineage:artifact:abc", "issuer:untrusted"));
        }
        {
            let store = SqliteSecurityStore::open(&path).unwrap();
            let recovered = restore_rollback_evidence_policy_with_roots(&roots, &store, 1_200).unwrap();
            assert!(recovered.allows("lineage:mutation:xyz", "issuer:lineage"));
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite-shm"));
    }

    fn signed_lineage_fixture(
        signer: &ed25519_dalek::SigningKey,
        root: &TrustRoot,
        revision: u64,
    ) -> SignedVersionLineageRegistrySnapshot {
        use ed25519_dalek::Signer;
        let root_artifact = serde_json::json!({"gene":"g12.version-lineage","version":"1.0.0"});
        let root_digest = format!(
            "{:x}",
            Sha256::digest(canonical_json(&root_artifact).unwrap())
        );
        let middle_artifact = serde_json::json!({"gene":"g12.version-lineage","version":"1.1.0"});
        let middle_digest = format!(
            "{:x}",
            Sha256::digest(canonical_json(&middle_artifact).unwrap())
        );
        let candidate_artifact = serde_json::json!({"gene":"g12.version-lineage","version":"1.2.0"});
        let candidate_digest = format!(
            "{:x}",
            Sha256::digest(canonical_json(&candidate_artifact).unwrap())
        );
        let payload = crate::VersionLineageRegistrySnapshotPayload {
            revision,
            issued_at: 1_000,
            expires_at: 5_000,
            artifacts: vec![
                RegisteredLineageArtifact {
                    gene_id: "g12.version-lineage".into(),
                    version: "1.0.0".into(),
                    artifact_digest: root_digest.clone(),
                    artifact: root_artifact,
                    parent_version: None,
                    parent_digest: None,
                    mutation_id: None,
                    epoch: 0,
                },
                RegisteredLineageArtifact {
                    gene_id: "g12.version-lineage".into(),
                    version: "1.1.0".into(),
                    artifact_digest: middle_digest.clone(),
                    artifact: middle_artifact,
                    parent_version: Some("1.0.0".into()),
                    parent_digest: Some(root_digest.clone()),
                    mutation_id: Some("mutation-1".into()),
                    epoch: 1,
                },
                RegisteredLineageArtifact {
                    gene_id: "g12.version-lineage".into(),
                    version: "1.2.0".into(),
                    artifact_digest: candidate_digest.clone(),
                    artifact: candidate_artifact,
                    parent_version: Some("1.1.0".into()),
                    parent_digest: Some(middle_digest.clone()),
                    mutation_id: Some("mutation-2".into()),
                    epoch: 2,
                },
            ],
            mutations: vec![
                RegisteredMutationRecord {
                    mutation_ref: "mutation-ref-1".into(),
                    mutation_id: "mutation-1".into(),
                    source_version: Some("1.0.0".into()),
                    source_digest: Some(root_digest),
                    target_version: "1.1.0".into(),
                    target_digest: middle_digest,
                    approved: true,
                    gates_passed: true,
                    approval_commitment: "a".repeat(64),
                },
                RegisteredMutationRecord {
                    mutation_ref: "mutation-ref-2".into(),
                    mutation_id: "mutation-2".into(),
                    source_version: Some("1.1.0".into()),
                    source_digest: Some(format!(
                        "{:x}",
                        Sha256::digest(canonical_json(&serde_json::json!({"gene":"g12.version-lineage","version":"1.1.0"})).unwrap())
                    )),
                    target_version: "1.2.0".into(),
                    target_digest: candidate_digest,
                    approved: true,
                    gates_passed: true,
                    approval_commitment: "b".repeat(64),
                },
            ],
        };
        let unsigned = SignedVersionLineageRegistrySnapshot::from_signature(
            root.key_id.clone(),
            payload,
            Vec::new(),
        );
        let signature = signer
            .sign(&unsigned.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        SignedVersionLineageRegistrySnapshot::from_signature(
            root.key_id.clone(),
            unsigned.payload,
            signature,
        )
    }

    #[test]
    fn signed_lineage_registry_is_atomically_provisioned_and_recovered() {
        use std::fs;
        let (signer, root, _) = fixture(1);
        let roots = TrustRootSet::new(vec![root.clone()]).unwrap();
        let signed = signed_lineage_fixture(&signer, &root, 1);
        let expected_digest = signed.payload.artifacts[2].artifact_digest.clone();
        let path = std::env::temp_dir().join(format!(
            "iroka-lineage-registry-recovery-{}.sqlite",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        {
            let store = SqliteSecurityStore::open(&path).unwrap();
            assert_eq!(
                verify_and_install_version_lineage_snapshot(&signed, &roots, &store, 1_100),
                Ok(1)
            );
        }
        {
            let store = SqliteSecurityStore::open(&path).unwrap();
            assert_eq!(
                restore_version_lineage_snapshot_with_roots(&roots, &store, 1_200),
                Ok(1)
            );
            let record = crate::VersionLineageRegistry::resolve_lineage(
                &store, "1.0.0", &expected_digest
            ).unwrap();
            assert_eq!(record.registry_revision, 1);
            assert_eq!(record.ancestry.len(), 1);
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[test]
    fn lineage_registry_rejects_unsigned_tampering_and_revision_rollback() {
        let (signer, root, _) = fixture(1);
        let roots = TrustRootSet::new(vec![root.clone()]).unwrap();
        let first = signed_lineage_fixture(&signer, &root, 2);
        let older = signed_lineage_fixture(&signer, &root, 1);
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        verify_and_install_version_lineage_snapshot(&first, &roots, &store, 1_100).unwrap();
        assert_eq!(
            verify_and_install_version_lineage_snapshot(&older, &roots, &store, 1_100),
            Err(TrustBundleError::Rollback)
        );
        let mut tampered = signed_lineage_fixture(&signer, &root, 3);
        tampered.payload.artifacts[0].artifact["version"] = serde_json::json!("9.9.9");
        assert_eq!(
            verify_and_install_version_lineage_snapshot(&tampered, &roots, &store, 1_100),
            Err(TrustBundleError::InvalidSignature)
        );
        let record = store.resolve_lineage(
            "1.0.0",
            &first.payload.artifacts[0].artifact_digest
        ).unwrap();
        assert_eq!(record.registry_revision, 2);
    }

    #[test]
    fn signed_snapshot_survives_store_reopen_and_is_reverified_from_owner_roots() {
        use std::fs;
        let (_, root, bundle) = fixture(7);
        let path = std::env::temp_dir().join(format!(
            "iroka-trust-snapshot-recovery-{}.sqlite",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        {
            let store = SqliteSecurityStore::open(&path).unwrap();
            verify_and_install_trust_bundle(&bundle, &root, &store, 1_100).unwrap();
            assert!(store.latest_trust_bundle_document().unwrap().is_some());
        }
        {
            let store = SqliteSecurityStore::open(&path).unwrap();
            let roots = TrustRootSet::new(vec![root.clone()]).unwrap();
            let manager = TrustSnapshotManager::restore_with_roots(&roots, &store, 1_200).unwrap();
            assert!(manager.snapshot().is_ok());
            assert_eq!(store.highest_trust_bundle_version(), Ok(Some(7)));
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[test]
    fn snapshot_manager_publishes_only_verified_monotonic_bundles() {
        let (_, root, first) = fixture(1);
        let (_, _, second) = fixture(2);
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        let initial = verify_and_install_trust_bundle(&first, &root, &store, 1_100).unwrap();
        let manager = TrustSnapshotManager::new(initial);
        assert_eq!(manager.install(&second, &root, &store, 1_200), Ok(2));
        assert_eq!(store.highest_trust_bundle_version(), Ok(Some(2)));
        assert_eq!(
            manager.install(&first, &root, &store, 1_200),
            Err(TrustBundleError::Rollback)
        );
    }

    fn credential_for(signing: &SigningKey, key_id: &str) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let header = URL_SAFE_NO_PAD.encode(
            format!(r#"{{"alg":"EdDSA","typ":"IROKA-CREDENTIAL","kid":"{key_id}"}}"#).as_bytes(),
        );
        let claims = URL_SAFE_NO_PAD.encode(
            br#"{"iss":"issuer:iroka-test","sub":"principal:race","aud":"iroka-kernel","exp":4000,"nbf":1000,"iat":1000,"jti":"credential:race"}"#,
        );
        let input = format!("{header}.{claims}");
        let signature = signing.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    #[test]
    fn concurrent_snapshot_installation_serializes_persistence_and_publication() {
        use std::sync::mpsc;
        use std::time::Duration;

        let (_, root, initial_bundle) = fixture(1);
        let (_, _, middle_bundle) = fixture(2);
        let (_, _, newest_bundle) = fixture(3);
        let store = Arc::new(SqliteSecurityStore::open_in_memory().unwrap());
        let initial =
            verify_and_install_trust_bundle(&initial_bundle, &root, &store, 1_100).unwrap();
        let manager = Arc::new(TrustSnapshotManager::new(initial));

        // Pause the first installer after its durable version-2 write but before
        // publication. A second installer must not enter its verification/write
        // closure until the first installer publishes version 2.
        let (persisted_tx, persisted_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let first_manager = Arc::clone(&manager);
        let first_store = Arc::clone(&store);
        let first_root = root.clone();
        let first = std::thread::spawn(move || {
            first_manager.install_using(2, || {
                let trust = verify_and_install_trust_bundle(
                    &middle_bundle,
                    &first_root,
                    &first_store,
                    1_200,
                )?;
                persisted_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(trust)
            })
        });
        persisted_rx.recv().unwrap();

        let (second_entered_tx, second_entered_rx) = mpsc::channel();
        let second_manager = Arc::clone(&manager);
        let second_store = Arc::clone(&store);
        let second_root = root.clone();
        let second = std::thread::spawn(move || {
            second_manager.install_using(3, || {
                second_entered_tx.send(()).unwrap();
                verify_and_install_trust_bundle(&newest_bundle, &second_root, &second_store, 1_300)
            })
        });

        // This bounded wait is the assertion: the second install closure cannot
        // run while the first operation holds the publication-order mutex.
        assert!(second_entered_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err());
        release_tx.send(()).unwrap();
        assert_eq!(first.join().unwrap(), Ok(2));
        assert_eq!(second.join().unwrap(), Ok(3));
        assert_eq!(store.highest_trust_bundle_version(), Ok(Some(3)));

        let snapshot = manager.snapshot().unwrap();
        let verifier = crate::Ed25519CredentialVerifier::from_verified_trust_snapshot(
            &snapshot,
            crate::NoRevocations,
        );
        let issuer_signer = SigningKey::from_bytes(&[41u8; 32]);
        assert!(verifier
            .authenticate(
                &credential_for(&issuer_signer, "issuer-key-3"),
                "iroka-kernel",
                1_400,
            )
            .is_ok());
        assert_eq!(
            verifier.authenticate(
                &credential_for(&issuer_signer, "issuer-key-2"),
                "iroka-kernel",
                1_400,
            ),
            Err(crate::CredentialError::UnknownKey)
        );
    }

    #[test]
    fn poisoned_installation_lock_fails_closed_without_persisting_or_publishing() {
        let (_, root, initial_bundle) = fixture(1);
        let (_, _, next_bundle) = fixture(2);
        let store = Arc::new(SqliteSecurityStore::open_in_memory().unwrap());
        let initial =
            verify_and_install_trust_bundle(&initial_bundle, &root, &store, 1_100).unwrap();
        let manager = Arc::new(TrustSnapshotManager::new(initial));

        let poison_manager = Arc::clone(&manager);
        let poisoned = std::thread::spawn(move || {
            let _guard = poison_manager.installation.lock().unwrap();
            panic!("intentional test-only installation lock poisoning");
        });
        assert!(poisoned.join().is_err());

        assert_eq!(
            manager.install(&next_bundle, &root, &store, 1_200),
            Err(TrustBundleError::StoreUnavailable)
        );
        assert_eq!(store.highest_trust_bundle_version(), Ok(Some(1)));

        let snapshot = manager.snapshot().unwrap();
        let verifier = crate::Ed25519CredentialVerifier::from_verified_trust_snapshot(
            &snapshot,
            crate::NoRevocations,
        );
        let issuer_signer = SigningKey::from_bytes(&[41u8; 32]);
        assert!(verifier
            .authenticate(
                &credential_for(&issuer_signer, "issuer-key-1"),
                "iroka-kernel",
                1_400,
            )
            .is_ok());
        assert_eq!(
            verifier.authenticate(
                &credential_for(&issuer_signer, "issuer-key-2"),
                "iroka-kernel",
                1_400,
            ),
            Err(crate::CredentialError::UnknownKey)
        );
    }

    #[test]
    fn rollback_rejection_leaves_active_snapshot_unchanged() {
        let (_, root, newer) = fixture(2);
        let (_, _, older) = fixture(1);
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        let initial = verify_and_install_trust_bundle(&newer, &root, &store, 1_100).unwrap();
        let manager = TrustSnapshotManager::new(initial);

        assert_eq!(
            manager.install(&older, &root, &store, 1_200),
            Err(TrustBundleError::Rollback)
        );
        assert_eq!(store.highest_trust_bundle_version(), Ok(Some(2)));

        let snapshot = manager.snapshot().unwrap();
        let verifier = crate::Ed25519CredentialVerifier::from_verified_trust_snapshot(
            &snapshot,
            crate::NoRevocations,
        );
        let issuer_signer = SigningKey::from_bytes(&[41u8; 32]);
        assert!(verifier
            .authenticate(
                &credential_for(&issuer_signer, "issuer-key-2"),
                "iroka-kernel",
                1_400,
            )
            .is_ok());
        assert_eq!(
            verifier.authenticate(
                &credential_for(&issuer_signer, "issuer-key-1"),
                "iroka-kernel",
                1_400,
            ),
            Err(crate::CredentialError::UnknownKey)
        );
    }

    #[test]
    fn accepts_trust_root_rotation_during_explicit_overlap() {
        let (_, old_root, _) = fixture(1);
        let new_signer = SigningKey::from_bytes(&[88u8; 32]);
        let new_root = TrustRoot {
            key_id: "offline-root-2027".into(),
            public_key: new_signer.verifying_key().to_bytes(),
            not_before: 1_200,
            not_after: 10_000,
            provenance_ref: "fixture-next-root-provenance".into(),
        };
        let issuer = SigningKey::from_bytes(&[41u8; 32]);
        let payload = TrustBundlePayload {
            version: 2,
            issued_at: 1_300,
            expires_at: 5_000,
            trusted_issuers: vec!["issuer:iroka-test".into()],
            keys: vec![TrustedKey {
                issuer: "issuer:iroka-test".into(),
                key_id: "issuer-key-rotated".into(),
                public_key: issuer.verifying_key().to_bytes(),
                not_before: 1_300,
                not_after: 5_000,
            }],
        };
        let bytes = SignedTrustBundle::signing_bytes_for(&new_root.key_id, &payload).unwrap();
        let signature = new_signer.sign(&bytes).to_bytes().to_vec();
        let bundle = SignedTrustBundle::from_signature(new_root.key_id.clone(), payload, signature);
        let roots = TrustRootSet::new(vec![old_root, new_root]).unwrap();
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        assert!(verify_and_install_trust_bundle_with_roots(&bundle, &roots, &store, 1_400).is_ok());
        assert_eq!(store.highest_trust_bundle_version(), Ok(Some(2)));
    }
}
