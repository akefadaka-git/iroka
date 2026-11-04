//! Root-signed trust-bundle lifecycle: verification, expiry and rollback protection.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{SecurityStoreError, SqliteSecurityStore, TrustConfigError, TrustStore, TrustedKey};

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

impl TrustBundlePayload {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, TrustBundleError> {
        serde_json::to_vec(self).map_err(|_| TrustBundleError::Malformed)
    }
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

#[derive(Debug, Clone)]
pub struct TrustRoot {
    pub key_id: String,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
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
                || VerifyingKey::from_bytes(&root.public_key).is_err()
                || indexed.insert(root.key_id.clone(), root).is_some()
            {
                return Err(TrustBundleError::InvalidRoot);
            }
        }
        Ok(Self { roots: indexed })
    }

    fn get(&self, key_id: &str) -> Result<&TrustRoot, TrustBundleError> {
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
    store.install_trust_bundle(p.version, digest.as_slice(), p.issued_at, p.expires_at)?;
    Ok(trust)
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
    current: RwLock<Arc<TrustStore>>,
}

impl TrustSnapshotManager {
    pub fn new(initial: TrustStore) -> Self {
        Self {
            current: RwLock::new(Arc::new(initial)),
        }
    }

    pub fn snapshot(&self) -> Result<Arc<TrustStore>, TrustBundleError> {
        self.current
            .read()
            .map(|snapshot| Arc::clone(&snapshot))
            .map_err(|_| TrustBundleError::StoreUnavailable)
    }

    pub fn install(
        &self,
        bundle: &SignedTrustBundle,
        root: &TrustRoot,
        store: &SqliteSecurityStore,
        now: u64,
    ) -> Result<u64, TrustBundleError> {
        let next = verify_and_install_trust_bundle(bundle, root, store, now)?;
        let version = bundle.payload.version;
        let mut current = self
            .current
            .write()
            .map_err(|_| TrustBundleError::StoreUnavailable)?;
        *current = Arc::new(next);
        Ok(version)
    }
    pub fn install_with_roots(
        &self,
        bundle: &SignedTrustBundle,
        roots: &TrustRootSet,
        store: &SqliteSecurityStore,
        now: u64,
    ) -> Result<u64, TrustBundleError> {
        let next = verify_and_install_trust_bundle_with_roots(bundle, roots, store, now)?;
        let version = bundle.payload.version;
        let mut current = self
            .current
            .write()
            .map_err(|_| TrustBundleError::StoreUnavailable)?;
        *current = Arc::new(next);
        Ok(version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture(version: u64) -> (SigningKey, TrustRoot, SignedTrustBundle) {
        let root_signer = SigningKey::from_bytes(&[31u8; 32]);
        let issuer_signer = SigningKey::from_bytes(&[41u8; 32]);
        let root = TrustRoot {
            key_id: "offline-root-2026".into(),
            public_key: root_signer.verifying_key().to_bytes(),
            not_before: 900,
            not_after: 10_000,
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

    #[test]
    fn accepts_trust_root_rotation_during_explicit_overlap() {
        let (_, old_root, _) = fixture(1);
        let new_signer = SigningKey::from_bytes(&[88u8; 32]);
        let new_root = TrustRoot {
            key_id: "offline-root-2027".into(),
            public_key: new_signer.verifying_key().to_bytes(),
            not_before: 1_200,
            not_after: 10_000,
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
