//! Owner-signed K-04 witness roster manifests and activation.
//!
//! The Owner root is an out-of-band trust anchor. Never accept it from the
//! manifest, an API request, or another untrusted source. Production adapters
//! must load it from protected bootstrap configuration or hardware-backed trust.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::audit_verifier::{
    AuthorizedWitness, VerificationError, WitnessReceiptVerifier, WitnessRosterState,
    AUTHORIZED_WITNESS_COUNT,
};
use crate::trust_lifecycle::TrustRoot;
use crate::{SecurityStoreError, SqliteSecurityStore};

const DOMAIN_SEPARATOR: &[u8] = b"IROKA-K04-OWNER-WITNESS-ROSTER-V1\0";
const MAX_ROSTER_LIFETIME_SECS: u64 = 31_536_000;
const MAX_CLOCK_SKEW_SECS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WitnessRosterEntry {
    pub witness_id: String,
    pub signing_key_id: String,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WitnessRosterManifestPayload {
    pub version: u64,
    pub owner_subject: String,
    pub stream_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub witnesses: Vec<WitnessRosterEntry>,
    pub revoked_key_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedWitnessRosterManifest {
    pub root_key_id: String,
    pub payload: WitnessRosterManifestPayload,
    pub signature: Vec<u8>,
}

impl SignedWitnessRosterManifest {
    pub fn from_signature(
        root_key_id: impl Into<String>,
        payload: WitnessRosterManifestPayload,
        signature: Vec<u8>,
    ) -> Self {
        Self { root_key_id: root_key_id.into(), payload, signature }
    }

    /// Domain-separated signing input with deterministic struct-field ordering.
    pub fn signing_bytes_for(
        root_key_id: &str,
        payload: &WitnessRosterManifestPayload,
    ) -> Result<Vec<u8>, WitnessRosterManifestError> {
        #[derive(Serialize)]
        struct Envelope<'a> {
            root_key_id: &'a str,
            payload: &'a WitnessRosterManifestPayload,
        }
        let encoded = serde_json::to_vec(&Envelope { root_key_id, payload })
            .map_err(|_| WitnessRosterManifestError::Malformed)?;
        let mut bytes = Vec::with_capacity(DOMAIN_SEPARATOR.len() + encoded.len());
        bytes.extend_from_slice(DOMAIN_SEPARATOR);
        bytes.extend_from_slice(&encoded);
        Ok(bytes)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, WitnessRosterManifestError> {
        Self::signing_bytes_for(&self.root_key_id, &self.payload)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessRosterManifestError {
    Malformed,
    InvalidOwnerRoot,
    OwnerRootOutsideValidity,
    OwnerMismatch,
    InvalidSignature,
    NotYetValid,
    Expired,
    ExcessiveLifetime,
    NonCanonicalOrdering,
    InvalidRoster,
    Rollback,
    StoreUnavailable,
}

impl From<SecurityStoreError> for WitnessRosterManifestError {
    fn from(error: SecurityStoreError) -> Self {
        match error {
            SecurityStoreError::Rollback | SecurityStoreError::ConflictingVersion => Self::Rollback,
            SecurityStoreError::InvalidVersion => Self::Malformed,
            SecurityStoreError::Unavailable | SecurityStoreError::Revoked => Self::StoreUnavailable,
        }
    }
}

impl From<VerificationError> for WitnessRosterManifestError {
    fn from(_: VerificationError) -> Self {
        Self::InvalidRoster
    }
}

/// Verify and activate a complete Owner-signed witness roster.
///
/// The root is a pre-provisioned Owner trust anchor and MUST come from protected
/// out-of-band bootstrap configuration. The root is not carried in the manifest.
/// Successful activation durably advances the roster anti-rollback high-water mark.
pub fn activate_signed_witness_roster(
    manifest: &SignedWitnessRosterManifest,
    owner_subject: &str,
    root: &TrustRoot,
    store: &SqliteSecurityStore,
    now: u64,
) -> Result<WitnessRosterState, WitnessRosterManifestError> {
    if owner_subject.trim().is_empty()
        || root.key_id.trim().is_empty()
        || root.key_id != manifest.root_key_id
        || root.not_before >= root.not_after
    {
        return Err(WitnessRosterManifestError::InvalidOwnerRoot);
    }
    if now < root.not_before || now >= root.not_after {
        return Err(WitnessRosterManifestError::OwnerRootOutsideValidity);
    }

    let payload = &manifest.payload;
    if payload.version == 0
        || payload.owner_subject.trim().is_empty()
        || payload.stream_id.trim().is_empty()
        || payload.issued_at >= payload.expires_at
        || payload.witnesses.len() != AUTHORIZED_WITNESS_COUNT
    {
        return Err(WitnessRosterManifestError::Malformed);
    }
    if payload.owner_subject != owner_subject {
        return Err(WitnessRosterManifestError::OwnerMismatch);
    }
    if payload.issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(WitnessRosterManifestError::NotYetValid);
    }
    if payload.expires_at <= now {
        return Err(WitnessRosterManifestError::Expired);
    }
    if payload.expires_at - payload.issued_at > MAX_ROSTER_LIFETIME_SECS {
        return Err(WitnessRosterManifestError::ExcessiveLifetime);
    }
    if payload.issued_at < root.not_before || payload.issued_at >= root.not_after {
        return Err(WitnessRosterManifestError::OwnerRootOutsideValidity);
    }
    if payload.witnesses.windows(2).any(|pair| pair[0].witness_id >= pair[1].witness_id)
        || payload.revoked_key_ids.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(WitnessRosterManifestError::NonCanonicalOrdering);
    }

    let root_key = VerifyingKey::from_bytes(&root.public_key)
        .map_err(|_| WitnessRosterManifestError::InvalidOwnerRoot)?;
    let signature = Signature::from_slice(&manifest.signature)
        .map_err(|_| WitnessRosterManifestError::Malformed)?;
    let signing_bytes = manifest.signing_bytes()?;
    root_key.verify(&signing_bytes, &signature)
        .map_err(|_| WitnessRosterManifestError::InvalidSignature)?;

    let mut authorized = Vec::with_capacity(AUTHORIZED_WITNESS_COUNT);
    let mut witness_ids = std::collections::BTreeSet::new();
    let mut key_ids = std::collections::BTreeSet::new();
    let mut public_keys = std::collections::BTreeSet::new();
    let revoked: std::collections::BTreeSet<&str> =
        payload.revoked_key_ids.iter().map(String::as_str).collect();
    if payload.revoked_key_ids.iter().any(|id| id.trim().is_empty()) {
        return Err(WitnessRosterManifestError::Malformed);
    }
    for witness in &payload.witnesses {
        if witness.witness_id.trim().is_empty()
            || witness.signing_key_id.trim().is_empty()
            || witness.not_before >= witness.not_after
            || witness.not_before > now
            || witness.not_after <= now
            || witness.not_after > payload.expires_at
            || revoked.contains(witness.signing_key_id.as_str())
            || !witness_ids.insert(witness.witness_id.as_str())
            || !key_ids.insert(witness.signing_key_id.as_str())
            || !public_keys.insert(witness.public_key)
        {
            return Err(WitnessRosterManifestError::InvalidRoster);
        }
        let verifying_key = VerifyingKey::from_bytes(&witness.public_key)
            .map_err(|_| WitnessRosterManifestError::InvalidRoster)?;
        authorized.push(AuthorizedWitness {
            witness_id: witness.witness_id.clone(),
            signing_key_id: witness.signing_key_id.clone(),
            verifying_key,
        });
    }

    let verifier = WitnessReceiptVerifier::new(authorized)?;
    let digest = Sha256::digest(&signing_bytes);
    store.install_witness_roster(
        payload.version, digest.as_slice(), payload.issued_at, payload.expires_at, now,
    )?;

    Ok(WitnessRosterState::provisioned_from_manifest(
        verifier, payload.stream_id.clone(), payload.version, payload.expires_at,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture(version: u64) -> (SigningKey, TrustRoot, SignedWitnessRosterManifest) {
        let owner = SigningKey::from_bytes(&[61u8; 32]);
        let witness_keys = [
            SigningKey::from_bytes(&[62u8; 32]),
            SigningKey::from_bytes(&[63u8; 32]),
            SigningKey::from_bytes(&[64u8; 32]),
        ];
        let root = TrustRoot {
            key_id: "owner-witness-root-01".into(),
            public_key: owner.verifying_key().to_bytes(),
            not_before: 900,
            not_after: 10_000,
        };
        let witnesses = witness_keys.iter().enumerate().map(|(i, key)| WitnessRosterEntry {
            witness_id: format!("witness-{}", i + 1),
            signing_key_id: format!("witness-key-{}", i + 1),
            public_key: key.verifying_key().to_bytes(),
            not_before: 1_000,
            not_after: 5_000,
        }).collect::<Vec<_>>();
        let payload = WitnessRosterManifestPayload {
            version,
            owner_subject: "owner:akefa".into(),
            stream_id: "iroka:audit:primary".into(),
            issued_at: 1_000,
            expires_at: 4_000,
            witnesses,
            revoked_key_ids: Vec::new(),
        };
        let bytes = SignedWitnessRosterManifest::signing_bytes_for(&root.key_id, &payload).unwrap();
        let signature = owner.sign(&bytes).to_bytes().to_vec();
        (
            owner, root.clone(),
            SignedWitnessRosterManifest::from_signature(root.key_id.clone(), payload, signature),
        )
    }

    #[test]
    fn activates_owner_signed_roster_and_persists_version() {
        let (_, root, manifest) = fixture(1);
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        let state = activate_signed_witness_roster(&manifest, "owner:akefa", &root, &store, 1_100).unwrap();
        assert_eq!(state.version(), Some(1));
        assert_eq!(store.highest_witness_roster_version(), Ok(Some(1)));
        assert_eq!(store.witness_roster_history_count(), Ok(1));
    }

    #[test]
    fn rejects_manifest_tampering_and_wrong_owner() {
        let (_, root, manifest) = fixture(1);
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        let mut tampered = manifest.clone();
        tampered.payload.stream_id = "iroka:audit:other".into();
        assert!(matches!(
            activate_signed_witness_roster(&tampered, "owner:akefa", &root, &store, 1_100),
            Err(WitnessRosterManifestError::InvalidSignature)
        ));
        assert!(matches!(
            activate_signed_witness_roster(&manifest, "owner:someone-else", &root, &store, 1_100),
            Err(WitnessRosterManifestError::OwnerMismatch)
        ));
    }

    #[test]
    fn rejects_wrong_root_expiry_and_not_yet_valid_manifest() {
        let (_, root, manifest) = fixture(1);
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        let wrong = TrustRoot {
            public_key: SigningKey::from_bytes(&[99; 32]).verifying_key().to_bytes(),
            ..root.clone()
        };
        assert!(matches!(
            activate_signed_witness_roster(&manifest, "owner:akefa", &wrong, &store, 1_100),
            Err(WitnessRosterManifestError::InvalidSignature)
        ));
        assert!(matches!(
            activate_signed_witness_roster(&manifest, "owner:akefa", &root, &store, 4_100),
            Err(WitnessRosterManifestError::Expired)
        ));
        assert!(matches!(
            activate_signed_witness_roster(&manifest, "owner:akefa", &root, &store, 950),
            Err(WitnessRosterManifestError::NotYetValid)
        ));
    }

    #[test]
    fn rejects_duplicate_keys_and_noncanonical_order() {
        let (owner, root, mut manifest) = fixture(1);
        manifest.payload.witnesses[1].public_key = manifest.payload.witnesses[0].public_key;
        let bytes = manifest.signing_bytes().unwrap();
        manifest.signature = owner.sign(&bytes).to_bytes().to_vec();
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        assert!(matches!(
            activate_signed_witness_roster(&manifest, "owner:akefa", &root, &store, 1_100),
            Err(WitnessRosterManifestError::InvalidRoster)
        ));

        let (owner, root, mut manifest) = fixture(1);
        manifest.payload.witnesses.swap(0, 1);
        let bytes = manifest.signing_bytes().unwrap();
        manifest.signature = owner.sign(&bytes).to_bytes().to_vec();
        assert!(matches!(
            activate_signed_witness_roster(&manifest, "owner:akefa", &root, &store, 1_100),
            Err(WitnessRosterManifestError::NonCanonicalOrdering)
        ));
    }

    #[test]
    fn rejects_roster_rollback_and_conflicting_same_version() {
        let (_, root, second) = fixture(2);
        let (_, _, first) = fixture(1);
        let (_, _, conflicting) = fixture(2);
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        activate_signed_witness_roster(&second, "owner:akefa", &root, &store, 1_100).unwrap();
        assert!(matches!(
            activate_signed_witness_roster(&first, "owner:akefa", &root, &store, 1_100),
            Err(WitnessRosterManifestError::Rollback)
        ));
        assert!(matches!(
            activate_signed_witness_roster(&conflicting, "owner:akefa", &root, &store, 1_100),
            Err(WitnessRosterManifestError::Rollback)
        ));
    }
}
