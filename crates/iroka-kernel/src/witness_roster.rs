//! Owner-signed K-04 witness roster manifests and activation.
//!
//! The Owner root is an out-of-band trust anchor. Never accept it from the
//! manifest, an API request, or another untrusted source. Production adapters
//! must load it from protected bootstrap configuration or hardware-backed trust.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use sha2::{Digest, Sha256};

use crate::audit_verifier::{
    AuthorizedWitness, VerificationError, WitnessReceiptVerifier, WitnessRosterState,
    AUTHORIZED_WITNESS_COUNT,
};
use crate::{SecurityStoreError, SqliteSecurityStore};

const DOMAIN_SEPARATOR: &[u8] = b"IROKA-K04-OWNER-WITNESS-ROSTER-V1\0";
const MAX_ROSTER_LIFETIME_SECS: u64 = 31_536_000;
const MAX_CLOCK_SKEW_SECS: u64 = 30;

#[derive(Debug, Clone)]
pub struct OwnerWitnessRosterRoot {
    pub owner_subject: String,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
}

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
        Self {
            root_key_id: root_key_id.into(),
            payload,
            signature,
        }
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
        let encoded = serde_json::to_vec(&Envelope {
            root_key_id,
            payload,
        })
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
    StateUnavailable,
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
    root: &OwnerWitnessRosterRoot,
    store: &SqliteSecurityStore,
    now: u64,
) -> Result<WitnessRosterState, WitnessRosterManifestError> {
    if root.owner_subject.trim().is_empty()
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
    if payload.owner_subject != root.owner_subject {
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
    if payload.issued_at < root.not_before
        || payload.issued_at >= root.not_after
        || payload.expires_at > root.not_after
    {
        return Err(WitnessRosterManifestError::OwnerRootOutsideValidity);
    }
    if payload
        .witnesses
        .windows(2)
        .any(|pair| pair[0].witness_id >= pair[1].witness_id)
        || payload
            .revoked_key_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(WitnessRosterManifestError::NonCanonicalOrdering);
    }

    let root_key = VerifyingKey::from_bytes(&root.public_key)
        .map_err(|_| WitnessRosterManifestError::InvalidOwnerRoot)?;
    let signature = Signature::from_slice(&manifest.signature)
        .map_err(|_| WitnessRosterManifestError::Malformed)?;
    let signing_bytes = manifest.signing_bytes()?;
    root_key
        .verify(&signing_bytes, &signature)
        .map_err(|_| WitnessRosterManifestError::InvalidSignature)?;

    let mut authorized = Vec::with_capacity(AUTHORIZED_WITNESS_COUNT);
    let mut witness_ids = std::collections::BTreeSet::new();
    let mut key_ids = std::collections::BTreeSet::new();
    let mut public_keys = std::collections::BTreeSet::new();
    let revoked: std::collections::BTreeSet<&str> =
        payload.revoked_key_ids.iter().map(String::as_str).collect();
    if payload
        .revoked_key_ids
        .iter()
        .any(|id| id.trim().is_empty())
    {
        return Err(WitnessRosterManifestError::Malformed);
    }
    for witness in &payload.witnesses {
        if witness.witness_id.trim().is_empty()
            || witness.signing_key_id.trim().is_empty()
            || witness.not_before >= witness.not_after
            || witness.not_before > now
            || witness.not_after <= now
            || witness.not_before > payload.issued_at
            || witness.not_after < payload.expires_at
            || witness.public_key == root.public_key
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
    let manifest_json =
        serde_json::to_vec(manifest).map_err(|_| WitnessRosterManifestError::Malformed)?;
    store.install_witness_roster(
        payload.version,
        digest.as_slice(),
        payload.issued_at,
        payload.expires_at,
        now,
        &manifest_json,
    )?;

    Ok(WitnessRosterState::provisioned_from_manifest(
        verifier,
        payload.stream_id.clone(),
        payload.version,
        payload.expires_at,
    ))
}

/// Historical resolver backed by immutable Owner-signed roster manifests retained by the
/// security store. It deliberately validates a historical manifest at the receipt's
/// witness-assigned time, not at the current time.
pub struct HistoricalWitnessRosterResolver {
    root: OwnerWitnessRosterRoot,
    store: Arc<SqliteSecurityStore>,
}

impl HistoricalWitnessRosterResolver {
    pub fn new(root: OwnerWitnessRosterRoot, store: Arc<SqliteSecurityStore>) -> Self {
        Self { root, store }
    }
}

impl crate::WitnessReceiptKeyResolver for HistoricalWitnessRosterResolver {
    fn verify_receipt(
        &self,
        receipt: &crate::WitnessReceipt,
    ) -> Result<(), VerificationError> {
        let manifests = self
            .store
            .witness_roster_manifests()
            .map_err(|_| VerificationError::InvalidWitnessRoster)?;
        let mut matched = false;
        for (_, bytes) in manifests {
            let manifest: SignedWitnessRosterManifest = serde_json::from_slice(&bytes)
                .map_err(|_| VerificationError::InvalidWitnessRoster)?;
            if manifest.payload.stream_id != receipt.stream_id
                || receipt.witnessed_at < manifest.payload.issued_at
                || receipt.witnessed_at >= manifest.payload.expires_at
                || !manifest.payload.witnesses.iter().any(|entry| {
                    entry.witness_id == receipt.witness_id
                        && entry.signing_key_id == receipt.signing_key_id
                })
            {
                continue;
            }
            let temporary_store = SqliteSecurityStore::open_in_memory()
                .map_err(|_| VerificationError::InvalidWitnessRoster)?;
            let state = activate_signed_witness_roster(
                &manifest,
                &self.root,
                &temporary_store,
                receipt.witnessed_at,
            )
            .map_err(|_| VerificationError::UnauthorizedWitness)?;
            state.verify_receipt_at(receipt, receipt.witnessed_at)?;
            if matched {
                // A key ID must resolve to exactly one historical signed roster.
                return Err(VerificationError::InvalidWitnessRoster);
            }
            matched = true;
        }
        if matched {
            Ok(())
        } else {
            Err(VerificationError::UnauthorizedWitness)
        }
    }
}

/// Process-local atomic publication boundary for the currently trusted witness roster.
/// Deployments should share one manager across all checkpoint and recovery handlers.
pub struct WitnessRosterManager {
    state: RwLock<WitnessRosterState>,
}

impl WitnessRosterManager {
    pub fn unprovisioned() -> Self {
        Self {
            state: RwLock::new(WitnessRosterState::unprovisioned()),
        }
    }

    /// Persist and validate the new manifest first, then atomically replace the in-memory
    /// state. Readers holding the read lock finish against the old snapshot; subsequent
    /// readers observe only the new version.
    pub fn activate(
        &self,
        manifest: &SignedWitnessRosterManifest,
        root: &OwnerWitnessRosterRoot,
        store: &SqliteSecurityStore,
        now: u64,
    ) -> Result<u64, WitnessRosterManifestError> {
        let candidate = activate_signed_witness_roster(manifest, root, store, now)?;
        let version = candidate
            .version()
            .ok_or(WitnessRosterManifestError::Malformed)?;
        let mut active = self
            .state
            .write()
            .map_err(|_| WitnessRosterManifestError::StateUnavailable)?;
        if active.version().is_some_and(|current| version < current) {
            return Err(WitnessRosterManifestError::Rollback);
        }
        *active = candidate;
        Ok(version)
    }

    pub fn active_version(&self) -> Result<Option<u64>, WitnessRosterManifestError> {
        self.state
            .read()
            .map(|state| state.version())
            .map_err(|_| WitnessRosterManifestError::StateUnavailable)
    }

    pub fn verify_checkpoint_and_quorum(
        &self,
        signed: &crate::SignedCheckpoint,
        checkpoint_verifier: &dyn crate::CheckpointSignatureVerifier,
        receipts: &[crate::WitnessReceipt],
        now: u64,
    ) -> Result<(), VerificationError> {
        let state = self
            .state
            .read()
            .map_err(|_| VerificationError::RosterStateUnavailable)?;
        crate::audit_verifier::verify_checkpoint_and_quorum(
            signed,
            checkpoint_verifier,
            receipts,
            &state,
            now,
        )
    }

    pub fn verify_receipt_chain(
        &self,
        receipts: &[crate::WitnessReceipt],
        expected_head: &crate::WitnessReceipt,
        now: u64,
    ) -> Result<(), VerificationError> {
        let state = self
            .state
            .read()
            .map_err(|_| VerificationError::RosterStateUnavailable)?;
        crate::audit_verifier::verify_receipt_chain(receipts, expected_head, &state, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture(
        version: u64,
    ) -> (
        SigningKey,
        OwnerWitnessRosterRoot,
        SignedWitnessRosterManifest,
    ) {
        let owner = SigningKey::from_bytes(&[61u8; 32]);
        let witness_keys = [
            SigningKey::from_bytes(&[62u8; 32]),
            SigningKey::from_bytes(&[63u8; 32]),
            SigningKey::from_bytes(&[64u8; 32]),
        ];
        let root = OwnerWitnessRosterRoot {
            owner_subject: "owner:akefa".into(),
            key_id: "owner-witness-root-01".into(),
            public_key: owner.verifying_key().to_bytes(),
            not_before: 900,
            not_after: 10_000,
        };
        let witnesses = witness_keys
            .iter()
            .enumerate()
            .map(|(i, key)| WitnessRosterEntry {
                witness_id: format!("witness-{}", i + 1),
                signing_key_id: format!("witness-key-{}", i + 1),
                public_key: key.verifying_key().to_bytes(),
                not_before: 1_000,
                not_after: 5_000,
            })
            .collect::<Vec<_>>();
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
            owner,
            root.clone(),
            SignedWitnessRosterManifest::from_signature(root.key_id.clone(), payload, signature),
        )
    }

    #[test]
    fn manager_atomically_publishes_higher_roster_version() {
        let (_, root, first) = fixture(1);
        let (_, _, second) = fixture(2);
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        let manager = WitnessRosterManager::unprovisioned();
        assert_eq!(manager.active_version(), Ok(None));
        assert_eq!(manager.activate(&first, &root, &store, 1_100), Ok(1));
        assert_eq!(manager.active_version(), Ok(Some(1)));
        assert_eq!(manager.activate(&second, &root, &store, 1_200), Ok(2));
        assert_eq!(manager.active_version(), Ok(Some(2)));
        assert_eq!(
            manager.activate(&first, &root, &store, 1_300),
            Err(WitnessRosterManifestError::Rollback)
        );
        assert_eq!(manager.active_version(), Ok(Some(2)));
    }

    #[test]
    fn activates_owner_signed_roster_and_persists_version() {
        let (_, root, manifest) = fixture(1);
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        let state = activate_signed_witness_roster(&manifest, &root, &store, 1_100).unwrap();
        let retry = activate_signed_witness_roster(&manifest, &root, &store, 1_101).unwrap();
        assert_eq!(retry.version(), Some(1));
        assert_eq!(state.version(), Some(1));
        assert_eq!(store.highest_witness_roster_version(), Ok(Some(1)));
        assert_eq!(store.witness_roster_history_count(), Ok(1));
    }

    #[test]
    fn activated_signed_roster_verifies_the_approved_two_of_three_quorum() {
        use crate::audit_checkpoint::{AuditHead, CheckpointBuilder, V1_CHAIN_FORMAT};
        use crate::audit_signer::{
            CheckpointSigner, Ed25519CheckpointVerifier, LocalEd25519TestSigner,
        };
        use crate::audit_verifier::verify_checkpoint_and_quorum;
        use crate::audit_witness::{LocalWitnessTestSigner, MemoryWitnessLedger, WitnessLedger};

        let (_, root, manifest) = fixture(1);
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        let state = activate_signed_witness_roster(&manifest, &root, &store, 1_100).unwrap();

        let checkpoint_signer = LocalEd25519TestSigner::from_test_seed("checkpoint-key", [65; 32]);
        let checkpoint_verifier = Ed25519CheckpointVerifier::new(vec![(
            "checkpoint-key".into(),
            checkpoint_signer.verifying_key(),
        )]);
        let builder = CheckpointBuilder::new("iroka:audit:primary", "checkpoint-key");
        let head = AuditHead {
            first_sequence: 1,
            last_sequence: 1,
            event_count: 1,
            head_event_hash: [7; 32],
            chain_format: V1_CHAIN_FORMAT.into(),
        };
        let signed = checkpoint_signer
            .sign_checkpoint(&builder.initial_v1_anchor(&head, 1_100).unwrap())
            .unwrap();

        let witness_one = MemoryWitnessLedger::new(
            "witness-1",
            Box::new(LocalWitnessTestSigner::from_test_seed(
                "witness-key-1",
                [62; 32],
            )),
        );
        let witness_two = MemoryWitnessLedger::new(
            "witness-2",
            Box::new(LocalWitnessTestSigner::from_test_seed(
                "witness-key-2",
                [63; 32],
            )),
        );
        let receipt_one = witness_one
            .accept(&signed, &checkpoint_verifier, 1_101)
            .unwrap();
        let receipt_two = witness_two
            .accept(&signed, &checkpoint_verifier, 1_101)
            .unwrap();
        assert_eq!(
            verify_checkpoint_and_quorum(
                &signed,
                &checkpoint_verifier,
                &[receipt_one, receipt_two],
                &state,
                1_102,
            ),
            Ok(())
        );
    }

    #[test]
    fn rejects_manifest_tampering_and_wrong_owner() {
        let (_, root, manifest) = fixture(1);
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        let mut tampered = manifest.clone();
        tampered.payload.stream_id = "iroka:audit:other".into();
        assert!(matches!(
            activate_signed_witness_roster(&tampered, &root, &store, 1_100),
            Err(WitnessRosterManifestError::InvalidSignature)
        ));
        assert!(matches!(
            activate_signed_witness_roster(
                &manifest,
                &OwnerWitnessRosterRoot {
                    owner_subject: String::from("owner:someone-else"),
                    ..root.clone()
                },
                &store,
                1_100
            ),
            Err(WitnessRosterManifestError::OwnerMismatch)
        ));
    }

    #[test]
    fn rejects_wrong_root_expiry_and_not_yet_valid_manifest() {
        let (_, root, manifest) = fixture(1);
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        let wrong = OwnerWitnessRosterRoot {
            public_key: SigningKey::from_bytes(&[99; 32]).verifying_key().to_bytes(),
            ..root.clone()
        };
        assert!(matches!(
            activate_signed_witness_roster(&manifest, &wrong, &store, 1_100),
            Err(WitnessRosterManifestError::InvalidSignature)
        ));
        assert!(matches!(
            activate_signed_witness_roster(&manifest, &root, &store, 4_100),
            Err(WitnessRosterManifestError::Expired)
        ));
        assert!(matches!(
            activate_signed_witness_roster(&manifest, &root, &store, 950),
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
            activate_signed_witness_roster(&manifest, &root, &store, 1_100),
            Err(WitnessRosterManifestError::InvalidRoster)
        ));

        let (owner, root, mut manifest) = fixture(1);
        manifest.payload.witnesses.swap(0, 1);
        let bytes = manifest.signing_bytes().unwrap();
        manifest.signature = owner.sign(&bytes).to_bytes().to_vec();
        assert!(matches!(
            activate_signed_witness_roster(&manifest, &root, &store, 1_100),
            Err(WitnessRosterManifestError::NonCanonicalOrdering)
        ));
    }

    #[test]
    fn rejects_a_key_listed_as_revoked_from_remaining_active() {
        let (owner, root, mut manifest) = fixture(1);
        manifest.payload.revoked_key_ids = vec!["witness-key-2".into()];
        manifest.signature = owner
            .sign(&manifest.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        assert!(matches!(
            activate_signed_witness_roster(&manifest, &root, &store, 1_100),
            Err(WitnessRosterManifestError::InvalidRoster)
        ));
    }

    #[test]
    fn accepts_new_roster_version_with_explicit_key_rotation_and_revocation() {
        let (_, root, first) = fixture(1);
        let (owner, _, mut rotated) = fixture(2);
        for (index, witness) in rotated.payload.witnesses.iter_mut().enumerate() {
            witness.signing_key_id = format!("witness-key-v2-{}", index + 1);
            witness.public_key = SigningKey::from_bytes(&[72 + index as u8; 32])
                .verifying_key()
                .to_bytes();
        }
        rotated.payload.revoked_key_ids = vec![
            "witness-key-1".into(),
            "witness-key-2".into(),
            "witness-key-3".into(),
        ];
        rotated.signature = owner
            .sign(&rotated.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        activate_signed_witness_roster(&first, &root, &store, 1_100).unwrap();
        let state = activate_signed_witness_roster(&rotated, &root, &store, 1_200).unwrap();
        assert_eq!(state.version(), Some(2));
        assert_eq!(store.highest_witness_roster_version(), Ok(Some(2)));
        assert_eq!(store.witness_roster_history_count(), Ok(2));
    }

    #[test]
    fn rejects_witness_key_that_expires_before_its_roster() {
        let (owner, root, mut manifest) = fixture(1);
        manifest.payload.witnesses[0].not_after = 3_000;
        manifest.signature = owner
            .sign(&manifest.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        assert!(matches!(
            activate_signed_witness_roster(&manifest, &root, &store, 1_100),
            Err(WitnessRosterManifestError::InvalidRoster)
        ));
    }

    #[test]
    fn rejects_roster_rollback_and_conflicting_same_version() {
        let (_, root, second) = fixture(2);
        let (_, _, first) = fixture(1);
        let (owner, _, mut conflicting) = fixture(2);
        conflicting.payload.stream_id = "iroka:audit:conflicting".into();
        conflicting.signature = owner
            .sign(&conflicting.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        let store = SqliteSecurityStore::open_in_memory().unwrap();
        activate_signed_witness_roster(&second, &root, &store, 1_100).unwrap();
        assert!(matches!(
            activate_signed_witness_roster(&first, &root, &store, 1_100),
            Err(WitnessRosterManifestError::Rollback)
        ));
        assert!(matches!(
            activate_signed_witness_roster(&conflicting, &root, &store, 1_100),
            Err(WitnessRosterManifestError::Rollback)
        ));
    }
}
