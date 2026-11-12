//! G08 trusted-time and cryptographic worker-authentication boundary.
//!
//! A production caller must inject a trusted clock and durable replay guard.
//! This module deliberately provides no wall-clock fallback and no production
//! in-memory replay implementation. Worker proofs are Ed25519 signatures over
//! RFC 8785 canonical JSON and are bound to one operation and resource scope.

use std::collections::HashMap;
use std::sync::Mutex;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const G08_WORKER_AUDIENCE: &str = "iroka-g08-worker-v1";
pub const MAX_WORKER_PROOF_TTL_SECS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedTimeError {
    Unavailable,
    Invalid,
}

/// Trusted clock adapter. Implementations are part of the trusted computing
/// base and must fail closed when their authenticated time source is stale,
/// unavailable, or inconsistent. No SystemTime fallback is provided.
pub trait TrustedClock: Send + Sync {
    fn now_unix_seconds(&self) -> Result<u64, TrustedTimeError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerReplayError {
    Replay,
    Unavailable,
}

/// Must atomically persist the highest accepted sequence for each worker/key
/// pair. Production implementations must be durable across restart and shared
/// across every verifier instance that can accept the same worker identity.
pub trait WorkerReplayGuard: Send + Sync {
    fn consume_sequence(
        &self,
        worker_id: &str,
        key_id: &str,
        sequence: u64,
    ) -> Result<(), WorkerReplayError>;
}

/// Must consult current worker and key revocation state. Unavailable means deny.
pub trait WorkerRevocationChecker: Send + Sync {
    fn worker_revoked(&self, worker_id: &str) -> Result<bool, WorkerReplayError>;
    fn key_revoked(&self, worker_id: &str, key_id: &str)
        -> Result<bool, WorkerReplayError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkerKey {
    pub worker_id: String,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Debug, Clone)]
struct WorkerKeyRecord {
    key: VerifyingKey,
    not_before: u64,
    not_after: u64,
}

/// Immutable worker trust snapshot. Key rotation is performed by replacing
/// the snapshot; revoked keys must also be rejected by the revocation adapter.
#[derive(Debug, Clone)]
pub struct WorkerTrustStore {
    keys: HashMap<(String, String), WorkerKeyRecord>,
}

impl WorkerTrustStore {
    pub fn new(keys: Vec<WorkerKey>) -> Result<Self, WorkerAuthError> {
        if keys.is_empty() {
            return Err(WorkerAuthError::InvalidTrustConfiguration);
        }
        let mut records = HashMap::new();
        for item in keys {
            if item.worker_id.trim().is_empty()
                || item.key_id.trim().is_empty()
                || item.worker_id.len() > 256
                || item.key_id.len() > 256
                || item.not_before >= item.not_after
            {
                return Err(WorkerAuthError::InvalidTrustConfiguration);
            }
            let key = VerifyingKey::from_bytes(&item.public_key)
                .map_err(|_| WorkerAuthError::InvalidTrustConfiguration)?;
            let index = (item.worker_id.clone(), item.key_id.clone());
            if records
                .insert(
                    index,
                    WorkerKeyRecord {
                        key,
                        not_before: item.not_before,
                        not_after: item.not_after,
                    },
                )
                .is_some()
            {
                return Err(WorkerAuthError::InvalidTrustConfiguration);
            }
        }
        Ok(Self { keys: records })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkerProofPayload {
    pub worker_id: String,
    pub key_id: String,
    pub audience: String,
    pub operation: String,
    pub tenant_selector: String,
    pub resource_id: Option<String>,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedWorkerProof {
    pub payload: WorkerProofPayload,
    pub signature: Vec<u8>,
}

impl SignedWorkerProof {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, WorkerAuthError> {
        serde_jcs::to_vec(&self.payload).map_err(|_| WorkerAuthError::MalformedProof)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerOperationScope {
    operation: String,
    tenant_selector: String,
    resource_id: Option<String>,
}

impl WorkerOperationScope {
    pub fn new(
        operation: impl Into<String>,
        tenant_selector: impl Into<String>,
        resource_id: Option<String>,
    ) -> Result<Self, WorkerAuthError> {
        let operation = operation.into();
        let tenant_selector = tenant_selector.into();
        if operation.trim().is_empty()
            || tenant_selector.trim().is_empty()
            || operation.len() > 128
            || tenant_selector.len() > 256
            || resource_id.as_ref().is_some_and(|v| v.trim().is_empty() || v.len() > 256)
        {
            return Err(WorkerAuthError::MalformedProof);
        }
        Ok(Self {
            operation,
            tenant_selector,
            resource_id,
        })
    }
}

/// Opaque identity returned only after signature, scope, time, revocation and
/// replay checks have succeeded. Callers cannot construct one directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedWorker {
    worker_id: String,
    key_id: String,
    sequence: u64,
    authenticated_at: u64,
    proof_digest: [u8; 32],
}

impl AuthenticatedWorker {
    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn authenticated_at(&self) -> u64 {
        self.authenticated_at
    }

    pub fn proof_digest(&self) -> [u8; 32] {
        self.proof_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerAuthError {
    InvalidTrustConfiguration,
    MalformedProof,
    UnknownWorkerKey,
    KeyOutsideValidity,
    InvalidSignature,
    ScopeMismatch,
    NotYetValid,
    Expired,
    ExcessiveLifetime,
    WorkerRevoked,
    KeyRevoked,
    RevocationUnavailable,
    Replay,
    ReplayGuardUnavailable,
    ClockUnavailable,
    InvalidClock,
}

pub struct Ed25519WorkerAuthenticator<R, G> {
    trust: WorkerTrustStore,
    revocations: R,
    replay_guard: G,
}

impl<R: WorkerRevocationChecker, G: WorkerReplayGuard> Ed25519WorkerAuthenticator<R, G> {
    pub fn new(trust: WorkerTrustStore, revocations: R, replay_guard: G) -> Self {
        Self {
            trust,
            revocations,
            replay_guard,
        }
    }

    /// Obtain time only from the injected trusted clock. The proof is bound to
    /// the exact operation, tenant selector and optional resource identifier.
    pub fn authenticate(
        &self,
        proof: &SignedWorkerProof,
        scope: &WorkerOperationScope,
        clock: &dyn TrustedClock,
    ) -> Result<AuthenticatedWorker, WorkerAuthError> {
        let now = clock
            .now_unix_seconds()
            .map_err(|_| WorkerAuthError::ClockUnavailable)?;
        if now == 0 {
            return Err(WorkerAuthError::InvalidClock);
        }
        let p = &proof.payload;
        if p.worker_id.trim().is_empty()
            || p.key_id.trim().is_empty()
            || p.worker_id.len() > 256
            || p.key_id.len() > 256
            || p.sequence == 0
            || p.audience != G08_WORKER_AUDIENCE
        {
            return Err(WorkerAuthError::MalformedProof);
        }
        if p.operation != scope.operation
            || p.tenant_selector != scope.tenant_selector
            || p.resource_id != scope.resource_id
        {
            return Err(WorkerAuthError::ScopeMismatch);
        }
        if p.issued_at > now {
            return Err(WorkerAuthError::NotYetValid);
        }
        if p.expires_at <= now {
            return Err(WorkerAuthError::Expired);
        }
        if p.expires_at <= p.issued_at
            || p.expires_at - p.issued_at > MAX_WORKER_PROOF_TTL_SECS
        {
            return Err(WorkerAuthError::ExcessiveLifetime);
        }
        let record = self
            .trust
            .keys
            .get(&(p.worker_id.clone(), p.key_id.clone()))
            .ok_or(WorkerAuthError::UnknownWorkerKey)?;
        if now < record.not_before || now >= record.not_after {
            return Err(WorkerAuthError::KeyOutsideValidity);
        }
        if self
            .revocations
            .worker_revoked(&p.worker_id)
            .map_err(|_| WorkerAuthError::RevocationUnavailable)?
        {
            return Err(WorkerAuthError::WorkerRevoked);
        }
        if self
            .revocations
            .key_revoked(&p.worker_id, &p.key_id)
            .map_err(|_| WorkerAuthError::RevocationUnavailable)?
        {
            return Err(WorkerAuthError::KeyRevoked);
        }
        if proof.signature.len() != 64 {
            return Err(WorkerAuthError::MalformedProof);
        }
        let signature = Signature::from_slice(&proof.signature)
            .map_err(|_| WorkerAuthError::MalformedProof)?;
        let signing_bytes = proof.signing_bytes()?;
        record
            .key
            .verify(&signing_bytes, &signature)
            .map_err(|_| WorkerAuthError::InvalidSignature)?;

        self.replay_guard
            .consume_sequence(&p.worker_id, &p.key_id, p.sequence)
            .map_err(|error| match error {
                WorkerReplayError::Replay => WorkerAuthError::Replay,
                WorkerReplayError::Unavailable => WorkerAuthError::ReplayGuardUnavailable,
            })?;

        let proof_digest: [u8; 32] = Sha256::digest(
            [signing_bytes.as_slice(), proof.signature.as_slice()].concat(),
        )
        .into();
        Ok(AuthenticatedWorker {
            worker_id: p.worker_id.clone(),
            key_id: p.key_id.clone(),
            sequence: p.sequence,
            authenticated_at: now,
            proof_digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::Mutex;

    struct FixedClock(u64);
    impl TrustedClock for FixedClock {
        fn now_unix_seconds(&self) -> Result<u64, TrustedTimeError> {
            Ok(self.0)
        }
    }

    struct UnavailableClock;
    impl TrustedClock for UnavailableClock {
        fn now_unix_seconds(&self) -> Result<u64, TrustedTimeError> {
            Err(TrustedTimeError::Unavailable)
        }
    }

    #[derive(Default)]
    struct TestReplayGuard(Mutex<HashMap<(String, String), u64>>);
    impl WorkerReplayGuard for TestReplayGuard {
        fn consume_sequence(
            &self,
            worker_id: &str,
            key_id: &str,
            sequence: u64,
        ) -> Result<(), WorkerReplayError> {
            let mut values = self.0.lock().map_err(|_| WorkerReplayError::Unavailable)?;
            let key = (worker_id.to_owned(), key_id.to_owned());
            if values.get(&key).is_some_and(|previous| sequence <= *previous) {
                return Err(WorkerReplayError::Replay);
            }
            values.insert(key, sequence);
            Ok(())
        }
    }

    struct NoRevocations;
    impl WorkerRevocationChecker for NoRevocations {
        fn worker_revoked(&self, _: &str) -> Result<bool, WorkerReplayError> {
            Ok(false)
        }
        fn key_revoked(&self, _: &str, _: &str) -> Result<bool, WorkerReplayError> {
            Ok(false)
        }
    }

    struct RevokedWorker;
    impl WorkerRevocationChecker for RevokedWorker {
        fn worker_revoked(&self, _: &str) -> Result<bool, WorkerReplayError> {
            Ok(true)
        }
        fn key_revoked(&self, _: &str, _: &str) -> Result<bool, WorkerReplayError> {
            Ok(false)
        }
    }

    fn fixture<R: WorkerRevocationChecker>(
        revocations: R,
    ) -> (SigningKey, Ed25519WorkerAuthenticator<R, TestReplayGuard>) {
        let signing = SigningKey::from_bytes(&[91u8; 32]);
        let trust = WorkerTrustStore::new(vec![WorkerKey {
            worker_id: "worker:alpha".into(),
            key_id: "worker-key-1".into(),
            public_key: signing.verifying_key().to_bytes(),
            not_before: 900,
            not_after: 2_000,
        }])
        .unwrap();
        (
            signing,
            Ed25519WorkerAuthenticator::new(trust, revocations, TestReplayGuard::default()),
        )
    }

    fn proof(signing: &SigningKey, sequence: u64) -> SignedWorkerProof {
        let payload = WorkerProofPayload {
            worker_id: "worker:alpha".into(),
            key_id: "worker-key-1".into(),
            audience: G08_WORKER_AUDIENCE.into(),
            operation: "task.claim".into(),
            tenant_selector: "tenant:1".into(),
            resource_id: None,
            sequence,
            issued_at: 1_000,
            expires_at: 1_020,
        };
        let bytes = serde_jcs::to_vec(&payload).unwrap();
        SignedWorkerProof {
            payload,
            signature: signing.sign(&bytes).to_bytes().to_vec(),
        }
    }

    fn scope() -> WorkerOperationScope {
        WorkerOperationScope::new("task.claim", "tenant:1", None).unwrap()
    }

    #[test]
    fn accepts_valid_scope_bound_ed25519_worker_proof() {
        let (signing, verifier) = fixture(NoRevocations);
        let worker = verifier
            .authenticate(&proof(&signing, 1), &scope(), &FixedClock(1_010))
            .unwrap();
        assert_eq!(worker.worker_id(), "worker:alpha");
        assert_eq!(worker.key_id(), "worker-key-1");
        assert_eq!(worker.sequence(), 1);
        assert_eq!(worker.authenticated_at(), 1_010);
    }

    #[test]
    fn rejects_replayed_or_non_monotonic_worker_sequence() {
        let (signing, verifier) = fixture(NoRevocations);
        let signed = proof(&signing, 1);
        verifier
            .authenticate(&signed, &scope(), &FixedClock(1_010))
            .unwrap();
        assert_eq!(
            verifier.authenticate(&signed, &scope(), &FixedClock(1_010)),
            Err(WorkerAuthError::Replay)
        );
    }

    #[test]
    fn rejects_scope_substitution() {
        let (signing, verifier) = fixture(NoRevocations);
        let wrong_scope =
            WorkerOperationScope::new("task.complete", "tenant:1", Some("task:1".into()))
                .unwrap();
        assert_eq!(
            verifier.authenticate(&proof(&signing, 1), &wrong_scope, &FixedClock(1_010)),
            Err(WorkerAuthError::ScopeMismatch)
        );
    }

    #[test]
    fn rejects_expired_and_excessively_long_proofs() {
        let (signing, verifier) = fixture(NoRevocations);
        assert_eq!(
            verifier.authenticate(&proof(&signing, 1), &scope(), &FixedClock(1_020)),
            Err(WorkerAuthError::Expired)
        );
        let mut long = proof(&signing, 2);
        long.payload.expires_at = 1_100;
        long.signature = signing
            .sign(&serde_jcs::to_vec(&long.payload).unwrap())
            .to_bytes()
            .to_vec();
        assert_eq!(
            verifier.authenticate(&long, &scope(), &FixedClock(1_010)),
            Err(WorkerAuthError::ExcessiveLifetime)
        );
    }

    #[test]
    fn fails_closed_when_clock_is_unavailable_or_worker_revoked() {
        let (signing, verifier) = fixture(NoRevocations);
        assert_eq!(
            verifier.authenticate(&proof(&signing, 1), &scope(), &UnavailableClock),
            Err(WorkerAuthError::ClockUnavailable)
        );
        let (signing, revoked) = fixture(RevokedWorker);
        assert_eq!(
            revoked.authenticate(&proof(&signing, 1), &scope(), &FixedClock(1_010)),
            Err(WorkerAuthError::WorkerRevoked)
        );
    }

    #[test]
    fn rejects_tampered_signature() {
        let (signing, verifier) = fixture(NoRevocations);
        let mut signed = proof(&signing, 1);
        signed.payload.tenant_selector = "tenant:other".into();
        assert_eq!(
            verifier.authenticate(&signed, &scope(), &FixedClock(1_010)),
            Err(WorkerAuthError::ScopeMismatch)
        );
    }
}
