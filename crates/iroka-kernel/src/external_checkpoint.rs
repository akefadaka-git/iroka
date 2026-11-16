//! Provider-neutral, signed external audit checkpoints and witness receipts.
//! Production signer and witness transports are deliberately injected by callers.
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const CHECKPOINT_DOMAIN: &[u8] = b"IROKA:G11:EXTERNAL-CHECKPOINT:V1\0";
const RECEIPT_DOMAIN: &[u8] = b"IROKA:G11:WITNESS-RECEIPT:V1\0";
const ALGORITHM: &str = "Ed25519";
const VERSION: u32 = 1;
const MAX_CLOCK_SKEW_SECS: u64 = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    Malformed,
    UnsupportedVersion,
    UnknownKey,
    InvalidSignature,
    StreamMismatch,
    SequenceConflict,
    SequenceGap,
    PredecessorMismatch,
    ReceiptMismatch,
    WitnessUnavailable,
    LocalIntegrityFailure,
    LocalAuditUnavailable,
    SequenceRegression,
    LocalBehindAnchor,
    LocalAheadOfAnchor,
    ForkDetected,
    QuorumNotMet,
    DuplicateWitness,
    InvalidWitnessEndpoint,
    InvalidWitnessResponse,
    WitnessIdentityMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointPayload {
    pub protocol: String,
    pub version: u32,
    pub stream_id: String,
    pub checkpoint_sequence: u64,
    pub event_sequence: u64,
    pub event_head_sha256: String,
    pub previous_checkpoint_sha256: Option<String>,
    pub signer_key_id: String,
    pub issued_at: u64,
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedCheckpoint {
    pub payload: CheckpointPayload,
    pub signature: Vec<u8>,
}

/// Proof object created only after checkpoint signature and witness quorum verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCheckpointEvidence {
    checkpoint: SignedCheckpoint,
    receipts: Vec<WitnessReceipt>,
    required_quorum: usize,
}

impl VerifiedCheckpointEvidence {
    pub fn checkpoint(&self) -> &SignedCheckpoint {
        &self.checkpoint
    }

    pub fn receipts(&self) -> &[WitnessReceipt] {
        &self.receipts
    }

    pub fn required_quorum(&self) -> usize {
        self.required_quorum
    }
}

impl SignedCheckpoint {
    pub fn digest(&self) -> Result<[u8; 32], CheckpointError> {
        let bytes = canonical(self)?;
        Ok(Sha256::digest(bytes).into())
    }

    pub fn signing_bytes(payload: &CheckpointPayload) -> Result<Vec<u8>, CheckpointError> {
        let mut bytes = CHECKPOINT_DOMAIN.to_vec();
        bytes.extend(canonical(payload)?);
        Ok(bytes)
    }

    pub fn verify(&self, trusted: &BTreeMap<String, VerifyingKey>) -> Result<(), CheckpointError> {
        validate_payload(&self.payload)?;
        let key = trusted
            .get(&self.payload.signer_key_id)
            .ok_or(CheckpointError::UnknownKey)?;
        let sig = Signature::from_slice(&self.signature)
            .map_err(|_| CheckpointError::InvalidSignature)?;
        key.verify(&Self::signing_bytes(&self.payload)?, &sig)
            .map_err(|_| CheckpointError::InvalidSignature)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WitnessReceiptPayload {
    pub protocol: String,
    pub version: u32,
    pub witness_id: String,
    pub witness_key_id: String,
    pub stream_id: String,
    pub checkpoint_sequence: u64,
    pub checkpoint_digest_sha256: String,
    pub previous_checkpoint_digest_sha256: Option<String>,
    pub accepted_at: u64,
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WitnessReceipt {
    pub payload: WitnessReceiptPayload,
    pub signature: Vec<u8>,
}

impl WitnessReceipt {
    pub fn signing_bytes(payload: &WitnessReceiptPayload) -> Result<Vec<u8>, CheckpointError> {
        let mut bytes = RECEIPT_DOMAIN.to_vec();
        bytes.extend(canonical(payload)?);
        Ok(bytes)
    }

    pub fn verify(
        &self,
        checkpoint: &SignedCheckpoint,
        trusted_checkpoint_signers: &BTreeMap<String, VerifyingKey>,
        trusted_witnesses: &BTreeMap<String, VerifyingKey>,
    ) -> Result<(), CheckpointError> {
        checkpoint.verify(trusted_checkpoint_signers)?;
        let p = &self.payload;
        let cp = &checkpoint.payload;
        if p.witness_id.trim().is_empty()
            || p.witness_key_id.trim().is_empty()
            || p.accepted_at == 0
            || p.accepted_at.saturating_add(MAX_CLOCK_SKEW_SECS) < cp.issued_at
        {
            return Err(CheckpointError::Malformed);
        }
        if p.protocol != "iroka.g11.witness-receipt"
            || p.version != VERSION
            || p.algorithm != ALGORITHM
        {
            return Err(CheckpointError::UnsupportedVersion);
        }
        if p.stream_id != cp.stream_id
            || p.checkpoint_sequence != cp.checkpoint_sequence
            || p.checkpoint_digest_sha256 != hex(&checkpoint.digest()?)
            || p.previous_checkpoint_digest_sha256 != cp.previous_checkpoint_sha256
        {
            return Err(CheckpointError::ReceiptMismatch);
        }
        let key = trusted_witnesses
            .get(&p.witness_key_id)
            .ok_or(CheckpointError::UnknownKey)?;
        let sig = Signature::from_slice(&self.signature)
            .map_err(|_| CheckpointError::InvalidSignature)?;
        key.verify(&Self::signing_bytes(p)?, &sig)
            .map_err(|_| CheckpointError::InvalidSignature)
    }
}

/// Inject a production HSM/KMS/Owner-controlled signer; no key material is stored here.
pub trait CheckpointSigner: Send + Sync {
    fn key_id(&self) -> &str;
    fn sign(&self, domain_separated_bytes: &[u8]) -> Result<Vec<u8>, CheckpointError>;
}

/// Independent witness transport. Implementations must durably enforce monotonic acceptance.
pub trait CheckpointWitness: Send + Sync {
    fn publish(&self, checkpoint: &SignedCheckpoint) -> Result<WitnessReceipt, CheckpointError>;
    fn latest(
        &self,
        stream_id: &str,
    ) -> Result<Option<(SignedCheckpoint, WitnessReceipt)>, CheckpointError>;
}

pub fn create_checkpoint(
    signer: &dyn CheckpointSigner,
    stream_id: &str,
    checkpoint_sequence: u64,
    event_sequence: u64,
    event_head: [u8; 32],
    previous_checkpoint_sha256: Option<String>,
    issued_at: u64,
) -> Result<SignedCheckpoint, CheckpointError> {
    if stream_id.trim().is_empty()
        || checkpoint_sequence == 0
        || event_sequence == 0
        || event_head == [0; 32]
        || issued_at == 0
    {
        return Err(CheckpointError::Malformed);
    }
    let payload = CheckpointPayload {
        protocol: "iroka.g11.audit-checkpoint".into(),
        version: VERSION,
        stream_id: stream_id.into(),
        checkpoint_sequence,
        event_sequence,
        event_head_sha256: hex(&event_head),
        previous_checkpoint_sha256,
        signer_key_id: signer.key_id().into(),
        issued_at,
        algorithm: ALGORITHM.into(),
    };
    validate_payload(&payload)?;
    let signature = signer.sign(&SignedCheckpoint::signing_bytes(&payload)?)?;
    Ok(SignedCheckpoint { payload, signature })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reconciliation {
    Exact,
    LocalAheadUnanchored,
}

/// Verify a configurable quorum of distinct witness identities for one exact envelope.
/// Trust roots must be supplied by the caller from the applicable governance configuration.
pub fn verify_witness_quorum(
    checkpoint: &SignedCheckpoint,
    receipts: &[WitnessReceipt],
    trusted_checkpoint_signers: &BTreeMap<String, VerifyingKey>,
    trusted_witnesses: &BTreeMap<String, VerifyingKey>,
    required: usize,
) -> Result<usize, CheckpointError> {
    if required == 0 {
        return Err(CheckpointError::Malformed);
    }
    checkpoint.verify(trusted_checkpoint_signers)?;
    let mut identities = std::collections::BTreeSet::new();
    let mut witness_keys = std::collections::BTreeSet::new();
    for receipt in receipts {
        receipt.verify(checkpoint, trusted_checkpoint_signers, trusted_witnesses)?;
        if !identities.insert(receipt.payload.witness_id.as_str())
            || !witness_keys.insert(receipt.payload.witness_key_id.as_str())
        {
            return Err(CheckpointError::DuplicateWitness);
        }
    }
    if identities.len() < required {
        return Err(CheckpointError::QuorumNotMet);
    }
    Ok(identities.len())
}

/// Verify a checkpoint signature and a quorum of distinct witness identities
/// and keys. The returned evidence cannot be constructed directly by callers.
pub fn verify_checkpoint_evidence(
    checkpoint: SignedCheckpoint,
    receipts: Vec<WitnessReceipt>,
    trusted_checkpoint_signers: &BTreeMap<String, VerifyingKey>,
    trusted_witnesses: &BTreeMap<String, VerifyingKey>,
    required: usize,
) -> Result<VerifiedCheckpointEvidence, CheckpointError> {
    verify_witness_quorum(
        &checkpoint,
        &receipts,
        trusted_checkpoint_signers,
        trusted_witnesses,
        required,
    )?;
    Ok(VerifiedCheckpointEvidence {
        checkpoint,
        receipts,
        required_quorum: required,
    })
}

/// Compare a locally verified head with a witness-verified external checkpoint.
/// Local state behind the anchor or a same-position hash mismatch is a hard failure.
/// Create a signed checkpoint from a locally verified audit head.
/// The audit chain and terminal sequence/digest are read under one SQLite snapshot.
pub fn create_audit_checkpoint(
    signer: &dyn CheckpointSigner,
    audit: &crate::SqliteAuditSink,
    stream_id: &str,
    checkpoint_sequence: u64,
    previous_checkpoint_sha256: Option<String>,
    issued_at: u64,
) -> Result<SignedCheckpoint, CheckpointError> {
    let (event_sequence, event_head) = audit.verified_head().map_err(map_audit_error)?;
    if event_sequence == 0 || event_head == [0; 32] {
        return Err(CheckpointError::Malformed);
    }
    create_checkpoint(
        signer,
        stream_id,
        checkpoint_sequence,
        event_sequence,
        event_head,
        previous_checkpoint_sha256,
        issued_at,
    )
}

/// Verify the checkpoint signer, a distinct-identity witness quorum, and the
/// complete local audit chain before reconciling their sequence and digest.
pub fn verify_and_reconcile_head(
    audit: &crate::SqliteAuditSink,
    evidence: &VerifiedCheckpointEvidence,
) -> Result<Reconciliation, CheckpointError> {
    let checkpoint = evidence.checkpoint();
    let verified = audit
        .verified_head_and_prefix(checkpoint.payload.event_sequence)
        .map_err(map_audit_error)?;
    reconcile_head(
        verified.sequence,
        verified.digest,
        verified.prefix_digest,
        checkpoint,
    )
}

fn map_audit_error(error: crate::AuditStoreError) -> CheckpointError {
    match error {
        crate::AuditStoreError::IntegrityFailure => CheckpointError::LocalIntegrityFailure,
        crate::AuditStoreError::Unavailable => CheckpointError::LocalAuditUnavailable,
        crate::AuditStoreError::Rejected => CheckpointError::Malformed,
    }
}

fn reconcile_head(
    local_sequence: u64,
    local_hash: [u8; 32],
    local_prefix_hash: Option<[u8; 32]>,
    checkpoint: &SignedCheckpoint,
) -> Result<Reconciliation, CheckpointError> {
    let p = &checkpoint.payload;
    validate_payload(p)?;
    if local_sequence < p.event_sequence {
        return Err(CheckpointError::LocalBehindAnchor);
    }
    if local_sequence == p.event_sequence {
        if hex(&local_hash) != p.event_head_sha256 {
            return Err(CheckpointError::ForkDetected);
        }
        return Ok(Reconciliation::Exact);
    }
    let anchored_prefix = local_prefix_hash.ok_or(CheckpointError::LocalBehindAnchor)?;
    if hex(&anchored_prefix) != p.event_head_sha256 {
        return Err(CheckpointError::ForkDetected);
    }
    Ok(Reconciliation::LocalAheadUnanchored)
}

fn validate_payload(p: &CheckpointPayload) -> Result<(), CheckpointError> {
    if p.protocol != "iroka.g11.audit-checkpoint"
        || p.version != VERSION
        || p.algorithm != ALGORITHM
    {
        return Err(CheckpointError::UnsupportedVersion);
    }
    if p.stream_id.trim().is_empty()
        || p.signer_key_id.trim().is_empty()
        || p.checkpoint_sequence == 0
        || p.event_sequence == 0
        || p.issued_at == 0
        || p.event_head_sha256.len() != 64
        || !p.event_head_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || p.previous_checkpoint_sha256
            .as_ref()
            .is_some_and(|v| v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(CheckpointError::Malformed);
    }
    Ok(())
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, CheckpointError> {
    let v = serde_json::to_value(value).map_err(|_| CheckpointError::Malformed)?;
    crate::canonical_json(&v).map_err(|_| CheckpointError::Malformed)
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(H[(b >> 4) as usize] as char);
        out.push(H[(b & 15) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::Mutex;

    struct TestSigner {
        id: String,
        key: SigningKey,
    }
    impl CheckpointSigner for TestSigner {
        fn key_id(&self) -> &str {
            &self.id
        }
        fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, CheckpointError> {
            Ok(self.key.sign(bytes).to_bytes().to_vec())
        }
    }

    struct TestWitness {
        id: String,
        key_id: String,
        key: SigningKey,
        signer_key_id: String,
        signer_key: VerifyingKey,
        accepted: Mutex<BTreeMap<String, SignedCheckpoint>>,
    }
    impl TestWitness {
        fn new(signer: &TestSigner) -> Self {
            Self {
                id: "witness:test".into(),
                key_id: "witness-key:test".into(),
                key: SigningKey::from_bytes(&[92; 32]),
                signer_key_id: signer.id.clone(),
                signer_key: signer.key.verifying_key(),
                accepted: Mutex::new(BTreeMap::new()),
            }
        }
        fn receipt(&self, cp: &SignedCheckpoint) -> Result<WitnessReceipt, CheckpointError> {
            let payload = WitnessReceiptPayload {
                protocol: "iroka.g11.witness-receipt".into(),
                version: VERSION,
                witness_id: self.id.clone(),
                witness_key_id: self.key_id.clone(),
                stream_id: cp.payload.stream_id.clone(),
                checkpoint_sequence: cp.payload.checkpoint_sequence,
                checkpoint_digest_sha256: hex(&cp.digest()?),
                previous_checkpoint_digest_sha256: cp.payload.previous_checkpoint_sha256.clone(),
                accepted_at: cp.payload.issued_at,
                algorithm: ALGORITHM.into(),
            };
            let signature = self
                .key
                .sign(&WitnessReceipt::signing_bytes(&payload)?)
                .to_bytes()
                .to_vec();
            Ok(WitnessReceipt { payload, signature })
        }
    }
    impl CheckpointWitness for TestWitness {
        fn publish(&self, cp: &SignedCheckpoint) -> Result<WitnessReceipt, CheckpointError> {
            cp.verify(&BTreeMap::from([(
                self.signer_key_id.clone(),
                self.signer_key,
            )]))?;
            let mut map = self
                .accepted
                .lock()
                .map_err(|_| CheckpointError::WitnessUnavailable)?;
            if let Some(prev) = map.get(&cp.payload.stream_id) {
                if cp.payload.checkpoint_sequence <= prev.payload.checkpoint_sequence {
                    return Err(CheckpointError::SequenceConflict);
                }
                let expected_sequence = prev
                    .payload
                    .checkpoint_sequence
                    .checked_add(1)
                    .ok_or(CheckpointError::SequenceConflict)?;
                if cp.payload.checkpoint_sequence != expected_sequence {
                    return Err(CheckpointError::SequenceGap);
                }
                if cp.payload.event_sequence <= prev.payload.event_sequence {
                    return Err(CheckpointError::SequenceRegression);
                }
                let expected_previous = hex(&prev.digest()?);
                if cp.payload.previous_checkpoint_sha256.as_deref()
                    != Some(expected_previous.as_str())
                {
                    return Err(CheckpointError::PredecessorMismatch);
                }
            } else if cp.payload.checkpoint_sequence != 1
                || cp.payload.previous_checkpoint_sha256.is_some()
            {
                return Err(CheckpointError::PredecessorMismatch);
            }
            map.insert(cp.payload.stream_id.clone(), cp.clone());
            self.receipt(cp)
        }
        fn latest(
            &self,
            stream: &str,
        ) -> Result<Option<(SignedCheckpoint, WitnessReceipt)>, CheckpointError> {
            let map = self
                .accepted
                .lock()
                .map_err(|_| CheckpointError::WitnessUnavailable)?;
            map.get(stream)
                .map(|cp| Ok((cp.clone(), self.receipt(cp)?)))
                .transpose()
        }
    }

    fn signer() -> TestSigner {
        TestSigner {
            id: "checkpoint:test".into(),
            key: SigningKey::from_bytes(&[31; 32]),
        }
    }
    fn trust(id: &str, key: &SigningKey) -> BTreeMap<String, VerifyingKey> {
        BTreeMap::from([(id.into(), key.verifying_key())])
    }

    fn audit_with_events(ids: &[&str]) -> crate::SqliteAuditSink {
        let audit = crate::SqliteAuditSink::open_in_memory().unwrap();
        for (index, id) in ids.iter().enumerate() {
            audit
                .append_event(&crate::AuditEvent::new(
                    *id,
                    "trace:checkpoint-test",
                    "principal:checkpoint-test",
                    "audit.checkpoint",
                    "audit-stream:alpha",
                    "policy:test",
                    crate::DecisionCode::Allow,
                    1_900 + index as u64,
                ))
                .unwrap();
        }
        audit
    }

    #[test]
    fn signed_checkpoint_and_witness_quorum_reconcile_verified_audit_head() {
        let s = signer();
        let w = TestWitness::new(&s);
        let audit = audit_with_events(&["event:one"]);
        let cp = create_audit_checkpoint(&s, &audit, "audit-stream:alpha", 1, None, 2_000).unwrap();
        let receipt = w.publish(&cp).unwrap();
        let evidence = verify_checkpoint_evidence(
            cp.clone(),
            vec![receipt],
            &trust(&s.id, &s.key),
            &trust(&w.key_id, &w.key),
            1,
        )
        .unwrap();
        audit.persist_checkpoint_evidence(&evidence, 2_001).unwrap();
        assert_eq!(
            audit.persist_checkpoint_evidence(&evidence, 2_002),
            Ok(())
        );
        let (checkpoint_bytes, receipt_bytes) = audit
            .latest_checkpoint_evidence_bytes("audit-stream:alpha")
            .unwrap()
            .unwrap();
        let recovered_checkpoint: SignedCheckpoint =
            serde_json::from_slice(&checkpoint_bytes).unwrap();
        let recovered_receipts: Vec<WitnessReceipt> =
            serde_json::from_slice(&receipt_bytes).unwrap();
        let recovered = verify_checkpoint_evidence(
            recovered_checkpoint,
            recovered_receipts,
            &trust(&s.id, &s.key),
            &trust(&w.key_id, &w.key),
            1,
        )
        .unwrap();
        assert_eq!(
            verify_and_reconcile_head(&audit, &recovered),
            Ok(Reconciliation::Exact)
        );
        let forked_store = audit_with_events(&["event:forked"]);
        assert_eq!(
            forked_store.persist_checkpoint_evidence(&evidence, 2_003),
            Err(crate::AuditStoreError::IntegrityFailure)
        );

        let local_ahead = audit_with_events(&["event:one", "event:two"]);
        assert_eq!(
            verify_and_reconcile_head(&local_ahead, &evidence),
            Ok(Reconciliation::LocalAheadUnanchored)
        );

        let local_behind = audit_with_events(&[]);
        assert_eq!(
            verify_and_reconcile_head(&local_behind, &evidence),
            Err(CheckpointError::LocalBehindAnchor)
        );

        let forked = audit_with_events(&["event:forked", "event:forked-tail"]);
        assert_eq!(
            verify_and_reconcile_head(&forked, &evidence),
            Err(CheckpointError::ForkDetected)
        );
    }

    #[test]
    fn rejects_tampered_checkpoint_and_receipt() {
        let s = signer();
        let w = TestWitness::new(&s);
        let cp = create_checkpoint(&s, "audit-stream:alpha", 1, 7, [8; 32], None, 1_900).unwrap();
        let mut bad = cp.clone();
        bad.payload.event_sequence = 8;
        assert_eq!(
            bad.verify(&trust(&s.id, &s.key)),
            Err(CheckpointError::InvalidSignature)
        );
        let receipt = w.publish(&cp).unwrap();
        let mut changed = receipt.clone();
        changed.payload.checkpoint_sequence = 2;
        assert_eq!(
            changed.verify(&cp, &trust(&s.id, &s.key), &trust(&w.key_id, &w.key)),
            Err(CheckpointError::ReceiptMismatch)
        );
    }

    #[test]
    fn witness_rejects_replay_gap_and_wrong_predecessor() {
        let s = signer();
        let w = TestWitness::new(&s);
        let one = create_checkpoint(&s, "audit-stream:alpha", 1, 7, [8; 32], None, 1_900).unwrap();
        w.publish(&one).unwrap();
        assert_eq!(w.publish(&one), Err(CheckpointError::SequenceConflict));
        let gap = create_checkpoint(
            &s,
            "audit-stream:alpha",
            3,
            9,
            [9; 32],
            Some(hex(&one.digest().unwrap())),
            1_901,
        )
        .unwrap();
        assert_eq!(w.publish(&gap), Err(CheckpointError::SequenceGap));
        let wrong = create_checkpoint(
            &s,
            "audit-stream:alpha",
            2,
            8,
            [9; 32],
            Some("00".repeat(32)),
            1_901,
        )
        .unwrap();
        assert_eq!(w.publish(&wrong), Err(CheckpointError::PredecessorMismatch));

        let regressed = create_checkpoint(
            &s,
            "audit-stream:alpha",
            2,
            7,
            [9; 32],
            Some(hex(&one.digest().unwrap())),
            1_901,
        )
        .unwrap();
        assert_eq!(
            w.publish(&regressed),
            Err(CheckpointError::SequenceRegression)
        );
    }

    #[test]
    fn quorum_requires_distinct_witnesses_and_threshold() {
        let s = signer();
        let w = TestWitness::new(&s);
        let cp = create_checkpoint(&s, "audit-stream:quorum", 1, 1, [4; 32], None, 1_900).unwrap();
        let receipt = w.publish(&cp).unwrap();
        let roots = trust(&w.key_id, &w.key);
        assert_eq!(
            verify_witness_quorum(
                &cp,
                std::slice::from_ref(&receipt),
                &trust(&s.id, &s.key),
                &roots,
                1
            ),
            Ok(1)
        );
        assert_eq!(
            verify_witness_quorum(
                &cp,
                std::slice::from_ref(&receipt),
                &trust(&s.id, &s.key),
                &roots,
                2
            ),
            Err(CheckpointError::QuorumNotMet)
        );
        assert_eq!(
            verify_witness_quorum(
                &cp,
                &[receipt.clone(), receipt],
                &trust(&s.id, &s.key),
                &roots,
                2
            ),
            Err(CheckpointError::DuplicateWitness)
        );
    }

    #[test]
    fn quorum_rejects_reusing_one_witness_key_under_multiple_identities() {
        let s = signer();
        let w = TestWitness::new(&s);
        let checkpoint = create_checkpoint(
            &s,
            "audit-stream:key-uniqueness",
            1,
            1,
            [5; 32],
            None,
            1_900,
        )
        .unwrap();
        let first = w.publish(&checkpoint).unwrap();
        let mut alias = first.clone();
        alias.payload.witness_id = "witness:aliased-identity".into();
        alias.signature = w
            .key
            .sign(&WitnessReceipt::signing_bytes(&alias.payload).unwrap())
            .to_bytes()
            .to_vec();

        assert_eq!(
            verify_witness_quorum(
                &checkpoint,
                &[first, alias],
                &trust(&s.id, &s.key),
                &trust(&w.key_id, &w.key),
                2,
            ),
            Err(CheckpointError::DuplicateWitness)
        );
    }

    #[test]
    fn witness_keeps_streams_separate_and_receipt_is_bound_to_digest() {
        let s = signer();
        let w = TestWitness::new(&s);
        let a = create_checkpoint(&s, "audit-stream:a", 1, 1, [1; 32], None, 1_900).unwrap();
        let b = create_checkpoint(&s, "audit-stream:b", 1, 1, [2; 32], None, 1_900).unwrap();
        let ra = w.publish(&a).unwrap();
        w.publish(&b).unwrap();
        assert_eq!(
            ra.verify(&b, &trust(&s.id, &s.key), &trust(&w.key_id, &w.key),),
            Err(CheckpointError::ReceiptMismatch)
        );
        assert_eq!(w.latest("audit-stream:a").unwrap().unwrap().0, a);
    }
}
