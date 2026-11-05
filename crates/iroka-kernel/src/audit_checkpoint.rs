//! Deterministic K-04 checkpoint payload and V1 anchor builder.
//! The payload uses a fixed-position CBOR array to avoid map-key ordering ambiguity.
//! No V1 event hash is rewritten by this module.

use sha2::{Digest, Sha256};

pub const CHECKPOINT_PROTOCOL_V1: &str = "IROKA-AUDIT-CHECKPOINT-V1";
pub const V1_CHAIN_FORMAT: &str = "IROKA:G11:AUDIT-EVENT:V1";
pub const HASH_SHA256: &str = "SHA-256";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditHead {
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub event_count: u64,
    pub head_event_hash: [u8; 32],
    pub chain_format: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointPayload {
    pub protocol: String,
    pub stream_id: String,
    pub checkpoint_number: u64,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub event_count: u64,
    pub head_event_hash: [u8; 32],
    pub previous_checkpoint_digest: [u8; 32],
    pub chain_format: String,
    pub hash_algorithm: String,
    pub created_at: u64,
    pub signing_key_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    InvalidStream,
    InvalidSequence,
    InvalidCount,
    InvalidHead,
    InvalidPrevious,
    InvalidKeyId,
}

impl CheckpointPayload {
    pub fn validate(&self) -> Result<(), CheckpointError> {
        if self.protocol != CHECKPOINT_PROTOCOL_V1 || self.stream_id.trim().is_empty() {
            return Err(CheckpointError::InvalidStream);
        }
        if self.checkpoint_number == 0 || self.first_sequence != 1
            || self.last_sequence < self.first_sequence
        {
            return Err(CheckpointError::InvalidSequence);
        }
        if self.event_count == 0 || self.event_count != self.last_sequence - self.first_sequence + 1 {
            return Err(CheckpointError::InvalidCount);
        }
        if self.head_event_hash == [0; 32] || self.chain_format != V1_CHAIN_FORMAT
            || self.hash_algorithm != HASH_SHA256
        {
            return Err(CheckpointError::InvalidHead);
        }
        if self.checkpoint_number == 1 && self.previous_checkpoint_digest != [0; 32] {
            return Err(CheckpointError::InvalidPrevious);
        }
        if self.signing_key_id.trim().is_empty() {
            return Err(CheckpointError::InvalidKeyId);
        }
        Ok(())
    }

    /// Canonical CBOR fixed-length array, in the exact field order documented above.
    pub fn canonical_cbor(&self) -> Result<Vec<u8>, CheckpointError> {
        self.validate()?;
        let mut out = Vec::with_capacity(256);
        cbor_array(&mut out, 12);
        cbor_text(&mut out, &self.protocol);
        cbor_text(&mut out, &self.stream_id);
        cbor_uint(&mut out, self.checkpoint_number);
        cbor_uint(&mut out, self.first_sequence);
        cbor_uint(&mut out, self.last_sequence);
        cbor_uint(&mut out, self.event_count);
        cbor_bytes(&mut out, &self.head_event_hash);
        cbor_bytes(&mut out, &self.previous_checkpoint_digest);
        cbor_text(&mut out, &self.chain_format);
        cbor_text(&mut out, &self.hash_algorithm);
        cbor_uint(&mut out, self.created_at);
        cbor_text(&mut out, &self.signing_key_id);
        Ok(out)
    }

    pub fn digest(&self) -> Result<[u8; 32], CheckpointError> {
        let bytes = self.canonical_cbor()?;
        let mut h = Sha256::new();
        h.update(b"IROKA:G11:AUDIT-CHECKPOINT-DIGEST:V1\0");
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(bytes);
        Ok(h.finalize().into())
    }
}

pub struct CheckpointBuilder {
    stream_id: String,
    signing_key_id: String,
}

impl CheckpointBuilder {
    pub fn new(stream_id: impl Into<String>, signing_key_id: impl Into<String>) -> Self {
        Self { stream_id: stream_id.into(), signing_key_id: signing_key_id.into() }
    }

    /// Builds the first checkpoint that anchors an existing V1 chain without rewriting it.
    pub fn initial_v1_anchor(
        &self,
        head: &AuditHead,
        created_at: u64,
    ) -> Result<CheckpointPayload, CheckpointError> {
        if head.chain_format != V1_CHAIN_FORMAT || head.last_sequence == 0
            || head.first_sequence == 0 || head.event_count == 0
            || head.last_sequence - head.first_sequence + 1 != head.event_count
        {
            return Err(CheckpointError::InvalidHead);
        }
        let payload = CheckpointPayload {
            protocol: CHECKPOINT_PROTOCOL_V1.into(),
            stream_id: self.stream_id.clone(),
            checkpoint_number: 1,
            first_sequence: head.first_sequence,
            last_sequence: head.last_sequence,
            event_count: head.event_count,
            head_event_hash: head.head_event_hash,
            previous_checkpoint_digest: [0; 32],
            chain_format: head.chain_format.clone(),
            hash_algorithm: HASH_SHA256.into(),
            created_at,
            signing_key_id: self.signing_key_id.clone(),
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn next(
        &self,
        head: &AuditHead,
        previous: &CheckpointPayload,
        created_at: u64,
    ) -> Result<CheckpointPayload, CheckpointError> {
        previous.validate()?;
        if previous.stream_id != self.stream_id || head.last_sequence <= previous.last_sequence
            || head.first_sequence != previous.first_sequence
            || head.event_count != head.last_sequence - head.first_sequence + 1
            || head.chain_format != previous.chain_format
        {
            return Err(CheckpointError::InvalidSequence);
        }
        let payload = CheckpointPayload {
            protocol: CHECKPOINT_PROTOCOL_V1.into(),
            stream_id: self.stream_id.clone(),
            checkpoint_number: previous.checkpoint_number + 1,
            first_sequence: previous.first_sequence,
            last_sequence: head.last_sequence,
            event_count: head.event_count,
            head_event_hash: head.head_event_hash,
            previous_checkpoint_digest: previous.digest()?,
            chain_format: head.chain_format.clone(),
            hash_algorithm: HASH_SHA256.into(),
            created_at,
            signing_key_id: self.signing_key_id.clone(),
        };
        payload.validate()?;
        Ok(payload)
    }
}

fn cbor_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    match value {
        0..=23 => out.push(prefix | value as u8),
        24..=0xff => { out.push(prefix | 24); out.push(value as u8); }
        0x100..=0xffff => { out.push(prefix | 25); out.extend_from_slice(&(value as u16).to_be_bytes()); }
        0x1_0000..=0xffff_ffff => { out.push(prefix | 26); out.extend_from_slice(&(value as u32).to_be_bytes()); }
        _ => { out.push(prefix | 27); out.extend_from_slice(&value.to_be_bytes()); }
    }
}
fn cbor_array(out: &mut Vec<u8>, n: u64) { cbor_head(out, 4, n); }
fn cbor_uint(out: &mut Vec<u8>, n: u64) { cbor_head(out, 0, n); }
fn cbor_text(out: &mut Vec<u8>, value: &str) {
    cbor_head(out, 3, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}
fn cbor_bytes(out: &mut Vec<u8>, value: &[u8]) {
    cbor_head(out, 2, value.len() as u64);
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(n: u64, hash: u8) -> AuditHead {
        AuditHead { first_sequence: 1, last_sequence: n, event_count: n,
            head_event_hash: [hash; 32], chain_format: V1_CHAIN_FORMAT.into() }
    }

    #[test]
    fn initial_anchor_commits_v1_head_without_rewriting_history() {
        let b = CheckpointBuilder::new("stream:pilot", "checkpoint-key-1");
        let cp = b.initial_v1_anchor(&head(3, 7), 100).unwrap();
        assert_eq!(cp.checkpoint_number, 1);
        assert_eq!(cp.last_sequence, 3);
        assert_eq!(cp.previous_checkpoint_digest, [0; 32]);
        assert_eq!(cp.canonical_cbor().unwrap()[0], 0x8c);
    }

    #[test]
    fn next_checkpoint_is_linked_and_strictly_advances() {
        let b = CheckpointBuilder::new("stream:pilot", "checkpoint-key-1");
        let first = b.initial_v1_anchor(&head(3, 7), 100).unwrap();
        let next = b.next(&head(5, 8), &first, 110).unwrap();
        assert_eq!(next.checkpoint_number, 2);
        assert_eq!(next.previous_checkpoint_digest, first.digest().unwrap());
        assert!(b.next(&head(3, 7), &first, 120).is_err());
    }
}
