//! A3 G01 signed identity succession lineage evaluator.
//! Supports an ordered single-parent chain. Merge lineage is deliberately excluded.

use crate::{canonical_json, Ed25519CredentialVerifier, RevocationChecker};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_DEPTH: usize = 128;
const MAX_PROOF_TTL: u64 = 86_400;
const CLOCK_SKEW: u64 = 30;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IdentityRelationship {
    Root,
    Derived,
    Successor,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityLineageNode {
    pub subject_id: String,
    pub predecessor_id: Option<String>,
    pub relationship: IdentityRelationship,
    pub epoch: u64,
    pub issuer_id: String,
    pub key_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    pub provenance_digest: String,
    pub version_evidence_digest: String,
    pub proof_digest: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IdentityLineageInput {
    pub subject_id: String,
    pub predecessor_id: Option<String>,
    pub relationship: IdentityRelationship,
    pub proof_digest: String,
    pub epoch: u64,
    pub lineage_chain: Vec<IdentityLineageNode>,
    pub provenance: BTreeMap<String, Value>,
    pub version_bound_evidence: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityLineagePolicy {
    current_epoch: u64,
}
impl IdentityLineagePolicy {
    pub fn new(current_epoch: u64) -> Self {
        Self { current_epoch }
    }
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityLineageEvidence {
    pub provenance: BTreeMap<String, Value>,
    pub version_bound_evidence: BTreeMap<String, Value>,
    pub proofs_verified: bool,
    pub graph_acyclic: bool,
    pub parent_links_valid: bool,
    pub epoch_monotonic: bool,
    pub proof_count: u64,
    pub verified_issuers: Vec<String>,
    pub decision_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityLineageOutput {
    pub subject_id: String,
    pub lineage_valid: bool,
    pub chain_digest: Option<String>,
    pub verified_depth: u64,
    pub evidence: IdentityLineageEvidence,
    pub version_bound_evidence: BTreeMap<String, Value>,
}

#[derive(Serialize)]
struct ProofPayload<'a> {
    subject_id: &'a str,
    predecessor_id: &'a Option<String>,
    relationship: IdentityRelationship,
    epoch: u64,
    issuer_id: &'a str,
    key_id: &'a str,
    issued_at: u64,
    expires_at: u64,
    nonce: &'a str,
    provenance_digest: &'a str,
    version_evidence_digest: &'a str,
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn map_digest(map: &BTreeMap<String, Value>) -> Option<String> {
    let value = serde_json::to_value(map).ok()?;
    canonical_json(&value).ok().map(|bytes| digest(&bytes))
}
fn proof_bytes(node: &IdentityLineageNode) -> Option<Vec<u8>> {
    let payload = ProofPayload {
        subject_id: &node.subject_id,
        predecessor_id: &node.predecessor_id,
        relationship: node.relationship,
        epoch: node.epoch,
        issuer_id: &node.issuer_id,
        key_id: &node.key_id,
        issued_at: node.issued_at,
        expires_at: node.expires_at,
        nonce: &node.nonce,
        provenance_digest: &node.provenance_digest,
        version_evidence_digest: &node.version_evidence_digest,
    };
    canonical_json(&serde_json::to_value(payload).ok()?).ok()
}
fn deny(input: &IdentityLineageInput, reason: &str) -> IdentityLineageOutput {
    IdentityLineageOutput {
        subject_id: input.subject_id.clone(),
        lineage_valid: false,
        chain_digest: None,
        verified_depth: 0,
        evidence: IdentityLineageEvidence {
            provenance: input.provenance.clone(),
            version_bound_evidence: input.version_bound_evidence.clone(),
            proofs_verified: false,
            graph_acyclic: false,
            parent_links_valid: false,
            epoch_monotonic: false,
            proof_count: 0,
            verified_issuers: Vec::new(),
            decision_reason: reason.into(),
        },
        version_bound_evidence: input.version_bound_evidence.clone(),
    }
}

/// Verify a root-to-tip chain using detached Ed25519 proofs, a trusted snapshot,
/// and the injected live revocation checker. This function never mutates trust state.
pub fn evaluate_identity_lineage<R: RevocationChecker>(
    input: &IdentityLineageInput,
    policy: &IdentityLineagePolicy,
    verifier: &Ed25519CredentialVerifier<R>,
    now: u64,
) -> IdentityLineageOutput {
    let chain = &input.lineage_chain;
    if input.subject_id.trim().is_empty()
        || input.provenance.is_empty()
        || input.version_bound_evidence.is_empty()
        || chain.is_empty()
        || chain.len() > MAX_DEPTH
        || input.epoch > policy.current_epoch
        || !valid_digest(&input.proof_digest)
    {
        return deny(input, "invalid_input_or_lineage_depth");
    }
    let Some(provenance_digest) = map_digest(&input.provenance) else {
        return deny(input, "provenance_canonicalization_failed");
    };
    let Some(version_digest) = map_digest(&input.version_bound_evidence) else {
        return deny(input, "version_evidence_canonicalization_failed");
    };
    let mut subjects = BTreeSet::new();
    let mut nonces = BTreeSet::new();
    let mut issuers = BTreeSet::new();
    let mut proof_digests = Vec::with_capacity(chain.len());

    for (index, node) in chain.iter().enumerate() {
        if node.subject_id.trim().is_empty()
            || node.issuer_id.trim().is_empty()
            || node.key_id.trim().is_empty()
            || node.nonce.len() < 16
            || !subjects.insert(node.subject_id.as_str())
            || !nonces.insert(node.nonce.as_str())
            || node.epoch > policy.current_epoch
            || !valid_digest(&node.proof_digest)
            || !valid_digest(&node.provenance_digest)
            || !valid_digest(&node.version_evidence_digest)
            || node.signature.len() != 64
        {
            return deny(input, "malformed_or_duplicate_lineage_node");
        }
        if index == 0 {
            if node.relationship != IdentityRelationship::Root || node.predecessor_id.is_some() {
                return deny(input, "lineage_root_must_have_no_predecessor");
            }
        } else {
            let parent = &chain[index - 1];
            if node.relationship == IdentityRelationship::Root
                || node.predecessor_id.as_deref() != Some(parent.subject_id.as_str())
                || node.epoch <= parent.epoch
            {
                return deny(input, "parent_link_or_epoch_order_invalid");
            }
        }
        if node.issued_at > now.saturating_add(CLOCK_SKEW)
            || node.expires_at <= now.saturating_sub(CLOCK_SKEW)
            || node.expires_at <= node.issued_at
            || node.expires_at - node.issued_at > MAX_PROOF_TTL
        {
            return deny(input, "lineage_proof_expired_or_malformed");
        }
        if index + 1 == chain.len()
            && (node.provenance_digest != provenance_digest
                || node.version_evidence_digest != version_digest)
        {
            return deny(input, "tip_evidence_commitment_mismatch");
        }
        let Some(bytes) = proof_bytes(node) else {
            return deny(input, "lineage_proof_canonicalization_failed");
        };
        if digest(&bytes) != node.proof_digest {
            return deny(input, "lineage_proof_digest_mismatch");
        }
        if verifier
            .verify_detached_payload(&node.issuer_id, &node.key_id, &bytes, &node.signature, now)
            .is_err()
        {
            return deny(input, "lineage_proof_signature_or_trust_invalid");
        }
        issuers.insert(node.issuer_id.clone());
        proof_digests.push(node.proof_digest.clone());
    }
    let Some(tip) = chain.last() else {
        return deny(input, "lineage_chain_empty");
    };
    if tip.subject_id != input.subject_id
        || tip.predecessor_id != input.predecessor_id
        || tip.relationship != input.relationship
        || tip.epoch != input.epoch
        || tip.proof_digest != input.proof_digest
    {
        return deny(input, "candidate_does_not_match_verified_lineage_tip");
    }
    let Ok(value) = serde_json::to_value(&proof_digests) else {
        return deny(input, "lineage_digest_serialization_failed");
    };
    let Ok(bytes) = canonical_json(&value) else {
        return deny(input, "lineage_digest_canonicalization_failed");
    };
    IdentityLineageOutput {
        subject_id: input.subject_id.clone(),
        lineage_valid: true,
        chain_digest: Some(digest(&bytes)),
        verified_depth: chain.len() as u64,
        evidence: IdentityLineageEvidence {
            provenance: input.provenance.clone(),
            version_bound_evidence: input.version_bound_evidence.clone(),
            proofs_verified: true,
            graph_acyclic: true,
            parent_links_valid: true,
            epoch_monotonic: true,
            proof_count: chain.len() as u64,
            verified_issuers: issuers.into_iter().collect(),
            decision_reason: "lineage_verified".into(),
        },
        version_bound_evidence: input.version_bound_evidence.clone(),
    }
}
