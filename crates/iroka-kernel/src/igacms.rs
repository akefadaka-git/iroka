//! IGACMS v1.0 validator, fingerprint, attestation, genesis and evolution contracts.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
const ATTESTATION_DOMAIN: &str = "IROKA-IGACMS-ATTESTATION-V1";

const EMBEDDED: &[u8] = include_bytes!("../igacms/genome-v1.0.0.json");
const DOMAINS: [&str; 8] = [
    "identity",
    "authority",
    "evidence",
    "assurance",
    "reasoning",
    "security",
    "execution",
    "evolution",
];
const MARKER_IDS: [&str; 27] = [
    "IDN-001", "IDN-002", "IDN-003", "IDN-004", "INT-001", "INT-002", "INT-003", "PRV-001",
    "PRV-002", "EVD-001", "EVD-002", "EVD-003", "AUT-001", "AUT-002", "AZN-001", "AZN-002",
    "SEC-001", "SEC-002", "ASN-001", "ASN-002", "LFC-001", "LFC-002", "EVO-001", "EVO-002",
    "EVO-003", "CNF-001", "CNF-002",
];
const CHROMOSOMES: [&str; 12] = [
    "G01", "G02", "G03", "G04", "G05", "G06", "G07", "G08", "G09", "G10", "G11", "G12",
];
const EXPECTED_GENOME_SHA256: &str =
    "a89e2b5bdb3519201268cf087b84df676e34f932c33c888de00794362864351c";
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IgacmsError {
    Malformed,
    Identity,
    MissingDomain(String),
    Chromosome,
    Gene,
    Marker,
    DuplicateId(String),
    Dependency,
    DependencyCycle,
    UnknownRoot,
    RevokedRoot,
    RootExpired,
    Signature,
    Genesis,
    Epoch,
    MutationDenied,
    HistoricalEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    pub digest_hex: String,
    pub canonical_bytes: Vec<u8>,
    pub algorithm: &'static str,
    pub canonicalization: &'static str,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedGenome {
    pub value: Value,
    pub fingerprint: Fingerprint,
}

struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a JSON value with unique object keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(Number::from(v))))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(Number::from(v))))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                Number::from_f64(v)
                    .map(|n| UniqueValue(Value::Number(n)))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(v.to_owned())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(v)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(v) = seq.next_element::<UniqueValue>()? {
                    values.push(v.0);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some((key, value)) = access.next_entry::<String, UniqueValue>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate JSON object key"));
                    }
                    values.insert(key, value.0);
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}
pub fn canonical_json(value: &Value) -> Result<Vec<u8>, IgacmsError> {
    serde_jcs::to_vec(value).map_err(|_| IgacmsError::Malformed)
}
fn parse_unique(bytes: &[u8]) -> Result<Value, IgacmsError> {
    let mut d = serde_json::Deserializer::from_slice(bytes);
    let v = UniqueValue::deserialize(&mut d)
        .map_err(|_| IgacmsError::Malformed)?
        .0;
    d.end().map_err(|_| IgacmsError::Malformed)?;
    Ok(v)
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, IgacmsError> {
    v.get(k)
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or(IgacmsError::Malformed)
}
fn unique<'a>(a: &'a [Value], k: &str) -> Result<BTreeSet<&'a str>, IgacmsError> {
    let mut s = BTreeSet::new();
    for v in a {
        let id = text(v, k)?;
        if !s.insert(id) {
            return Err(IgacmsError::DuplicateId(id.into()));
        }
    }
    Ok(s)
}
fn graph_is_acyclic(g: &[(String, Vec<String>)]) -> Result<(), IgacmsError> {
    fn visit(
        n: &str,
        m: &BTreeMap<String, Vec<String>>,
        active: &mut BTreeSet<String>,
        done: &mut BTreeSet<String>,
    ) -> Result<(), IgacmsError> {
        if done.contains(n) {
            return Ok(());
        }
        if !active.insert(n.into()) {
            return Err(IgacmsError::DependencyCycle);
        }
        for d in m.get(n).ok_or(IgacmsError::Dependency)? {
            if !m.contains_key(d) {
                return Err(IgacmsError::Dependency);
            }
            visit(d, m, active, done)?
        }
        active.remove(n);
        done.insert(n.into());
        Ok(())
    }
    let m: BTreeMap<_, _> = g.iter().cloned().collect();
    let (mut a, mut d) = (BTreeSet::new(), BTreeSet::new());
    for n in m.keys() {
        visit(n, &m, &mut a, &mut d)?
    }
    Ok(())
}
pub fn validate_genome(bytes: &[u8]) -> Result<ValidatedGenome, IgacmsError> {
    let v = parse_unique(bytes)?;
    if text(&v, "specification_id")? != "IGACMS"
        || text(&v, "specification_version")? != "1.0.0"
        || text(v.get("dna").ok_or(IgacmsError::Identity)?, "id")? != "iroka.dna"
        || text(v.get("dna").ok_or(IgacmsError::Identity)?, "kind")?
            != "IROKA_CONSTITUTIONAL_DNA_CONTRACT"
        || text(
            v.get("dna").ok_or(IgacmsError::Identity)?,
            "contract_version",
        )? != "1.0.0"
        || text(v.get("genome").ok_or(IgacmsError::Identity)?, "id")? != "IROKA_ZERO_GENOME"
        || text(v.get("genome").ok_or(IgacmsError::Identity)?, "version")? != "1.0.0"
        || v["genome"]["epoch"].as_u64() != Some(0)
    {
        return Err(IgacmsError::Identity);
    }
    let domains = v["historical_domains"]
        .as_array()
        .ok_or(IgacmsError::Malformed)?;
    let domain_set: BTreeSet<&str> = domains.iter().filter_map(Value::as_str).collect();
    if domain_set.len() != domains.len()
        || domain_set
            .iter()
            .any(|domain| !DOMAINS.iter().any(|known| known == domain))
    {
        return Err(IgacmsError::Malformed);
    }
    for required_domain in DOMAINS {
        if !domain_set.contains(required_domain) {
            return Err(IgacmsError::MissingDomain(required_domain.to_owned()));
        }
    }
    if domains.len() != DOMAINS.len() {
        return Err(IgacmsError::Malformed);
    }
    let c = v["chromosomes"].as_array().ok_or(IgacmsError::Chromosome)?;
    if c.len() != 12 {
        return Err(IgacmsError::Chromosome);
    }
    let ids = unique(c, "id")?;
    for id in CHROMOSOMES {
        if !ids.contains(id) {
            return Err(IgacmsError::Chromosome);
        }
    }
    let genes = v["genes"].as_array().ok_or(IgacmsError::Gene)?;
    if genes.len() != 36 {
        return Err(IgacmsError::Gene);
    }
    unique(genes, "id")?;
    for g in genes {
        for k in [
            "chromosome_id",
            "version",
            "purpose",
            "input_schema",
            "output_schema",
            "failure_semantics",
            "compatibility_policy",
            "owner",
            "review_state",
        ] {
            text(g, k)?;
        }
        if !ids.contains(text(g, "chromosome_id")?) {
            return Err(IgacmsError::Gene);
        }
    }
    for x in c {
        let gs = x["core_genes"].as_array().ok_or(IgacmsError::Gene)?;
        if gs.len() != 3 {
            return Err(IgacmsError::Gene);
        }
        for name in gs {
            let gene_name = name.as_str().ok_or(IgacmsError::Gene)?;
            let expected = format!("{}.{}", text(x, "id")?.to_lowercase(), gene_name);
            if !v["genes"]
                .as_array()
                .ok_or(IgacmsError::Gene)?
                .iter()
                .any(|g| {
                    g["id"].as_str() == Some(expected.as_str())
                        && g["chromosome_id"].as_str() == text(x, "id").ok()
                })
            {
                return Err(IgacmsError::Gene);
            }
        }
    }
    let p = v["principles"].as_array().ok_or(IgacmsError::Malformed)?;
    let i = v["invariants"].as_array().ok_or(IgacmsError::Malformed)?;
    if p.len() != 14 || i.len() != 14 {
        return Err(IgacmsError::Identity);
    }
    unique(p, "id")?;
    unique(i, "id")?;
    // Enforce exact A2 catalogue semantics, not merely counts and unique IDs.
    let approved = parse_unique(EMBEDDED)?;
    if v["principles"] != approved["principles"] || v["invariants"] != approved["invariants"] {
        return Err(IgacmsError::Identity);
    }
    let m = v["markers"].as_array().ok_or(IgacmsError::Marker)?;
    if m.len() != MARKER_IDS.len() {
        return Err(IgacmsError::Marker);
    }
    let marker_ids = unique(m, "id")?;
    if MARKER_IDS.iter().any(|id| !marker_ids.contains(id)) {
        return Err(IgacmsError::Marker);
    }
    let mut edges = Vec::new();
    for n in v["dependency_graph"]
        .as_array()
        .ok_or(IgacmsError::Dependency)?
    {
        let id = text(n, "node")?.to_owned();
        let ds = n["depends_on"]
            .as_array()
            .ok_or(IgacmsError::Dependency)?
            .iter()
            .map(|x| x.as_str().map(str::to_owned).ok_or(IgacmsError::Dependency))
            .collect::<Result<Vec<_>, _>>()?;
        edges.push((id, ds));
    }
    if edges.len() != 12
        || edges
            .iter()
            .map(|x| x.0.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            != 12
        || CHROMOSOMES
            .iter()
            .any(|id| !edges.iter().any(|x| x.0 == *id))
    {
        return Err(IgacmsError::Dependency);
    }
    let graph: BTreeMap<&str, &Vec<String>> = edges
        .iter()
        .map(|(node, deps)| (node.as_str(), deps))
        .collect();
    for (node, deps) in &edges {
        let unique_deps: BTreeSet<&str> = deps.iter().map(String::as_str).collect();
        if unique_deps.len() != deps.len() {
            return Err(IgacmsError::Dependency);
        }
        let chromosome = c
            .iter()
            .find(|item| item["id"].as_str() == Some(node.as_str()))
            .ok_or(IgacmsError::Dependency)?;
        let declared = chromosome["dependencies"]
            .as_array()
            .ok_or(IgacmsError::Dependency)?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(IgacmsError::Dependency)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if &declared != deps
            || deps
                .iter()
                .any(|dependency| !graph.contains_key(dependency.as_str()))
        {
            return Err(IgacmsError::Dependency);
        }
    }
    graph_is_acyclic(&edges)?;
    let bytes = canonical_json(&v)?;
    let digest = Sha256::digest(&bytes);
    Ok(ValidatedGenome {
        value: v,
        fingerprint: Fingerprint {
            digest_hex: format!("{:x}", digest),
            canonical_bytes: bytes,
            algorithm: "SHA-256",
            canonicalization: "RFC8785-JCS",
        },
    })
}
pub fn validate_embedded_baseline() -> Result<Fingerprint, IgacmsError> {
    let fp = validate_genome(EMBEDDED)?.fingerprint;
    if fp.digest_hex != EXPECTED_GENOME_SHA256 {
        return Err(IgacmsError::Identity);
    }
    Ok(fp)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkerAssertion {
    pub assertion_id: String,
    pub marker_id: String,
    pub subject_id: String,
    pub genome_version: String,
    pub chromosome_version: String,
    pub asserted_state: String,
    pub issuer: String,
    pub issued_at: u64,
    pub valid_from: u64,
    pub valid_until: Option<u64>,
    pub evidence_refs: Vec<String>,
    pub verifier: String,
    pub verification_method: String,
    pub signature_ref: Option<String>,
    pub supersedes_ref: Option<String>,
    pub status: String,
}
fn validate_marker_assertion_inner(
    a: &MarkerAssertion,
    allow_attested: bool,
) -> Result<(), IgacmsError> {
    if !MARKER_IDS.contains(&a.marker_id.as_str())
        || [
            &a.assertion_id,
            &a.subject_id,
            &a.genome_version,
            &a.chromosome_version,
            &a.issuer,
        ]
        .iter()
        .any(|s| s.trim().is_empty())
        || a.issued_at < a.valid_from
        || a.valid_until
            .is_some_and(|x| x <= a.valid_from || a.issued_at >= x)
        || a.evidence_refs.iter().any(|r| r.trim().is_empty())
        || a.evidence_refs.iter().collect::<BTreeSet<_>>().len() != a.evidence_refs.len()
    {
        return Err(IgacmsError::Marker);
    }
    if (a.asserted_state == "VERIFIED" || a.asserted_state == "ATTESTED")
        && (a.evidence_refs.is_empty()
            || a.verifier.trim().is_empty()
            || a.verification_method.trim().is_empty())
    {
        return Err(IgacmsError::Marker);
    }
    if a.asserted_state == "ATTESTED"
        && (!allow_attested || a.signature_ref.as_deref().unwrap_or("").trim().is_empty())
    {
        return Err(IgacmsError::Marker);
    }
    if a.asserted_state != "ATTESTED" && a.signature_ref.is_some() {
        return Err(IgacmsError::Marker);
    }
    if ![
        "DEFINED",
        "OBSERVED",
        "VERIFIED",
        "ATTESTED",
        "FAILED",
        "REVOKED",
        "UNKNOWN",
        "NOT_APPLICABLE",
    ]
    .contains(&a.asserted_state.as_str())
        || !["PASS", "FAIL", "INDETERMINATE", "NOT_RUN", "NOT_APPLICABLE"]
            .contains(&a.status.as_str())
    {
        return Err(IgacmsError::Marker);
    }
    if (matches!(
        a.asserted_state.as_str(),
        "UNKNOWN" | "NOT_APPLICABLE" | "REVOKED"
    ) && a.status == "PASS")
        || (a.asserted_state == "FAILED" && a.status != "FAIL")
    {
        return Err(IgacmsError::Marker);
    }
    Ok(())
}

/// Structural validation cannot confer ATTESTED status; use the cryptographic verifier.
pub fn validate_marker_assertion(a: &MarkerAssertion) -> Result<(), IgacmsError> {
    validate_marker_assertion_inner(a, false)
}

fn marker_assertion_digest(a: &MarkerAssertion) -> Result<String, IgacmsError> {
    // Exclude signature_ref to avoid a self-referential payload digest.
    let payload = serde_json::json!({
        "assertion_id": a.assertion_id, "marker_id": a.marker_id, "subject_id": a.subject_id,
        "genome_version": a.genome_version, "chromosome_version": a.chromosome_version,
        "asserted_state": a.asserted_state, "issuer": a.issuer, "issued_at": a.issued_at,
        "valid_from": a.valid_from, "valid_until": a.valid_until, "evidence_refs": a.evidence_refs,
        "verifier": a.verifier, "verification_method": a.verification_method,
        "supersedes_ref": a.supersedes_ref, "status": a.status
    });
    Ok(format!("{:x}", Sha256::digest(canonical_json(&payload)?)))
}

pub fn sign_marker_assertion(
    assertion: &mut MarkerAssertion,
    key_id: &str,
    key: &SigningKey,
) -> Result<Attestation, IgacmsError> {
    if assertion.asserted_state != "ATTESTED" || key_id.trim().is_empty() {
        return Err(IgacmsError::Marker);
    }
    let digest = marker_assertion_digest(assertion)?;
    assertion.signature_ref = Some(digest.clone());
    validate_marker_assertion_inner(assertion, true)?;
    let mut attestation = Attestation {
        envelope_type: "iroka.igacms.attestation".into(),
        version: "1.0.0".into(),
        digest,
        epoch: assertion.issued_at,
        key_id: key_id.into(),
        signature: Vec::new(),
    };
    attestation.signature = key.sign(&attestation.bytes()).to_bytes().to_vec();
    Ok(attestation)
}

/// Verify payload binding and Ed25519 trust against the immutable trust snapshot.
/// A valid signature authenticates the assertion source; it does not prove substantive truth.
pub fn verify_attested_marker_assertion(
    assertion: &MarkerAssertion,
    attestation: &Attestation,
    roots: &crate::trust_lifecycle::TrustRootSet,
    now: u64,
) -> Result<(), IgacmsError> {
    validate_marker_assertion_inner(assertion, true)?;
    let digest = marker_assertion_digest(assertion)?;
    if assertion.signature_ref.as_deref() != Some(digest.as_str())
        || attestation.digest != digest
        || attestation.epoch != assertion.issued_at
        || now < assertion.valid_from
        || assertion.valid_until.is_some_and(|until| now >= until)
        || assertion.issued_at > now
    {
        return Err(IgacmsError::Signature);
    }
    verify_attestation_with_trust_roots(attestation, roots, now)
}

/// A replacement assertion must have a new identity and explicitly supersede its predecessor.
/// REVOKED is terminal for an assertion ID; a new assertion may replace it but cannot revive it.
pub fn validate_marker_transition(
    previous: Option<&MarkerAssertion>,
    next: &MarkerAssertion,
) -> Result<(), IgacmsError> {
    validate_marker_assertion(next)?;
    match previous {
        None if next.supersedes_ref.is_none() => Ok(()),
        Some(prior)
            if prior.assertion_id != next.assertion_id
                && next.supersedes_ref.as_deref() == Some(prior.assertion_id.as_str()) =>
        {
            Ok(())
        }
        _ => Err(IgacmsError::Marker),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedRoot {
    pub key_id: String,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub revoked: bool,
    pub provenance: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    pub envelope_type: String,
    pub version: String,
    pub digest: String,
    pub epoch: u64,
    pub key_id: String,
    pub signature: Vec<u8>,
}
impl Attestation {
    fn bytes(&self) -> Vec<u8> {
        {
            let mut out = Vec::new();
            for field in [
                ATTESTATION_DOMAIN,
                self.envelope_type.as_str(),
                self.version.as_str(),
                self.digest.as_str(),
                self.key_id.as_str(),
            ] {
                let b = field.as_bytes();
                out.extend_from_slice(&(b.len() as u64).to_be_bytes());
                out.extend_from_slice(b);
            }
            out.extend_from_slice(&self.epoch.to_be_bytes());
            out
        }
    }
}
pub fn sign_fingerprint(
    fp: &Fingerprint,
    epoch: u64,
    key_id: &str,
    key: &SigningKey,
) -> Attestation {
    let mut a = Attestation {
        envelope_type: "iroka.igacms.attestation".into(),
        version: "1.0.0".into(),
        digest: fp.digest_hex.clone(),
        epoch,
        key_id: key_id.into(),
        signature: Vec::new(),
    };
    a.signature = key.sign(&a.bytes()).to_bytes().to_vec();
    a
}
pub(crate) fn verify_attestation(
    a: &Attestation,
    roots: &[TrustedRoot],
    now: u64,
) -> Result<(), IgacmsError> {
    let r = roots
        .iter()
        .find(|r| r.key_id == a.key_id)
        .ok_or(IgacmsError::UnknownRoot)?;
    if r.revoked {
        return Err(IgacmsError::RevokedRoot);
    }
    if now < r.not_before
        || now >= r.not_after
        || r.not_before >= r.not_after
        || r.provenance.trim().is_empty()
    {
        return Err(IgacmsError::RootExpired);
    }
    if a.envelope_type != "iroka.igacms.attestation" || a.version != "1.0.0" {
        return Err(IgacmsError::Signature);
    }
    let k = VerifyingKey::from_bytes(&r.public_key).map_err(|_| IgacmsError::UnknownRoot)?;
    let s = Signature::from_slice(&a.signature).map_err(|_| IgacmsError::Signature)?;
    k.verify(&a.bytes(), &s).map_err(|_| IgacmsError::Signature)
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Genesis {
    pub dna_id: String,
    pub dna_version: String,
    pub genome_id: String,
    pub genome_version: String,
    pub digest: String,
    pub canonicalization: String,
    pub hash_algorithm: String,
    pub epoch: u64,
    pub parent: Option<String>,
    pub owner_approval_ref: String,
    pub trust_root_key_ids: Vec<String>,
    pub trust_root_provenance_refs: Vec<String>,
    pub attestation: Attestation,
    pub audit_refs: Vec<String>,
}
impl Genesis {
    fn signing_bytes(&self) -> Result<Vec<u8>, IgacmsError> {
        let envelope = serde_json::json!({
            "domain":"IROKA-IGACMS-GENESIS-V1",
            "dna_id":self.dna_id,"dna_version":self.dna_version,
            "genome_id":self.genome_id,"genome_version":self.genome_version,
            "payload_digest":self.digest,"canonicalization":self.canonicalization,
            "hash_algorithm":self.hash_algorithm,"epoch":self.epoch,"parent":self.parent,
            "owner_approval_ref":self.owner_approval_ref,
            "trust_root_key_ids":self.trust_root_key_ids,
            "trust_root_provenance_refs":self.trust_root_provenance_refs,
            "audit_refs":self.audit_refs
        });
        canonical_json(&envelope)
    }
}
pub fn sign_genesis(
    g: &Genesis,
    key_id: &str,
    key: &SigningKey,
) -> Result<Attestation, IgacmsError> {
    let envelope_digest = Sha256::digest(g.signing_bytes()?);
    let mut a = Attestation {
        envelope_type: "iroka.igacms.attestation".into(),
        version: "1.0.0".into(),
        digest: format!("{:x}", envelope_digest),
        epoch: g.epoch,
        key_id: key_id.into(),
        signature: Vec::new(),
    };
    a.signature = key.sign(&a.bytes()).to_bytes().to_vec();
    Ok(a)
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGenesis {
    digest: String,
    epoch: u64,
}
impl VerifiedGenesis {
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}
pub(crate) fn verify_genesis(
    g: &Genesis,
    fp: &Fingerprint,
    roots: &[TrustedRoot],
    now: u64,
) -> Result<VerifiedGenesis, IgacmsError> {
    if g.dna_id != "iroka.dna"
        || g.dna_version != "1.0.0"
        || g.genome_id != "IROKA_ZERO_GENOME"
        || g.genome_version != "1.0.0"
        || g.digest != fp.digest_hex
        || g.canonicalization != "RFC8785-JCS"
        || g.hash_algorithm != "SHA-256"
        || g.epoch != 0
        || g.parent.is_some()
        || g.owner_approval_ref.trim().is_empty()
        || g.audit_refs.is_empty()
        || g.trust_root_provenance_refs.is_empty()
        || !g.trust_root_key_ids.contains(&g.attestation.key_id)
        || g.attestation.epoch != 0
        || g.attestation.envelope_type != "iroka.igacms.attestation"
        || g.attestation.version != "1.0.0"
    {
        return Err(IgacmsError::Genesis);
    }
    if g.attestation.digest != format!("{:x}", Sha256::digest(g.signing_bytes()?)) {
        return Err(IgacmsError::Signature);
    }
    verify_attestation(&g.attestation, roots, now)?;
    Ok(VerifiedGenesis {
        digest: g.digest.clone(),
        epoch: g.epoch,
    })
}

pub fn verify_attestation_with_trust_roots(
    attestation: &Attestation,
    roots: &crate::trust_lifecycle::TrustRootSet,
    now: u64,
) -> Result<(), IgacmsError> {
    let root = roots
        .get(&attestation.key_id)
        .map_err(|_| IgacmsError::UnknownRoot)?;
    let trusted = TrustedRoot {
        key_id: root.key_id.clone(),
        public_key: root.public_key,
        not_before: root.not_before,
        not_after: root.not_after,
        revoked: false,
        provenance: root.provenance_ref.clone(),
    };
    verify_attestation(attestation, &[trusted], now)
}
/// Verify against the process trust snapshot, which must be bootstrapped from an Owner-controlled offline root ceremony.
/// Never construct or accept this root set from an untrusted request.
pub fn verify_genesis_with_trust_roots(
    genesis: &Genesis,
    fingerprint: &Fingerprint,
    roots: &crate::trust_lifecycle::TrustRootSet,
    now: u64,
) -> Result<VerifiedGenesis, IgacmsError> {
    let root = roots
        .get(&genesis.attestation.key_id)
        .map_err(|_| IgacmsError::UnknownRoot)?;
    if !genesis
        .trust_root_provenance_refs
        .contains(&root.provenance_ref)
    {
        return Err(IgacmsError::Genesis);
    }
    let trusted = TrustedRoot {
        key_id: root.key_id.clone(),
        public_key: root.public_key,
        not_before: root.not_before,
        not_after: root.not_after,
        revoked: false,
        provenance: root.provenance_ref.clone(),
    };
    verify_genesis(genesis, fingerprint, &[trusted], now)
}
pub fn verify_epoch_transition(
    epoch: u64,
    digest: &str,
    next: u64,
    parent: Option<&str>,
) -> Result<(), IgacmsError> {
    let expected = epoch.checked_add(1).ok_or(IgacmsError::Epoch)?;
    if next != expected || parent != Some(digest) {
        Err(IgacmsError::Epoch)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationClass {
    M0,
    M1,
    M2,
    M3,
    M4,
    M5,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MutationEvidence {
    pub owner_approved: bool,
    pub independent_review: bool,
    pub compatibility_checked: bool,
    pub schema_validated: bool,
    pub conformance_vectors_passed: bool,
    pub semantic_equivalence: bool,
    pub security_review: bool,
    pub impact_review: bool,
    pub migration_rollback_ready: bool,
    pub dual_control: bool,
    pub canonical_diff: bool,
}
pub fn authorize_mutation(c: MutationClass, e: &MutationEvidence) -> Result<(), IgacmsError> {
    let ok = match c {
        MutationClass::M0 => e.canonical_diff,
        MutationClass::M1 => e.canonical_diff && e.independent_review && e.semantic_equivalence,
        MutationClass::M2 => {
            e.compatibility_checked && e.schema_validated && e.conformance_vectors_passed
        }
        MutationClass::M3 => {
            e.security_review && e.impact_review && e.migration_rollback_ready && e.owner_approved
        }
        MutationClass::M4 => e.owner_approved && e.independent_review && e.migration_rollback_ready,
        MutationClass::M5 => {
            e.owner_approved && e.independent_review && e.migration_rollback_ready && e.dual_control
        }
    };
    if ok {
        Ok(())
    } else {
        Err(IgacmsError::MutationDenied)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoricalArtifact {
    pub id: String,
    pub commit: String,
    pub blob_sha: String,
    pub bytes: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationEvidence {
    pub id: String,
    pub source_commit: String,
    pub source_blob_sha: String,
    pub digest: String,
    pub disposition: String,
}
pub fn git_blob_sha1(bytes: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("blob {}\0", bytes.len()).as_bytes());
    h.update(bytes);
    format!("{:x}", h.finalize())
}
pub fn preserve_historical(a: &HistoricalArtifact) -> Result<MigrationEvidence, IgacmsError> {
    if a.id.is_empty()
        || !(7..=40).contains(&a.commit.len())
        || !a.commit.bytes().all(|b| b.is_ascii_hexdigit())
        || a.bytes.is_empty()
        || git_blob_sha1(&a.bytes) != a.blob_sha
    {
        return Err(IgacmsError::HistoricalEvidence);
    }
    let d = Sha256::digest(&a.bytes);
    Ok(MigrationEvidence {
        id: a.id.clone(),
        source_commit: a.commit.clone(),
        source_blob_sha: a.blob_sha.clone(),
        digest: format!("{:x}", d),
        disposition: if a.id == "DNA-045" {
            "EXTENSION-REVIEW"
        } else {
            "RETAIN-HISTORICAL"
        }
        .into(),
    })
}
pub fn cross_chromosome_invariants() -> &'static [&'static str] {
    &[
        "G01 identity never implies G02 authority",
        "G02 authority never implies G09 authorization",
        "G07 capability never implies permission for a specific G09 effect",
        "G08 orchestration never creates or broadens authority",
        "G03 inference never silently upgrades G04/G06 evidence",
        "G05 persistence never converts uncertain information into verified truth",
        "G06 external input is untrusted by default",
        "G09 execution never creates authority and must produce an attributable receipt",
        "G10 learning can propose but cannot approve constitutional mutation",
        "G11 assurance evidence is not self-authenticating",
        "G12 evolution preserves ancestry and rejects unapproved rollback",
        "No chromosome may bypass G11 validation for a protected constitutional transition",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    #[test]
    fn rejects_duplicate_object_keys_before_canonicalization() {
        assert_eq!(
            validate_genome(br#"{"a":1,"a":2}"#),
            Err(IgacmsError::Malformed)
        );
    }
    #[test]
    fn marker_cannot_upgrade_unknown_to_pass() {
        let a = MarkerAssertion {
            assertion_id: "a".into(),
            marker_id: "IDN-001".into(),
            subject_id: "s".into(),
            genome_version: "1.0.0".into(),
            chromosome_version: "1.0.0".into(),
            asserted_state: "UNKNOWN".into(),
            issuer: "issuer".into(),
            issued_at: 1,
            valid_from: 1,
            valid_until: None,
            evidence_refs: vec![],
            verifier: "".into(),
            verification_method: "".into(),
            signature_ref: None,
            supersedes_ref: None,
            status: "PASS".into(),
        };
        assert_eq!(validate_marker_assertion(&a), Err(IgacmsError::Marker));
    }
    #[test]
    fn validates_all_twelve_and_reasoning_domain() {
        let f = validate_embedded_baseline().unwrap();
        assert_eq!(f.algorithm, "SHA-256");
        assert_eq!(f.digest_hex, EXPECTED_GENOME_SHA256);
    }
    #[test]
    fn rejects_duplicate_or_extra_historical_domains() {
        let mut v: Value = serde_json::from_slice(EMBEDDED).unwrap();
        v["historical_domains"] = serde_json::json!([
            "identity",
            "identity",
            "evidence",
            "assurance",
            "reasoning",
            "security",
            "execution",
            "evolution"
        ]);
        assert_eq!(
            validate_genome(&serde_json::to_vec(&v).unwrap()).unwrap_err(),
            IgacmsError::Malformed
        );
    }
    #[test]
    fn rejects_unknown_marker_catalogue_id() {
        let mut v: Value = serde_json::from_slice(EMBEDDED).unwrap();
        v["markers"][0]["id"] = Value::String("UNKNOWN-999".into());
        assert_eq!(
            validate_genome(&serde_json::to_vec(&v).unwrap()).unwrap_err(),
            IgacmsError::Marker
        );
    }
    #[test]
    fn rejects_missing_reasoning() {
        let mut v: Value = serde_json::from_slice(EMBEDDED).unwrap();
        v["historical_domains"] = Value::Array(
            v["historical_domains"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|x| x.as_str() != Some("reasoning"))
                .cloned()
                .collect(),
        );
        assert!(matches!(
            validate_genome(&serde_json::to_vec(&v).unwrap()),
            Err(IgacmsError::MissingDomain(_))
        ));
    }
    #[test]
    fn rejects_duplicate_gene_ids() {
        let mut v: Value = serde_json::from_slice(EMBEDDED).unwrap();
        let first = v["genes"][0].clone();
        v["genes"][1] = first;
        assert!(matches!(
            validate_genome(&serde_json::to_vec(&v).unwrap()),
            Err(IgacmsError::DuplicateId(_))
        ));
    }
    #[test]
    fn rejects_dependency_cycle() {
        let mut v: Value = serde_json::from_slice(EMBEDDED).unwrap();
        v["dependency_graph"][0]["depends_on"] = serde_json::json!(["G02"]);
        v["dependency_graph"][1]["depends_on"] = serde_json::json!(["G01"]);
        assert_eq!(
            validate_genome(&serde_json::to_vec(&v).unwrap()).unwrap_err(),
            IgacmsError::DependencyCycle
        );
    }
    #[test]
    fn verifies_ed25519_and_revocation() {
        let fp = validate_embedded_baseline().unwrap();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let a = sign_fingerprint(&fp, 0, "root", &key);
        let r = TrustedRoot {
            key_id: "root".into(),
            public_key: key.verifying_key().to_bytes(),
            not_before: 1,
            not_after: 99,
            revoked: false,
            provenance: "test".into(),
        };
        assert!(verify_attestation(&a, std::slice::from_ref(&r), 50).is_ok());
        let mut revoked = r;
        revoked.revoked = true;
        assert_eq!(
            verify_attestation(&a, &[revoked], 50),
            Err(IgacmsError::RevokedRoot)
        );
    }
    #[test]
    fn mutation_requires_owner_and_independent_review() {
        assert_eq!(
            authorize_mutation(MutationClass::M4, &MutationEvidence::default()),
            Err(IgacmsError::MutationDenied)
        );
        let e = MutationEvidence {
            owner_approved: true,
            independent_review: true,
            migration_rollback_ready: true,
            dual_control: true,
            security_review: true,
            impact_review: true,
            ..Default::default()
        };
        assert!(authorize_mutation(MutationClass::M5, &e).is_ok());
    }
    #[test]
    fn preserves_dna045_outside_genesis() {
        let a = HistoricalArtifact {
            id: "DNA-045".into(),
            commit: "1224bb8298f9ef21d2590dd6e70273501281cd9".into(),
            blob_sha: git_blob_sha1(b"immutable"),
            bytes: b"immutable".to_vec(),
        };
        assert_eq!(
            preserve_historical(&a).unwrap().disposition,
            "EXTENSION-REVIEW"
        );
        let mut tampered = a.clone();
        tampered.blob_sha = "0000000000000000000000000000000000000000".into();
        assert_eq!(
            preserve_historical(&tampered),
            Err(IgacmsError::HistoricalEvidence)
        );
    }
    #[test]
    fn verifies_epoch_zero_genesis_binding() {
        let fp = validate_embedded_baseline().unwrap();
        let key = SigningKey::from_bytes(&[4u8; 32]);
        let root = TrustedRoot {
            key_id: "root".into(),
            public_key: key.verifying_key().to_bytes(),
            not_before: 1,
            not_after: 100,
            revoked: false,
            provenance: "custody-record:test".into(),
        };
        let mut g = Genesis {
            dna_id: "iroka.dna".into(),
            dna_version: "1.0.0".into(),
            genome_id: "IROKA_ZERO_GENOME".into(),
            genome_version: "1.0.0".into(),
            digest: fp.digest_hex.clone(),
            canonicalization: "RFC8785-JCS".into(),
            hash_algorithm: "SHA-256".into(),
            epoch: 0,
            parent: None,
            owner_approval_ref: "approval-record:test".into(),
            trust_root_key_ids: vec!["root".into()],
            trust_root_provenance_refs: vec!["custody-record:test".into()],
            attestation: Attestation {
                envelope_type: "iroka.igacms.attestation".into(),
                version: "1.0.0".into(),
                digest: String::new(),
                epoch: 0,
                key_id: "root".into(),
                signature: Vec::new(),
            },
            audit_refs: vec!["audit:test".into()],
        };
        g.attestation = sign_genesis(&g, "root", &key).unwrap();
        assert!(verify_genesis(&g, &fp, &[root], 50).is_ok());
        let mut tampered = g.clone();
        tampered.owner_approval_ref = "approval-record:tampered".into();
        assert_eq!(
            verify_genesis(
                &tampered,
                &fp,
                &[TrustedRoot {
                    key_id: "root".into(),
                    public_key: key.verifying_key().to_bytes(),
                    not_before: 1,
                    not_after: 100,
                    revoked: false,
                    provenance: "custody-record:test".into()
                }],
                50
            ),
            Err(IgacmsError::Signature)
        );
    }
    #[test]
    fn rejects_epoch_rollback_and_overflow() {
        assert_eq!(
            verify_epoch_transition(1, "d", 1, None),
            Err(IgacmsError::Epoch)
        );
        assert!(verify_epoch_transition(1, "d", 2, Some("d")).is_ok());
        assert_eq!(
            verify_epoch_transition(u64::MAX, "d", u64::MAX, Some("d")),
            Err(IgacmsError::Epoch)
        );
    }
    fn marker_fixture(state: &str) -> MarkerAssertion {
        MarkerAssertion {
            assertion_id: "assertion-1".into(),
            marker_id: "IDN-001".into(),
            subject_id: "genome-0".into(),
            genome_version: "1.0.0".into(),
            chromosome_version: "1.0.0".into(),
            asserted_state: state.into(),
            issuer: "test-issuer".into(),
            issued_at: 50,
            valid_from: 10,
            valid_until: Some(100),
            evidence_refs: vec!["sha256:evidence".into()],
            verifier: "test-verifier".into(),
            verification_method: "fixture".into(),
            signature_ref: None,
            supersedes_ref: None,
            status: "PASS".into(),
        }
    }

    #[test]
    fn rejects_substituted_canonical_principle_id() {
        let mut value: Value = serde_json::from_slice(EMBEDDED).unwrap();
        value["principles"][0]["id"] = Value::String("invented-principle".into());
        assert_eq!(
            validate_genome(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            IgacmsError::Identity
        );
    }

    #[test]
    fn rejects_changed_canonical_invariant_semantics() {
        let mut value: Value = serde_json::from_slice(EMBEDDED).unwrap();
        value["invariants"][0]["statement"] = Value::String("altered".into());
        assert_eq!(
            validate_genome(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            IgacmsError::Identity
        );
    }

    #[test]
    fn rejects_dependency_graph_drift_and_duplicate_edges() {
        let mut drift: Value = serde_json::from_slice(EMBEDDED).unwrap();
        drift["dependency_graph"][2]["depends_on"] = serde_json::json!(["G01"]);
        assert_eq!(
            validate_genome(&serde_json::to_vec(&drift).unwrap()).unwrap_err(),
            IgacmsError::Dependency
        );
        let mut duplicate: Value = serde_json::from_slice(EMBEDDED).unwrap();
        duplicate["dependency_graph"][2]["depends_on"] =
            serde_json::json!(["G01", "G01", "G04", "G11"]);
        assert_eq!(
            validate_genome(&serde_json::to_vec(&duplicate).unwrap()).unwrap_err(),
            IgacmsError::Dependency
        );
    }

    #[test]
    fn attested_marker_requires_a_trusted_signature_bound_to_payload() {
        let key = SigningKey::from_bytes(&[31u8; 32]);
        let mut assertion = marker_fixture("ATTESTED");
        let attestation = sign_marker_assertion(&mut assertion, "marker-root", &key).unwrap();
        assert_eq!(
            validate_marker_assertion(&assertion),
            Err(IgacmsError::Marker)
        );
        let roots =
            crate::trust_lifecycle::TrustRootSet::new(vec![crate::trust_lifecycle::TrustRoot {
                key_id: "marker-root".into(),
                public_key: key.verifying_key().to_bytes(),
                not_before: 1,
                not_after: 100,
                provenance_ref: "test-root-provenance".into(),
            }])
            .unwrap();
        assert!(verify_attested_marker_assertion(&assertion, &attestation, &roots, 60).is_ok());
        let mut tampered = assertion.clone();
        tampered.evidence_refs.push("sha256:changed".into());
        assert_eq!(
            verify_attested_marker_assertion(&tampered, &attestation, &roots, 60),
            Err(IgacmsError::Signature)
        );
        let wrong_key = SigningKey::from_bytes(&[32u8; 32]);
        let wrong_roots =
            crate::trust_lifecycle::TrustRootSet::new(vec![crate::trust_lifecycle::TrustRoot {
                key_id: "marker-root".into(),
                public_key: wrong_key.verifying_key().to_bytes(),
                not_before: 1,
                not_after: 100,
                provenance_ref: "test-root-provenance".into(),
            }])
            .unwrap();
        assert_eq!(
            verify_attested_marker_assertion(&assertion, &attestation, &wrong_roots, 60),
            Err(IgacmsError::Signature)
        );
    }

    #[test]
    fn marker_replacement_requires_new_id_and_supersession_even_after_revocation() {
        let previous = marker_fixture("REVOKED");
        let mut replacement = marker_fixture("OBSERVED");
        replacement.assertion_id = "assertion-2".into();
        replacement.supersedes_ref = Some(previous.assertion_id.clone());
        assert!(validate_marker_transition(Some(&previous), &replacement).is_ok());
        replacement.assertion_id = previous.assertion_id.clone();
        assert_eq!(
            validate_marker_transition(Some(&previous), &replacement),
            Err(IgacmsError::Marker)
        );
        replacement.assertion_id = "assertion-3".into();
        replacement.supersedes_ref = None;
        assert_eq!(
            validate_marker_transition(Some(&previous), &replacement),
            Err(IgacmsError::Marker)
        );
    }

}
