//! G02 Owner-governance evidence evaluator. Read-only: it never authorizes or executes.
use crate::{canonical_json, OwnerApprovalVerifier, OwnerApprovalError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const DOMAIN_APPROVAL: &[u8] = b"IROKA-OWNER-GOVERNANCE-APPROVAL-V1\0";
const DOMAIN_REGISTER: &[u8] = b"IROKA-OWNER-DECISION-REGISTER-V1\0";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="snake_case")]
pub enum OwnerDecision { Approved, Rejected }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="snake_case")]
pub enum OwnerRegisterStatus { Active, Superseded, Revoked }
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="snake_case")]
pub enum OwnerGovernanceDecision { Approved, Rejected, Expired }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerDecisionRegisterEntry {
    pub decision_id: String,
    pub owner_id: String,
    pub decision_digest: String,
    pub scope: Vec<String>,
    pub nonce: String,
    pub sequence: u64,
    pub status: OwnerRegisterStatus,
    pub superseded_by: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedOwnerDecisionRegisterSnapshot {
    pub owner_id: String,
    pub key_id: String,
    pub issued_at: String,
    pub expires_at: String,
    pub sequence: u64,
    pub entries: Vec<OwnerDecisionRegisterEntry>,
    pub signature: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerGovernanceApprovalPayload {
    pub owner_id: String,
    pub decision_id: String,
    pub decision: OwnerDecision,
    pub decision_digest: String,
    pub scope: Vec<String>,
    pub nonce: String,
    pub contract_version: String,
    pub issued_at: String,
    pub expires_at: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedOwnerGovernanceApproval {
    pub payload: OwnerGovernanceApprovalPayload,
    pub signature: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OwnerGovernanceInput {
    pub owner_id: String,
    pub decision_id: String,
    pub scope: Vec<String>,
    pub approval_digest: String,
    pub signature: Vec<u8>,
    pub issued_at: String,
    pub expires_at: String,
    pub approval: SignedOwnerGovernanceApproval,
    pub register_snapshot: SignedOwnerDecisionRegisterSnapshot,
    pub provenance: BTreeMap<String, Value>,
    pub version_bound_evidence: BTreeMap<String, Value>,
    pub safeguard_conflicts: Vec<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnerGovernancePolicy {
    minimum_register_sequence: u64,
    maximum_approval_ttl_secs: u64,
}
impl OwnerGovernancePolicy {
    pub fn new(minimum_register_sequence: u64, maximum_approval_ttl_secs: u64) -> Self {
        Self { minimum_register_sequence, maximum_approval_ttl_secs }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerGovernanceEvidence {
    pub owner_identity_verified: bool,
    pub approval_signature_verified: bool,
    pub register_snapshot_verified: bool,
    pub decision_register_entry_unique: bool,
    pub scope_exact_match: bool,
    pub temporal_validity_verified: bool,
    pub revocation_checked: bool,
    pub register_sequence: u64,
    pub evaluated_at: String,
    pub provenance: BTreeMap<String, Value>,
    pub decision_reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerGovernanceOutput {
    pub decision_id: String,
    pub approval_valid: bool,
    pub authorized_scope: Vec<String>,
    pub decision: OwnerGovernanceDecision,
    pub evidence: OwnerGovernanceEvidence,
    pub version_bound_evidence: BTreeMap<String, Value>,
    pub safeguard_conflicts: Vec<String>,
    pub safeguards_satisfied: bool,
    pub execution_authorized: bool,
}

#[derive(Serialize)]
struct RegisterPayload<'a> {
    owner_id: &'a str, key_id: &'a str, issued_at: &'a str,
    expires_at: &'a str, sequence: u64, entries: &'a [OwnerDecisionRegisterEntry],
}
fn canonical<T: Serialize>(value: &T) -> Option<Vec<u8>> {
    canonical_json(&serde_json::to_value(value).ok()?).ok()
}
fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn digest_matches(a: &str, b: &str) -> bool {
    if a.len()!=b.len() { return false; }
    a.bytes().zip(b.bytes()).fold(0u8, |acc,(x,y)| acc | (x^y))==0
}
fn approval_bytes(payload: &OwnerGovernanceApprovalPayload) -> Option<Vec<u8>> {
    let mut bytes=DOMAIN_APPROVAL.to_vec();
    bytes.extend(canonical(payload)?);
    Some(bytes)
}
fn register_bytes(snapshot: &SignedOwnerDecisionRegisterSnapshot) -> Option<Vec<u8>> {
    let payload=RegisterPayload {
        owner_id:&snapshot.owner_id,key_id:&snapshot.key_id,issued_at:&snapshot.issued_at,
        expires_at:&snapshot.expires_at,sequence:snapshot.sequence,entries:&snapshot.entries,
    };
    let mut bytes=DOMAIN_REGISTER.to_vec();
    bytes.extend(canonical(&payload)?);
    Some(bytes)
}
fn parse_utc(value:&str)->Option<u64>{
    let b=value.as_bytes();
    if b.len()!=20 || b[4]!=b'-' || b[7]!=b'-' || b[10]!=b'T' || b[13]!=b':' || b[16]!=b':' || b[19]!=b'Z' {return None;}
    let p=|a:usize,z:usize|->Option<i64>{let s=std::str::from_utf8(&b[a..z]).ok()?;if !s.bytes().all(|c|c.is_ascii_digit()){return None;}s.parse().ok()};
    let y=p(0,4)?;let m=p(5,7)?;let d=p(8,10)?;let h=p(11,13)?;let mi=p(14,16)?;let s=p(17,19)?;
    if !(1970..=9999).contains(&y)||!(1..=12).contains(&m)||!(0..=23).contains(&h)||!(0..=59).contains(&mi)||!(0..=59).contains(&s){return None;}
    let leap=y%4==0&&(y%100!=0||y%400==0);
    let md=[31,if leap{29}else{28},31,30,31,30,31,31,30,31,30,31];
    if d<1||d>md[(m-1) as usize]{return None;}
    let yy=y-if m<=2{1}else{0};let era=yy/400;let yoe=yy-era*400;let mp=m+if m>2{-3}else{9};
    let doy=(153*mp+2)/5+d-1;let doe=yoe*365+yoe/4-yoe/100+doy;
    u64::try_from((era*146097+doe-719468)*86400+h*3600+mi*60+s).ok()
}
fn canonical_scope(scope:&[String])->Option<Vec<String>>{
    if scope.is_empty()||scope.iter().any(|s|s.trim().is_empty()||s.trim()!=s){return None;}
    let mut v=scope.to_vec();v.sort();
    if v.windows(2).any(|w|w[0]==w[1]){return None;}Some(v)
}
fn output(input:&OwnerGovernanceInput,now:u64,decision:OwnerGovernanceDecision,valid:bool,scope:Vec<String>,reason:&str,
    owner_ok:bool,approval_ok:bool,register_ok:bool,unique:bool,scope_ok:bool,time_ok:bool,revoked_checked:bool,sequence:u64)->OwnerGovernanceOutput{
    OwnerGovernanceOutput{
        decision_id:input.decision_id.clone(),approval_valid:valid,authorized_scope:scope,decision,
        evidence:OwnerGovernanceEvidence{
            owner_identity_verified:owner_ok,approval_signature_verified:approval_ok,register_snapshot_verified:register_ok,
            decision_register_entry_unique:unique,scope_exact_match:scope_ok,temporal_validity_verified:time_ok,
            revocation_checked:revoked_checked,register_sequence:sequence,evaluated_at:format!("unix:{now}"),
            provenance:input.provenance.clone(),decision_reason:reason.into(),
        },
        version_bound_evidence:input.version_bound_evidence.clone(),
        safeguard_conflicts:input.safeguard_conflicts.clone(),
        safeguards_satisfied:input.safeguard_conflicts.is_empty(),
        execution_authorized:false,
    }
}

/// Validate an Owner approval and its signed immutable decision-register snapshot.
/// This is read-only evidence evaluation: even a valid approval never authorizes execution.
pub fn evaluate_owner_governance(
    input:&OwnerGovernanceInput,policy:&OwnerGovernancePolicy,
    verifier:&OwnerApprovalVerifier,now:u64
)->OwnerGovernanceOutput{
    let p=&input.approval.payload;let snapshot=&input.register_snapshot;
    if input.owner_id.trim().is_empty()||input.decision_id.trim().is_empty()
        ||input.provenance.is_empty()||input.version_bound_evidence.is_empty()
        ||input.signature.len()!=64||input.approval.signature!=input.signature{
        return output(input,now,OwnerGovernanceDecision::Rejected,false,vec![],"required_input_or_signature_binding_invalid",false,false,false,false,false,false,false,0);
    }
    if p.owner_id!=input.owner_id||p.decision_id!=input.decision_id||p.scope!=input.scope
        ||p.issued_at!=input.issued_at||p.expires_at!=input.expires_at{
        return output(input,now,OwnerGovernanceDecision::Rejected,false,vec![],"approval_input_binding_mismatch",false,false,false,false,false,false,false,0);
    }
    let Some(scope)=canonical_scope(&input.scope) else {
        return output(input,now,OwnerGovernanceDecision::Rejected,false,vec![],"scope_noncanonical_or_ambiguous",false,false,false,false,false,false,false,0);
    };
    if scope!=input.scope||p.scope!=scope||p.contract_version.trim().is_empty()||p.nonce.len()<16
        ||p.decision_digest.len()!=64||!p.decision_digest.bytes().all(|b|b.is_ascii_hexdigit()&&!b.is_ascii_uppercase()){
        return output(input,now,OwnerGovernanceDecision::Rejected,false,vec![],"approval_payload_malformed",false,false,false,false,false,false,false,0);
    }
    if snapshot.owner_id!=input.owner_id||snapshot.sequence<policy.minimum_register_sequence
        ||snapshot.entries.is_empty()||snapshot.entries.len()>4096{
        return output(input,now,OwnerGovernanceDecision::Rejected,false,vec![],"decision_register_snapshot_invalid",false,false,false,false,false,false,false,snapshot.sequence);
    }
    let Some(issued)=parse_utc(&p.issued_at) else{return output(input,now,OwnerGovernanceDecision::Rejected,false,vec![],"approval_issued_at_noncanonical",false,false,false,false,false,false,false,snapshot.sequence)};
    let Some(expires)=parse_utc(&p.expires_at) else{return output(input,now,OwnerGovernanceDecision::Rejected,false,vec![],"approval_expires_at_noncanonical",false,false,false,false,false,false,false,snapshot.sequence)};
    let Some(reg_issued)=parse_utc(&snapshot.issued_at) else{return output(input,now,OwnerGovernanceDecision::Rejected,false,vec![],"register_issued_at_noncanonical",false,false,false,false,false,false,false,snapshot.sequence)};
    let Some(reg_expires)=parse_utc(&snapshot.expires_at) else{return output(input,now,OwnerGovernanceDecision::Rejected,false,vec![],"register_expires_at_noncanonical",false,false,false,false,false,false,false,snapshot.sequence)};
    if expires<=issued||expires-issued>policy.maximum_approval_ttl_secs||reg_expires<=reg_issued||now<reg_issued||now>=reg_expires{
        let exp=now>=expires||now>=reg_expires;
        return output(input,now,if exp{OwnerGovernanceDecision::Expired}else{OwnerGovernanceDecision::Rejected},false,vec![],"approval_or_register_time_window_invalid",false,false,false,false,false,false,false,snapshot.sequence);
    }
    let Some(approval_bytes)=approval_bytes(p) else{return output(input,now,OwnerGovernanceDecision::Rejected,false,vec![],"approval_canonicalization_failed",false,false,false,false,false,false,false,snapshot.sequence)};
    let approval_digest=digest(&approval_bytes);
    if !digest_matches(&approval_digest,&input.approval_digest){
        return output(input,now,OwnerGovernanceDecision::Rejected,false,vec![],"approval_digest_mismatch",false,false,false,false,false,false,false,snapshot.sequence);
    }
    let Some(register_bytes)=register_bytes(snapshot) else{return output(input,now,OwnerGovernanceDecision::Rejected,false,vec![],"register_canonicalization_failed",false,false,false,false,false,false,false,snapshot.sequence)};
    let reg_ok=verifier.verify_detached_owner_payload(&snapshot.owner_id,&snapshot.key_id,&register_bytes,&snapshot.signature,reg_issued,now).is_ok();
    if !reg_ok{return output(input,now,OwnerGovernanceDecision::Rejected,false,vec![],"register_signature_or_owner_key_invalid",false,false,false,false,false,false,false,snapshot.sequence);}
    let approval_ok=verifier.verify_detached_owner_payload(&p.owner_id,&snapshot.key_id,&approval_bytes,&input.signature,issued,now).is_ok();
    if !approval_ok{return output(input,now,OwnerGovernanceDecision::Rejected,false,vec![],"approval_signature_or_owner_key_invalid",true,false,true,false,false,false,true,snapshot.sequence);}
    let mut ids=BTreeSet::new();let mut nonces=BTreeSet::new();
    let unique=snapshot.entries.iter().all(|e|ids.insert(e.decision_id.as_str())&&nonces.insert(e.nonce.as_str()));
    if !unique{return output(input,now,OwnerGovernanceDecision::Rejected,false,vec![],"decision_register_duplicate_id_or_nonce",true,true,true,false,false,false,true,snapshot.sequence);}
    let matches:Vec<_>=snapshot.entries.iter().filter(|e|e.decision_id==input.decision_id).collect();
    if matches.len()!=1{return output(input,now,OwnerGovernanceDecision::Rejected,false,vec![],"decision_id_missing_or_ambiguous",true,true,true,false,false,false,true,snapshot.sequence);}
    let entry=matches[0];
    let scope_ok=entry.scope==scope&&entry.owner_id==input.owner_id&&entry.decision_digest==p.decision_digest&&entry.nonce==p.nonce;
    if !scope_ok||entry.sequence>snapshot.sequence||entry.status!=OwnerRegisterStatus::Active||entry.superseded_by.is_some(){
        return output(input,now,OwnerGovernanceDecision::Rejected,false,vec![],"decision_register_binding_or_status_invalid",true,true,true,true,false,false,true,snapshot.sequence);
    }
    if now<issued{return output(input,now,OwnerGovernanceDecision::Rejected,false,vec![],"approval_not_yet_valid",true,true,true,true,true,false,true,snapshot.sequence);}
    if now>=expires{return output(input,now,OwnerGovernanceDecision::Expired,false,vec![],"approval_expired",true,true,true,true,true,false,true,snapshot.sequence);}
    let (decision,valid,approved_scope,reason)=match p.decision{
        OwnerDecision::Approved=>(OwnerGovernanceDecision::Approved,true,scope,"owner_approval_verified"),
        OwnerDecision::Rejected=>(OwnerGovernanceDecision::Rejected,true,vec![],"owner_decision_rejected"),
    };
    output(input,now,decision,valid,approved_scope,reason,true,true,true,true,true,true,true,snapshot.sequence)
}

#[cfg(test)]
mod tests{
    use super::*;
    use crate::{SqliteSecurityStore,TrustedOwnerKey};
    use ed25519_dalek::{Signer,SigningKey};
    use std::sync::Arc;
    fn fixture()->(SigningKey,OwnerApprovalVerifier,OwnerGovernanceInput,OwnerGovernancePolicy){
        let signer=SigningKey::from_bytes(&[81u8;32]);let owner="owner:akefa";let key="owner-key-a3";
        let store=Arc::new(SqliteSecurityStore::open_in_memory().unwrap());
        let verifier=OwnerApprovalVerifier::new(vec![TrustedOwnerKey{owner_subject:owner.into(),key_id:key.into(),public_key:signer.verifying_key().to_bytes(),not_before:1_700_000_000,not_after:2_000_000_000}],store).unwrap();
        let scope=vec!["governance.decide".into(),"records.read".into()];
        let issued="2026-01-01T00:00:00Z";let expires="2026-01-01T00:10:00Z";
        let payload=OwnerGovernanceApprovalPayload{owner_id:owner.into(),decision_id:"decision:001".into(),decision:OwnerDecision::Approved,decision_digest:"a".repeat(64),scope:scope.clone(),nonce:"owner-decision-nonce-001".into(),contract_version:"1.1.0".into(),issued_at:issued.into(),expires_at:expires.into()};
        let mut ab=DOMAIN_APPROVAL.to_vec();ab.extend(canonical(&payload).unwrap());let approval_digest=digest(&ab);
        let signature=signer.sign(&ab).to_bytes().to_vec();
        let entry=OwnerDecisionRegisterEntry{decision_id:payload.decision_id.clone(),owner_id:owner.into(),decision_digest:payload.decision_digest.clone(),scope:scope.clone(),nonce:payload.nonce.clone(),sequence:1,status:OwnerRegisterStatus::Active,superseded_by:None};
        let mut snapshot=SignedOwnerDecisionRegisterSnapshot{owner_id:owner.into(),key_id:key.into(),issued_at:"2026-01-01T00:00:00Z".into(),expires_at:"2026-01-02T00:00:00Z".into(),sequence:1,entries:vec![entry],signature:vec![]};
        let mut rb=DOMAIN_REGISTER.to_vec();rb.extend(canonical(&RegisterPayload{owner_id:&snapshot.owner_id,key_id:&snapshot.key_id,issued_at:&snapshot.issued_at,expires_at:&snapshot.expires_at,sequence:snapshot.sequence,entries:&snapshot.entries}).unwrap());
        snapshot.signature=signer.sign(&rb).to_bytes().to_vec();
        let input=OwnerGovernanceInput{owner_id:owner.into(),decision_id:payload.decision_id.clone(),scope:scope.clone(),approval_digest,signature:signature.clone(),issued_at:issued.into(),expires_at:expires.into(),approval:SignedOwnerGovernanceApproval{payload,signature},register_snapshot:snapshot,provenance:BTreeMap::from([("source".into(),serde_json::json!("synthetic-owner-register"))]),version_bound_evidence:BTreeMap::from([("genome_digest".into(),serde_json::json!("c".repeat(64)))]),safeguard_conflicts:vec![]};
        (signer,verifier,input,OwnerGovernancePolicy::new(1,900))
    }
    #[test]fn accepts_signed_register_and_approval_without_execution(){
        let(_,v,i,p)=fixture();let o=evaluate_owner_governance(&i,&p,&v,1_767_225_700);
        assert!(o.approval_valid);assert_eq!(o.decision,OwnerGovernanceDecision::Approved);
        assert!(!o.execution_authorized);assert_eq!(o.authorized_scope.len(),2);
    }
    #[test]fn rejects_scope_substitution_and_superseded_decision(){
        let(_,v,mut i,p)=fixture();i.scope.push("system.execute".into());
        assert!(!evaluate_owner_governance(&i,&p,&v,1_767_225_700).approval_valid);
        let(_,v,mut i,p)=fixture();i.register_snapshot.entries[0].status=OwnerRegisterStatus::Superseded;
        assert!(!evaluate_owner_governance(&i,&p,&v,1_767_225_700).approval_valid);
    }
    #[test]fn records_safeguard_conflicts_without_overriding_them(){
        let(_,v,mut i,p)=fixture();i.safeguard_conflicts=vec!["constitutional_safeguard".into()];
        let o=evaluate_owner_governance(&i,&p,&v,1_767_225_700);
        assert!(o.approval_valid);assert!(!o.safeguards_satisfied);assert!(!o.execution_authorized);
    }
    #[test]fn rejects_expired_approval(){
        let(_,v,i,p)=fixture();let o=evaluate_owner_governance(&i,&p,&v,1_767_226_500);
        assert_eq!(o.decision,OwnerGovernanceDecision::Expired);assert!(!o.approval_valid);
    }
}
