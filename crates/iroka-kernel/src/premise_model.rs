//! G03 premise-model normalization with explicit epistemic status and complete disposition.
use crate::canonical_json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all="snake_case")]
pub enum EpistemicStatus { Fact, Assumption, Hypothesis, Unknown }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PremiseSourceReference {
    pub source_id: String,
    pub source_type: String,
    pub source_digest: String,
    pub provenance_ref: String,
    pub observed_at: Option<String>,
    pub observation_time_unknown_reason: Option<String>,
    pub valid_until: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PremiseInput {
    pub premise_id: String,
    pub statement: String,
    pub epistemic_status: EpistemicStatus,
    pub source_refs: Vec<PremiseSourceReference>,
    pub source_unavailable_reason: Option<String>,
    pub confidence: Option<f64>,
    pub context: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PremiseModelInput {
    pub premises: Vec<PremiseInput>,
    pub context_id: String,
    pub model_version: String,
    pub normalization_policy_version: String,
    pub provenance: BTreeMap<String, Value>,
    pub version_bound_evidence: BTreeMap<String, Value>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PremiseModelPolicy {
    expected_model_version: &'static str,
    normalization_policy_version: &'static str,
    maximum_premises: usize,
}
impl PremiseModelPolicy {
    pub fn new(expected_model_version: &'static str, normalization_policy_version: &'static str, maximum_premises: usize) -> Self {
        Self { expected_model_version, normalization_policy_version, maximum_premises }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NormalizedPremise {
    pub premise_id: String,
    pub normalized_statement: String,
    pub epistemic_status: EpistemicStatus,
    pub source_refs: Vec<PremiseSourceReference>,
    pub confidence: Option<f64>,
    pub context: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UnresolvedPremise {
    pub premise_id: String,
    pub statement: String,
    pub epistemic_status: EpistemicStatus,
    pub source_refs: Vec<PremiseSourceReference>,
    pub unresolved_reason: String,
    pub context: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PremiseModelEvidence {
    pub model_version: String,
    pub normalization_policy_version: String,
    pub input_premise_count: u64,
    pub normalized_count: u64,
    pub unresolved_count: u64,
    pub complete_disposition: bool,
    pub deterministic_ordering: bool,
    pub canonical_serialization: bool,
    pub provenance_digest: String,
    pub version_bound_evidence_digest: String,
    pub decision_reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PremiseModelOutput {
    pub model_id: String,
    pub model_valid: bool,
    pub premise_set_digest: Option<String>,
    pub normalized_premises: Vec<NormalizedPremise>,
    pub unresolved_premises: Vec<UnresolvedPremise>,
    pub evidence: PremiseModelEvidence,
    pub version_bound_evidence: BTreeMap<String, Value>,
}

fn digest(bytes:&[u8])->String{format!("{:x}",Sha256::digest(bytes))}
fn canonical<T:Serialize>(value:&T)->Option<Vec<u8>>{canonical_json(&serde_json::to_value(value).ok()?).ok()}
fn valid_digest(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_hexdigit()&&!b.is_ascii_uppercase())}
fn parse_utc(s:&str)->Option<u64>{
    let b=s.as_bytes();
    if b.len()!=20||b[4]!=b'-'||b[7]!=b'-'||b[10]!=b'T'||b[13]!=b':'||b[16]!=b':'||b[19]!=b'Z'{return None;}
    let p=|a:usize,z:usize|->Option<i64>{let v=std::str::from_utf8(&b[a..z]).ok()?;if !v.bytes().all(|c|c.is_ascii_digit()){return None;}v.parse().ok()};
    let y=p(0,4)?;let m=p(5,7)?;let d=p(8,10)?;let h=p(11,13)?;let mi=p(14,16)?;let se=p(17,19)?;
    if !(1970..=9999).contains(&y)||!(1..=12).contains(&m)||!(0..=23).contains(&h)||!(0..=59).contains(&mi)||!(0..=59).contains(&se){return None;}
    let leap=y%4==0&&(y%100!=0||y%400==0);let md=[31,if leap{29}else{28},31,30,31,30,31,31,30,31,30,31];
    if d<1||d>md[(m-1) as usize]{return None;}
    let yy=y-if m<=2{1}else{0};let era=yy/400;let yoe=yy-era*400;let mp=m+if m>2{-3}else{9};
    let doy=(153*mp+2)/5+d-1;let doe=yoe*365+yoe/4-yoe/100+doy;
    u64::try_from((era*146097+doe-719468)*86400+h*3600+mi*60+se).ok()
}
fn normalize_statement(s:&str)->String{s.split_whitespace().collect::<Vec<_>>().join(" ")}
fn unresolved(p:&PremiseInput,reason:&str)->UnresolvedPremise{
    let mut source_refs=p.source_refs.clone();
    source_refs.sort_by(|a,b|a.source_id.cmp(&b.source_id));
    UnresolvedPremise{premise_id:p.premise_id.clone(),statement:p.statement.clone(),epistemic_status:p.epistemic_status,
        source_refs,unresolved_reason:reason.into(),context:p.context.clone()}
}
fn source_problem(p:&PremiseInput,now:u64)->Option<String>{
    if p.premise_id.trim().is_empty()||p.statement.trim().is_empty()||p.context.trim().is_empty(){return Some("required_premise_field_missing".into());}
    if p.confidence.is_some_and(|v|!v.is_finite()||!(0.0..=1.0).contains(&v)){return Some("confidence_outside_finite_unit_interval".into());}
    if p.epistemic_status==EpistemicStatus::Unknown{return Some("epistemic_status_unknown".into());}
    if p.epistemic_status==EpistemicStatus::Fact&&p.source_refs.is_empty(){return Some("fact_without_source_reference".into());}
    if p.source_refs.is_empty(){return Some(p.source_unavailable_reason.clone().unwrap_or_else(||"source_unavailable_without_reason".into()));}
    if p.source_unavailable_reason.is_some(){return Some("source_unavailable_conflicts_with_source_reference".into());}
    let mut source_ids=BTreeSet::new();
    for src in &p.source_refs{
        if !source_ids.insert(src.source_id.as_str()){return Some("duplicate_source_reference_id".into());}
        if src.source_id.trim().is_empty()||src.source_type.trim().is_empty()||src.provenance_ref.trim().is_empty()||!valid_digest(&src.source_digest){
            return Some("source_reference_malformed".into());
        }
        let observed=match &src.observed_at{
            Some(v)=>match parse_utc(v){Some(t)=>t,None=>return Some("source_observation_time_noncanonical".into())},
            None=>if src.observation_time_unknown_reason.as_ref().map_or(true, |r|r.trim().is_empty()){return Some("source_observation_time_unknown_without_reason".into())}else{return Some("source_observation_time_unknown".into())},
        };
        if observed>now{return Some("source_observation_time_in_future".into());}
        if let Some(until)=&src.valid_until{
            let Some(t)=parse_utc(until) else{return Some("source_validity_time_noncanonical".into())};
            if t<=observed{return Some("source_validity_interval_invalid".into());}
            if now>=t{return Some("source_reference_expired".into());}
        }
    }
    None
}

/// Normalize premises without promoting assumptions or hypotheses to facts.
/// Every input premise appears exactly once in either normalized or unresolved output.
pub fn evaluate_premise_model(input:&PremiseModelInput,policy:&PremiseModelPolicy,now:u64)->PremiseModelOutput{
    let provenance_digest=canonical(&input.provenance).map(|b|digest(&b)).unwrap_or_default();
    let version_digest=canonical(&input.version_bound_evidence).map(|b|digest(&b)).unwrap_or_default();
    let version_ok= !input.provenance.is_empty()&&!input.version_bound_evidence.is_empty()
        &&input.model_version==policy.expected_model_version
        &&input.normalization_policy_version==policy.normalization_policy_version
        &&!input.context_id.trim().is_empty()
        &&!input.premises.is_empty()&&input.premises.len()<=policy.maximum_premises;
    let mut ids=BTreeSet::new();
    let unique=input.premises.iter().all(|p|ids.insert(p.premise_id.as_str()));
    let mut normalized=Vec::new();let mut unresolved_items=Vec::new();
    let mut sorted:Vec<_>=input.premises.iter().collect();
    sorted.sort_by(|a,b|a.premise_id.cmp(&b.premise_id));
    if !version_ok||!unique{
        for p in &sorted{
            unresolved_items.push(unresolved(p,if !unique{"duplicate_premise_id"}else{"model_context_or_version_unresolved"}));
        }
    }else{
        for p in sorted{
            if p.context!=input.context_id{
                unresolved_items.push(unresolved(p,"premise_context_mismatch"));
            }else if let Some(reason)=source_problem(p,now){
                unresolved_items.push(unresolved(p,&reason));
            }else{
                let mut source_refs=p.source_refs.clone();
                source_refs.sort_by(|a,b|a.source_id.cmp(&b.source_id));
                normalized.push(NormalizedPremise{
                    premise_id:p.premise_id.clone(),normalized_statement:normalize_statement(&p.statement),
                    epistemic_status:p.epistemic_status,source_refs,
                    confidence:p.confidence,context:p.context.clone(),
                });
            }
        }
    }
    let complete=normalized.len()+unresolved_items.len()==input.premises.len()
        && normalized.iter().all(|n|!unresolved_items.iter().any(|u|u.premise_id==n.premise_id));
    let model_valid=version_ok&&unique&&complete;
    let digest_value=serde_json::json!({
        "context_id":input.context_id,"model_version":input.model_version,
        "normalization_policy_version":input.normalization_policy_version,
        "normalized_premises":normalized,"unresolved_premises":unresolved_items,
        "provenance_digest":provenance_digest,"version_bound_evidence_digest":version_digest
    });
    let premise_set_digest=if model_valid{canonical(&digest_value).map(|b|digest(&b))}else{None};
    PremiseModelOutput{
        model_id:format!("{}:{}",input.model_version,input.context_id),model_valid,premise_set_digest,
        normalized_premises:normalized.clone(),unresolved_premises:unresolved_items.clone(),
        evidence:PremiseModelEvidence{
            model_version:input.model_version.clone(),normalization_policy_version:input.normalization_policy_version.clone(),
            input_premise_count:input.premises.len() as u64,normalized_count:normalized.len() as u64,
            unresolved_count:unresolved_items.len() as u64,complete_disposition:complete,
            deterministic_ordering:true,canonical_serialization:true,provenance_digest,
            version_bound_evidence_digest:version_digest,
            decision_reason:if model_valid{"premise_set_normalized_with_explicit_unresolved_items"}else{"premise_model_rejected_or_unresolved"}.into(),
        },
        version_bound_evidence:input.version_bound_evidence.clone(),
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    fn fixture()->(PremiseModelInput,PremiseModelPolicy){
        let source=PremiseSourceReference{source_id:"source:official-001".into(),source_type:"document".into(),
            source_digest:"a".repeat(64),provenance_ref:"provenance:source-001".into(),
            observed_at:Some("2026-01-01T00:00:00Z".into()),observation_time_unknown_reason:None,valid_until:None};
        let input=PremiseModelInput{
            premises:vec![
                PremiseInput{premise_id:"p-002".into(),statement:"  The   sky is blue. ".into(),epistemic_status:EpistemicStatus::Fact,
                    source_refs:vec![source],source_unavailable_reason:None,confidence:Some(0.95),context:"ctx-1".into()},
                PremiseInput{premise_id:"p-001".into(),statement:"The meeting may be delayed".into(),epistemic_status:EpistemicStatus::Hypothesis,
                    source_refs:vec![],source_unavailable_reason:Some("no corroborating source".into()),confidence:Some(0.4),context:"ctx-1".into()},
            ],
            context_id:"ctx-1".into(),model_version:"premise-normalizer-1.1.0".into(),
            normalization_policy_version:"normalize-policy-1.1.0".into(),
            provenance:BTreeMap::from([("source".into(),serde_json::json!("synthetic"))]),
            version_bound_evidence:BTreeMap::from([("genome_digest".into(),serde_json::json!("b".repeat(64)))]),
        };
        (input,PremiseModelPolicy::new("premise-normalizer-1.1.0","normalize-policy-1.1.0",512))
    }
    #[test]fn normalizes_fact_and_preserves_unresolved_hypothesis(){
        let(i,p)=fixture();let o=evaluate_premise_model(&i,&p,1_767_225_600);
        assert!(o.model_valid);assert_eq!(o.normalized_premises.len(),1);assert_eq!(o.unresolved_premises.len(),1);
        assert_eq!(o.normalized_premises[0].normalized_statement,"The sky is blue.");
        assert_eq!(o.unresolved_premises[0].epistemic_status,EpistemicStatus::Hypothesis);
    }
    #[test]fn rejects_fact_without_source_and_duplicate_ids(){
        let(i,p)=fixture();let mut bad=i.clone();bad.premises[0].source_refs.clear();bad.premises[0].source_unavailable_reason=Some("missing".into());
        let o=evaluate_premise_model(&bad,&p,1_767_225_600);assert_eq!(o.normalized_premises.len(),0);assert_eq!(o.unresolved_premises.len(),2);
        let mut dup=i;dup.premises[1].premise_id="p-002".into();
        let o=evaluate_premise_model(&dup,&p,1_767_225_600);assert!(!o.model_valid);assert_eq!(o.unresolved_premises.len(),2);
    }
    #[test]fn rejects_future_or_expired_source_time(){
        let(i,p)=fixture();let mut bad=i.clone();bad.premises[0].source_refs[0].observed_at=Some("2027-01-01T00:00:00Z".into());
        let o=evaluate_premise_model(&bad,&p,1_767_225_600);assert_eq!(o.unresolved_premises.len(),2);
        let mut bad=i;bad.premises[0].source_refs[0].valid_until=Some("2026-01-02T00:00:00Z".into());
        let o=evaluate_premise_model(&bad,&p,1_767_225_600);assert_eq!(o.unresolved_premises.len(),2);
    }
}
