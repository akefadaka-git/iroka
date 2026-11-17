//! G03 inference evaluator: constrained non-executable rule DSL with reproducible derivations.
use crate::canonical_json;
use crate::EpistemicStatus;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InferencePremise {
    pub premise_id: String,
    pub epistemic_status: EpistemicStatus,
    pub confidence: Option<f64>,
    pub source_digest: String,
    pub context_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InferenceRule {
    pub rule_id: String,
    pub rule_version: String,
    pub rule_digest: String,
    pub conclusion_id: String,
    pub conclusion_template: String,
    pub antecedent_premise_ids: Vec<String>,
    pub allowed_epistemic_statuses: Vec<EpistemicStatus>,
    pub rule_expression: String,
    pub query_match: String,
    pub rule_confidence: f64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InferenceRulesInput {
    pub rules: Vec<InferenceRule>,
    pub premises: Vec<InferencePremise>,
    pub premise_set_digest: String,
    pub premise_model_version: String,
    pub query: String,
    pub context_id: String,
    pub rule_version: String,
    pub rule_set_digest: String,
    pub confidence_policy_version: String,
    pub evaluator_version: String,
    pub provenance: BTreeMap<String, Value>,
    pub version_bound_evidence: BTreeMap<String, Value>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferenceRulePolicy {
    rule_version: String,
    rule_set_digest: String,
    confidence_policy_version: String,
    evaluator_version: String,
    approved_rule_digests: BTreeMap<String, String>,
    permitted_axiom_rule_ids: BTreeSet<String>,
    maximum_rules: usize,
    maximum_steps: usize,
}
impl InferenceRulePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rule_version: String, rule_set_digest: String, confidence_policy_version: String,
        evaluator_version: String, approved_rule_digests: BTreeMap<String, String>,
        permitted_axiom_rule_ids: BTreeSet<String>, maximum_rules: usize, maximum_steps: usize,
    ) -> Self {
        Self { rule_version, rule_set_digest, confidence_policy_version, evaluator_version,
            approved_rule_digests, permitted_axiom_rule_ids, maximum_rules, maximum_steps }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DerivationStep {
    pub step_id: String,
    pub rule_id: String,
    pub rule_version: String,
    pub premise_ids: Vec<String>,
    pub rule_expression: String,
    pub intermediate_support: f64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InferenceConclusion {
    pub conclusion_id: String,
    pub statement: String,
    pub supporting_premise_ids: Vec<String>,
    pub applied_rule_ids: Vec<String>,
    pub confidence: f64,
    pub derivation_trace: Vec<DerivationStep>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnsupportedInferenceStep {
    pub step_id: String,
    pub rule_id: Option<String>,
    pub premise_ids: Vec<String>,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InferenceEvidence {
    pub query_digest: String,
    pub premise_set_digest: String,
    pub premise_model_version: String,
    pub rule_version: String,
    pub rule_set_digest: String,
    pub confidence_policy_version: String,
    pub evaluator_version: String,
    pub reproducibility_digest: String,
    pub provenance: BTreeMap<String, Value>,
    pub decision_reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InferenceRulesOutput {
    pub inference_id: String,
    pub conclusion_set: Vec<InferenceConclusion>,
    pub applied_rule_ids: Vec<String>,
    pub unsupported_steps: Vec<UnsupportedInferenceStep>,
    pub evidence: InferenceEvidence,
    pub version_bound_evidence: BTreeMap<String, Value>,
}
fn canonical<T:Serialize>(value:&T)->Option<Vec<u8>>{canonical_json(&serde_json::to_value(value).ok()?).ok()}
fn digest(bytes:&[u8])->String{format!("{:x}",Sha256::digest(bytes))}
fn rule_content_digest(rule:&InferenceRule)->Option<String>{
    let mut payload=rule.clone();payload.rule_digest.clear();
    let mut bytes=b"IROKA-RULE-DEFINITION-V1\0".to_vec();bytes.extend(canonical(&payload)?);Some(digest(&bytes))
}
fn rule_set_digest(rules:&[InferenceRule])->Option<String>{
    let mut entries:Vec<_>=rules.iter().map(|r|(r.rule_id.clone(),r.rule_digest.clone())).collect();
    entries.sort_by(|a,b|a.0.cmp(&b.0));
    let mut bytes=b"IROKA-RULE-SET-V1\0".to_vec();bytes.extend(canonical(&entries)?);Some(digest(&bytes))
}
fn query_digest(query:&str)->Option<String>{
    let mut bytes=b"IROKA-INFERENCE-QUERY-V1\0".to_vec();bytes.extend(canonical(&query)?);Some(digest(&bytes))
}
fn valid_digest(s:&str)->bool{s.len()==64&&s.bytes().all(|b|b.is_ascii_hexdigit()&&!b.is_ascii_uppercase())}
fn step_id(rule_id:&str)->String{format!("step:{}",digest(rule_id.as_bytes()))}
fn expected_expression(ids:&[String])->String{format!("AND({})",ids.join(","))}
fn unsupported(rule:&InferenceRule,reason:&str)->UnsupportedInferenceStep{
    UnsupportedInferenceStep{step_id:step_id(&rule.rule_id),rule_id:Some(rule.rule_id.clone()),
        premise_ids:rule.antecedent_premise_ids.clone(),reason:reason.into()}
}
fn evidence(input:&InferenceRulesInput,reason:&str)->InferenceEvidence{
    let query_digest=query_digest(&input.query).unwrap_or_default();
    let reproducibility_digest=canonical(&serde_json::json!({
        "query_digest":query_digest,"premise_set_digest":input.premise_set_digest,
        "premise_model_version":input.premise_model_version,"rule_version":input.rule_version,
        "rule_set_digest":input.rule_set_digest,"confidence_policy_version":input.confidence_policy_version,
        "evaluator_version":input.evaluator_version,"provenance":input.provenance,
        "version_bound_evidence":input.version_bound_evidence
    })).map(|b|digest(&b)).unwrap_or_default();
    InferenceEvidence{query_digest,premise_set_digest:input.premise_set_digest.clone(),
        premise_model_version:input.premise_model_version.clone(),rule_version:input.rule_version.clone(),
        rule_set_digest:input.rule_set_digest.clone(),confidence_policy_version:input.confidence_policy_version.clone(),
        evaluator_version:input.evaluator_version.clone(),reproducibility_digest,
        provenance:input.provenance.clone(),decision_reason:reason.into()}
}
fn empty_output(input:&InferenceRulesInput,reason:&str,unsupported_steps:Vec<UnsupportedInferenceStep>)->InferenceRulesOutput{
    let ev=evidence(input,reason);
    let inference_id=format!("inference:{}",ev.reproducibility_digest);
    InferenceRulesOutput{inference_id,conclusion_set:vec![],applied_rule_ids:vec![],unsupported_steps,
        evidence:ev,version_bound_evidence:input.version_bound_evidence.clone()}
}

/// Evaluate only a tiny declarative DSL: AXIOM or AND(premise_id,...).
/// No expressions are interpreted as code, scripts, templates or executable programs.
pub fn evaluate_inference_rules(input:&InferenceRulesInput,policy:&InferenceRulePolicy)->InferenceRulesOutput{
    if input.rules.is_empty()||input.rules.len()>policy.maximum_rules||input.premises.is_empty()
        ||input.query.trim().is_empty()||input.context_id.trim().is_empty()
        ||!valid_digest(&input.premise_set_digest)||!valid_digest(&input.rule_set_digest)
        ||input.provenance.is_empty()||input.version_bound_evidence.is_empty(){
        return empty_output(input,"required_input_missing_or_malformed",vec![]);
    }
    let computed_rule_set_digest=rule_set_digest(&input.rules);
    let computed_query_digest=query_digest(&input.query);
    let version_ok=input.rule_version==policy.rule_version&&input.rule_set_digest==policy.rule_set_digest
        &&computed_rule_set_digest.as_deref()==Some(input.rule_set_digest.as_str())
        &&computed_query_digest.as_deref()==input.version_bound_evidence.get("query_digest").and_then(Value::as_str)
        &&input.version_bound_evidence.get("rule_set_digest").and_then(Value::as_str)==Some(input.rule_set_digest.as_str())
        &&input.version_bound_evidence.get("evaluator_version").and_then(Value::as_str)==Some(input.evaluator_version.as_str())
        &&input.confidence_policy_version==policy.confidence_policy_version
        &&input.evaluator_version==policy.evaluator_version
        &&input.version_bound_evidence.get("premise_set_digest").and_then(Value::as_str)==Some(input.premise_set_digest.as_str())
        &&input.version_bound_evidence.get("premise_model_version").and_then(Value::as_str)==Some(input.premise_model_version.as_str());
    let mut premise_map=BTreeMap::new();
    for p in &input.premises{
        if p.premise_id.trim().is_empty()||p.context_id!=input.context_id||!valid_digest(&p.source_digest)
            ||p.confidence.map_or(true, |v|!v.is_finite()||!(0.0..=1.0).contains(&v))
            ||premise_map.insert(p.premise_id.as_str(),p).is_some(){
            return empty_output(input,"premise_set_invalid_or_ambiguous",vec![]);
        }
    }
    let mut rule_ids=BTreeSet::new();
    if input.rules.iter().any(|r|!rule_ids.insert(r.rule_id.as_str())){
        return empty_output(input,"duplicate_rule_id",vec![]);
    }
    let mut rejected=Vec::new();
    let mut candidates:BTreeMap<String,Vec<(InferenceRule,DerivationStep,f64)>>=BTreeMap::new();
    for rule in &input.rules{
        let reason=if !version_ok{"rule_or_evidence_version_mismatch"}
        else if rule_content_digest(rule).as_deref()!=Some(rule.rule_digest.as_str()){"rule_content_digest_mismatch"}
        else if rule.rule_version!=policy.rule_version{"mixed_or_stale_rule_version"}
        else if policy.approved_rule_digests.get(&rule.rule_id)!=Some(&rule.rule_digest){"rule_not_in_immutable_registry"}
        else if rule.rule_id.trim().is_empty()||rule.conclusion_id.trim().is_empty()||rule.conclusion_template.trim().is_empty(){"malformed_rule"}
        else if rule.query_match!=input.query{"query_not_matched_exactly"}
        else if rule.rule_confidence.is_nan()||!rule.rule_confidence.is_finite()||!(0.0..=1.0).contains(&rule.rule_confidence){"invalid_rule_confidence"}
        else if rule.allowed_epistemic_statuses.is_empty()||rule.allowed_epistemic_statuses.contains(&EpistemicStatus::Unknown){"invalid_epistemic_status_policy"}
        else if rule.antecedent_premise_ids.is_empty()&&!(rule.rule_expression=="AXIOM"&&policy.permitted_axiom_rule_ids.contains(&rule.rule_id)){"zero_antecedent_rule_not_approved_axiom"}
        else if !rule.antecedent_premise_ids.is_empty()&&(rule.antecedent_premise_ids.windows(2).any(|w|w[0]>=w[1])||rule.rule_expression!=expected_expression(&rule.antecedent_premise_ids)){"rule_expression_not_in_constrained_grammar"}
        else if rule.conclusion_template.contains("{{")||rule.conclusion_template.contains("}}"){"executable_or_ambiguous_template_syntax"}
        else {""};
        if !reason.is_empty(){rejected.push(unsupported(rule,reason));continue;}
        let mut support=rule.rule_confidence;let mut failed=None;
        for id in &rule.antecedent_premise_ids{
            match premise_map.get(id.as_str()){
                None=>{failed=Some("antecedent_premise_missing");break;}
                Some(p) if !rule.allowed_epistemic_statuses.contains(&p.epistemic_status)=>{failed=Some("premise_epistemic_status_not_admissible");break;}
                Some(p)=>{support=support.min(p.confidence.unwrap_or(0.0));}
            }
        }
        if let Some(reason)=failed{rejected.push(unsupported(rule,reason));continue;}
        let trace=DerivationStep{step_id:step_id(&rule.rule_id),rule_id:rule.rule_id.clone(),
            rule_version:rule.rule_version.clone(),premise_ids:rule.antecedent_premise_ids.clone(),
            rule_expression:rule.rule_expression.clone(),intermediate_support:support};
        candidates.entry(rule.conclusion_id.clone()).or_default().push((rule.clone(),trace,support));
    }
    let mut conclusions=Vec::new();let mut applied=BTreeSet::new();
    for (conclusion_id,group) in candidates{
        let statements:BTreeSet<_>=group.iter().map(|(r,_,_)|r.conclusion_template.as_str()).collect();
        if statements.len()!=1{
            for (r,_,_) in group{rejected.push(unsupported(&r,"conflicting_conclusion_templates"));}
            continue;
        }
        let statement=group[0].0.conclusion_template.clone();
        let mut premise_ids=BTreeSet::new();let mut rule_ids=BTreeSet::new();let mut traces=Vec::new();
        let mut confidence=1.0f64;
        for (rule,trace,support) in group{
            confidence=confidence.min(support);
            for id in &rule.antecedent_premise_ids{premise_ids.insert(id.clone());}
            rule_ids.insert(rule.rule_id.clone());applied.insert(rule.rule_id);traces.push(trace);
        }
        traces.sort_by(|a,b|a.rule_id.cmp(&b.rule_id));
        conclusions.push(InferenceConclusion{conclusion_id,statement,
            supporting_premise_ids:premise_ids.into_iter().collect(),
            applied_rule_ids:rule_ids.into_iter().collect(),confidence,derivation_trace:traces});
    }
    if rejected.len()>policy.maximum_steps{
        return empty_output(input,"unsupported_step_limit_exceeded",vec![UnsupportedInferenceStep{
            step_id:"step:limit".into(),rule_id:None,premise_ids:vec![],reason:"unsupported_step_limit_exceeded".into()
        }]);
    }
    rejected.sort_by(|a,b|a.step_id.cmp(&b.step_id));
    conclusions.sort_by(|a,b|a.conclusion_id.cmp(&b.conclusion_id));
    let ev=evidence(input,if rejected.is_empty(){"all_applicable_rules_resolved"}else{"conclusions_and_explicit_unsupported_steps"});
    let inference_id=format!("inference:{}",ev.reproducibility_digest);
    InferenceRulesOutput{inference_id,conclusion_set:conclusions,applied_rule_ids:applied.into_iter().collect(),
        unsupported_steps:rejected,evidence:ev,version_bound_evidence:input.version_bound_evidence.clone()}
}

#[cfg(test)]
mod tests{
    use super::*;
    fn fixture()->(InferenceRulesInput,InferenceRulePolicy){
        let premise=InferencePremise{premise_id:"p-1".into(),epistemic_status:EpistemicStatus::Fact,
            confidence:Some(0.9),source_digest:"a".repeat(64),context_id:"ctx-1".into()};
        let rule=InferenceRule{rule_id:"r-1".into(),rule_version:"rules-1.1".into(),rule_digest:"b".repeat(64),
            conclusion_id:"c-1".into(),conclusion_template:"The source supports conclusion A".into(),
            antecedent_premise_ids:vec!["p-1".into()],allowed_epistemic_statuses:vec![EpistemicStatus::Fact],
            rule_expression:"AND(p-1)".into(),query_match:"Is conclusion A supported?".into(),rule_confidence:0.95};
        let mut rule=rule;rule.rule_digest=rule_content_digest(&rule).unwrap();
        let rules_digest=rule_set_digest(std::slice::from_ref(&rule)).unwrap();
        let query_digest=query_digest("Is conclusion A supported?").unwrap();
        let input=InferenceRulesInput{rules:vec![rule.clone()],premises:vec![premise],premise_set_digest:"c".repeat(64),
            premise_model_version:"premise-model-1.1".into(),query:"Is conclusion A supported?".into(),context_id:"ctx-1".into(),
            rule_version:"rules-1.1".into(),rule_set_digest:rules_digest.clone(),confidence_policy_version:"min-support-1.0".into(),
            evaluator_version:"inference-evaluator-1.1".into(),provenance:BTreeMap::from([("rules".into(),serde_json::json!("registry"))]),
            version_bound_evidence:BTreeMap::from([
                ("premise_set_digest".into(),serde_json::json!("c".repeat(64))),
                ("premise_model_version".into(),serde_json::json!("premise-model-1.1")),
                ("rule_set_digest".into(),serde_json::json!(rules_digest)),
                ("query_digest".into(),serde_json::json!(query_digest)),
                ("evaluator_version".into(),serde_json::json!("inference-evaluator-1.1"))
            ])};
        let policy=InferenceRulePolicy::new("rules-1.1".into(),rules_digest,"min-support-1.0".into(),
            "inference-evaluator-1.1".into(),BTreeMap::from([("r-1".into(),rule.rule_digest.clone())]),BTreeSet::new(),32,128);
        (input,policy)
    }
    fn refresh_bindings(i:&mut InferenceRulesInput,p:&mut InferenceRulePolicy){
        for rule in &mut i.rules { rule.rule_digest=rule_content_digest(rule).unwrap(); }
        let rd=rule_set_digest(&i.rules).unwrap();
        i.rule_set_digest=rd.clone();p.rule_set_digest=rd.clone();
        p.approved_rule_digests=i.rules.iter().map(|r|(r.rule_id.clone(),r.rule_digest.clone())).collect();
        i.version_bound_evidence.insert("rule_set_digest".into(),serde_json::json!(rd));
        i.version_bound_evidence.insert("query_digest".into(),serde_json::json!(query_digest(&i.query).unwrap()));
        i.version_bound_evidence.insert("evaluator_version".into(),serde_json::json!(i.evaluator_version));
    }
    #[test]fn derives_only_from_registered_exact_version_rule(){
        let(i,p)=fixture();let o=evaluate_inference_rules(&i,&p);
        assert_eq!(o.conclusion_set.len(),1);assert_eq!(o.applied_rule_ids,vec!["r-1"]);
        assert_eq!(o.conclusion_set[0].confidence,0.9);assert_eq!(o.conclusion_set[0].derivation_trace.len(),1);
    }
    #[test]fn rejects_unapproved_axiom_and_expression_code(){
        let(mut i,mut p)=fixture();i.rules[0].antecedent_premise_ids.clear();i.rules[0].rule_expression="AXIOM".into();
        refresh_bindings(&mut i,&mut p);
        let o=evaluate_inference_rules(&i,&p);assert!(o.conclusion_set.is_empty());assert!(!o.unsupported_steps.is_empty());
        let(mut i,mut p)=fixture();i.rules[0].rule_expression="std::process::exit(1)".into();
        refresh_bindings(&mut i,&mut p);
        let o=evaluate_inference_rules(&i,&p);assert!(o.conclusion_set.is_empty());assert!(!o.unsupported_steps.is_empty());
    }
    #[test]fn preserves_unsupported_premises_and_conflicts(){
        let(mut i,p)=fixture();i.premises[0].epistemic_status=EpistemicStatus::Hypothesis;
        let o=evaluate_inference_rules(&i,&p);assert!(o.conclusion_set.is_empty());assert_eq!(o.unsupported_steps[0].reason,"premise_epistemic_status_not_admissible");
        let(mut i,mut p)=fixture();i.rules[0].conclusion_template="Different conclusion".into();
        let mut second=i.rules[0].clone();second.rule_id="r-2".into();second.conclusion_template="Conflicting conclusion".into();
        i.rules.push(second);refresh_bindings(&mut i,&mut p);
        let o=evaluate_inference_rules(&i,&p);assert!(o.conclusion_set.is_empty());assert_eq!(o.unsupported_steps.len(),2);
    }
}
