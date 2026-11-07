//! IGACMS v1.0 validator, fingerprint, attestation, genesis and evolution contracts.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const EMBEDDED: &[u8] = include_bytes!("../igacms/genome-v1.0.0.json");
const DOMAINS: [&str; 8] = ["identity","authority","evidence","assurance","reasoning","security","execution","evolution"];
const CHROMOSOMES: [&str; 12] = ["G01","G02","G03","G04","G05","G06","G07","G08","G09","G10","G11","G12"];
const ATTESTATION_DOMAIN: &str = "IROKA-IGACMS-ATTESTATION-V1";

#[derive(Debug,Clone,PartialEq,Eq)]
pub enum IgacmsError { Malformed, UnsupportedNumber, Identity, MissingDomain(String), Chromosome, Gene, Marker, DuplicateId(String), Dependency, DependencyCycle, UnknownRoot, RevokedRoot, RootExpired, Signature, Genesis, Epoch, MutationDenied, HistoricalEvidence }

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct Fingerprint { pub digest_hex:String, pub canonical_bytes:Vec<u8>, pub algorithm:&'static str, pub canonicalization:&'static str }
#[derive(Debug,Clone)]
pub struct ValidatedGenome { pub value:Value, pub fingerprint:Fingerprint }

fn canonical(value:&Value,out:&mut Vec<u8>)->Result<(),IgacmsError>{
    match value {
        Value::Null=>out.extend_from_slice(b"null"),
        Value::Bool(v)=>out.extend_from_slice(if *v {b"true"} else {b"false"}),
        Value::Number(n)=>{if n.is_i64()||n.is_u64(){out.extend_from_slice(n.to_string().as_bytes())}else{return Err(IgacmsError::UnsupportedNumber)}},
        Value::String(s)=>out.extend_from_slice(serde_json::to_string(s).map_err(|_|IgacmsError::Malformed)?.as_bytes()),
        Value::Array(a)=>{out.push(b'[');for(i,v)in a.iter().enumerate(){if i>0{out.push(b',')}canonical(v,out)?}out.push(b']')},
        Value::Object(m)=>{let mut e:Vec<_>=m.iter().collect();e.sort_by(|a,b|a.0.encode_utf16().cmp(b.0.encode_utf16()));out.push(b'{');for(i,(k,v))in e.iter().enumerate(){if i>0{out.push(b',')}out.extend_from_slice(serde_json::to_string(k).map_err(|_|IgacmsError::Malformed)?.as_bytes());out.push(b':');canonical(v,out)?}out.push(b'}')}
    } Ok(())
}
pub fn canonical_json(v:&Value)->Result<Vec<u8>,IgacmsError>{let mut b=Vec::new();canonical(v,&mut b)?;Ok(b)}
fn text<'a>(v:&'a Value,k:&str)->Result<&'a str,IgacmsError>{v.get(k).and_then(Value::as_str).filter(|s|!s.trim().is_empty()).ok_or(IgacmsError::Malformed)}
fn unique<'a>(a:&'a [Value],k:&str)->Result<BTreeSet<&'a str>,IgacmsError>{let mut s=BTreeSet::new();for v in a{let id=text(v,k)?;if !s.insert(id){return Err(IgacmsError::DuplicateId(id.into()))}}Ok(s)}
fn graph_is_acyclic(g:&[(String,Vec<String>)])->Result<(),IgacmsError>{
    fn visit(n:&str,m:&BTreeMap<String,Vec<String>>,active:&mut BTreeSet<String>,done:&mut BTreeSet<String>)->Result<(),IgacmsError>{
        if done.contains(n){return Ok(())}if !active.insert(n.into()){return Err(IgacmsError::DependencyCycle)}
        for d in m.get(n).ok_or(IgacmsError::Dependency)?{if !m.contains_key(d){return Err(IgacmsError::Dependency)}visit(d,m,active,done)?}
        active.remove(n);done.insert(n.into());Ok(())
    }
    let m:BTreeMap<_,_>=g.iter().cloned().collect();let(mut a,mut d)=(BTreeSet::new(),BTreeSet::new());
    for n in m.keys(){visit(n,&m,&mut a,&mut d)?}Ok(())
}
pub fn validate_genome(bytes:&[u8])->Result<ValidatedGenome,IgacmsError>{
    let v:Value=serde_json::from_slice(bytes).map_err(|_|IgacmsError::Malformed)?;
    if text(&v,"specification_id")?!="IGACMS"||text(&v,"specification_version")?!="1.0.0"||text(v.get("dna").ok_or(IgacmsError::Identity)?,"id")?!="iroka.dna"||text(v.get("genome").ok_or(IgacmsError::Identity)?,"id")?!="IROKA_ZERO_GENOME"{return Err(IgacmsError::Identity)}
    let domains=v["historical_domains"].as_array().ok_or(IgacmsError::Malformed)?;
    for d in DOMAINS{if !domains.iter().any(|x|x.as_str()==Some(d)){return Err(IgacmsError::MissingDomain(d.into()))}}
    let c=v["chromosomes"].as_array().ok_or(IgacmsError::Chromosome)?;
    if c.len()!=12{return Err(IgacmsError::Chromosome)}let ids=unique(c,"id")?;
    for id in CHROMOSOMES{if !ids.contains(id){return Err(IgacmsError::Chromosome)}}
    for x in c{let gs=x["core_genes"].as_array().ok_or(IgacmsError::Gene)?;if gs.len()!=3{return Err(IgacmsError::Gene)}}
    let genes=v["genes"].as_array().ok_or(IgacmsError::Gene)?;
    if genes.len()!=36{ return Err(IgacmsError::Gene)}unique(genes,"id")?;
    for g in genes{for k in ["chromosome_id","version","purpose","input_schema","output_schema","failure_semantics","compatibility_policy","owner","review_state"]{text(g,k)?}if !ids.contains(text(g,"chromosome_id")?){return Err(IgacmsError::Gene)}}
    let p=v["principles"].as_array().ok_or(IgacmsError::Malformed)?;let i=v["invariants"].as_array().ok_or(IgacmsError::Malformed)?;
    if p.len()!=14||i.len()!=14{return Err(IgacmsError::Identity)}unique(p,"id")?;unique(i,"id")?;
    let m=v["markers"].as_array().ok_or(IgacmsError::Marker)?;if m.len()!=27{return Err(IgacmsError::Marker)}unique(m,"id")?;
    let mut edges=Vec::new();for n in v["dependency_graph"].as_array().ok_or(IgacmsError::Dependency)?{
        let id=text(n,"node")?.to_owned();let ds=n["depends_on"].as_array().ok_or(IgacmsError::Dependency)?.iter().map(|x|x.as_str().map(str::to_owned).ok_or(IgacmsError::Dependency)).collect::<Result<Vec<_>,_>>()?;edges.push((id,ds));
    }if edges.len()!=12{return Err(IgacmsError::Dependency)}graph_is_acyclic(&edges)?;
    let bytes=canonical_json(&v)?;let digest=Sha256::digest(&bytes);
    Ok(ValidatedGenome{value:v,fingerprint:Fingerprint{digest_hex:format!("{:x}",digest),canonical_bytes:bytes,algorithm:"SHA-256",canonicalization:"JCS-compatible integer-only profile"}})
}
pub fn validate_embedded_baseline()->Result<Fingerprint,IgacmsError>{Ok(validate_genome(EMBEDDED)?.fingerprint)}

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct TrustedRoot{pub key_id:String,pub public_key:[u8;32],pub not_before:u64,pub not_after:u64,pub revoked:bool,pub provenance:String}
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct Attestation{pub envelope_type:String,pub version:String,pub digest:String,pub epoch:u64,pub key_id:String,pub signature:Vec<u8>}
impl Attestation{fn bytes(&self)->Vec<u8>{format!("{}|{}|{}|{}|{}|{}",ATTESTATION_DOMAIN,self.envelope_type,self.version,self.digest,self.epoch,self.key_id).into_bytes()}}
pub fn sign_fingerprint(fp:&Fingerprint,epoch:u64,key_id:&str,key:&SigningKey)->Attestation{
    let mut a=Attestation{envelope_type:"iroka.igacms.attestation".into(),version:"1.0.0".into(),digest:fp.digest_hex.clone(),epoch,key_id:key_id.into(),signature:Vec::new()};
    a.signature=key.sign(&a.bytes()).to_bytes().to_vec();a
}
pub fn verify_attestation(a:&Attestation,roots:&[TrustedRoot],now:u64)->Result<(),IgacmsError>{
    let r=roots.iter().find(|r|r.key_id==a.key_id).ok_or(IgacmsError::UnknownRoot)?;
    if r.revoked{return Err(IgacmsError::RevokedRoot)}if now<r.not_before||now>=r.not_after||r.provenance.trim().is_empty(){return Err(IgacmsError::RootExpired)}
    let k=VerifyingKey::from_bytes(&r.public_key).map_err(|_|IgacmsError::UnknownRoot)?;
    let s=Signature::from_slice(&a.signature).map_err(|_|IgacmsError::Signature)?;
    k.verify(&a.bytes(),&s).map_err(|_|IgacmsError::Signature)
}
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct Genesis{pub dna_id:String,pub genome_id:String,pub digest:String,pub epoch:u64,pub parent:Option<String>,pub owner_approval_ref:String,pub trust_root_key_ids:Vec<String>,pub attestation:Attestation,pub audit_refs:Vec<String>}
pub fn verify_genesis(g:&Genesis,fp:&Fingerprint,roots:&[TrustedRoot],now:u64)->Result<(),IgacmsError>{
    if g.dna_id!="iroka.dna"||g.genome_id!="IROKA_ZERO_GENOME"||g.digest!=fp.digest_hex||g.epoch!=0||g.parent.is_some()||g.owner_approval_ref.trim().is_empty()||g.audit_refs.is_empty()||!g.trust_root_key_ids.contains(&g.attestation.key_id){return Err(IgacmsError::Genesis)}
    verify_attestation(&g.attestation,roots,now)
}
pub fn verify_epoch_transition(epoch:u64,digest:&str,next:u64,parent:Option<&str>)->Result<(),IgacmsError>{if next!=epoch.saturating_add(1)||parent!=Some(digest){Err(IgacmsError::Epoch)}else{Ok(())}}

#[derive(Debug,Clone,Copy,PartialEq,Eq)]pub enum MutationClass{M0,M1,M2,M3,M4,M5}
#[derive(Debug,Clone,Default,PartialEq,Eq)]pub struct MutationEvidence{pub owner_approved:bool,pub independent_review:bool,pub compatibility_checked:bool,pub migration_rollback_ready:bool,pub dual_control:bool,pub canonical_diff:bool}
pub fn authorize_mutation(c:MutationClass,e:&MutationEvidence)->Result<(),IgacmsError>{
    let ok=match c{MutationClass::M0=>e.canonical_diff,MutationClass::M1=>e.canonical_diff&&e.independent_review,MutationClass::M2=>e.compatibility_checked&&e.independent_review,MutationClass::M3=>e.independent_review&&e.migration_rollback_ready&&e.owner_approved,MutationClass::M4=>e.owner_approved&&e.independent_review&&e.migration_rollback_ready,MutationClass::M5=>e.owner_approved&&e.independent_review&&e.migration_rollback_ready&&e.dual_control};
    if ok{Ok(())}else{Err(IgacmsError::MutationDenied)}
}
#[derive(Debug,Clone,PartialEq,Eq)]pub struct HistoricalArtifact{pub id:String,pub commit:String,pub blob_sha:String,pub bytes:Vec<u8>}
#[derive(Debug,Clone,PartialEq,Eq)]pub struct MigrationEvidence{pub id:String,pub source_commit:String,pub source_blob_sha:String,pub digest:String,pub disposition:String}
pub fn preserve_historical(a:&HistoricalArtifact)->Result<MigrationEvidence,IgacmsError>{
    if a.id.is_empty()||a.commit.is_empty()||a.blob_sha.is_empty()||a.bytes.is_empty(){return Err(IgacmsError::HistoricalEvidence)}
    let d=Sha256::digest(&a.bytes);Ok(MigrationEvidence{id:a.id.clone(),source_commit:a.commit.clone(),source_blob_sha:a.blob_sha.clone(),digest:format!("{:x}",d),disposition:if a.id=="DNA-045"{"EXTENSION-REVIEW"}else{"RETAIN-HISTORICAL"}.into()})
}
pub fn cross_chromosome_invariants()->&'static [&'static str]{&[
"G01 identity never implies G02 authority","G02 authority never implies G09 authorization","G07 capability never implies permission for a specific G09 effect","G08 orchestration never creates or broadens authority","G03 inference never silently upgrades G04/G06 evidence","G05 persistence never converts uncertain information into verified truth","G06 external input is untrusted by default","G09 execution never creates authority and must produce an attributable receipt","G10 learning can propose but cannot approve constitutional mutation","G11 assurance evidence is not self-authenticating","G12 evolution preserves ancestry and rejects unapproved rollback","No chromosome may bypass G11 validation for a protected constitutional transition"]}

#[cfg(test)]mod tests{
use super::*;use ed25519_dalek::SigningKey;
#[test]fn validates_all_twelve_and_reasoning_domain(){let f=validate_embedded_baseline().unwrap();assert_eq!(f.algorithm,"SHA-256");}
#[test]fn rejects_missing_reasoning(){let mut v:Value=serde_json::from_slice(EMBEDDED).unwrap();v["historical_domains"]=Value::Array(v["historical_domains"].as_array().unwrap().iter().filter(|x|x.as_str()!=Some("reasoning")).cloned().collect());assert!(matches!(validate_genome(&serde_json::to_vec(&v).unwrap()),Err(IgacmsError::MissingDomain(_))));}
#[test]fn rejects_duplicate_gene_ids(){let mut v:Value=serde_json::from_slice(EMBEDDED).unwrap();v["genes"][1]=v["genes"][0].clone();assert!(matches!(validate_genome(&serde_json::to_vec(&v).unwrap()),Err(IgacmsError::DuplicateId(_))));}
#[test]fn rejects_dependency_cycle(){let mut v:Value=serde_json::from_slice(EMBEDDED).unwrap();v["dependency_graph"][0]["depends_on"]=serde_json::json!(["G02"]);v["dependency_graph"][1]["depends_on"]=serde_json::json!(["G01"]);assert_eq!(validate_genome(&serde_json::to_vec(&v).unwrap()).unwrap_err(),IgacmsError::DependencyCycle);}
#[test]fn verifies_ed25519_and_revocation(){let fp=validate_embedded_baseline().unwrap();let key=SigningKey::from_bytes(&[9u8;32]);let a=sign_fingerprint(&fp,0,"root",&key);let r=TrustedRoot{key_id:"root".into(),public_key:key.verifying_key().to_bytes(),not_before:1,not_after:99,revoked:false,provenance:"test".into()};assert!(verify_attestation(&a,&[r.clone()],50).is_ok());let mut revoked=r;revoked.revoked=true;assert_eq!(verify_attestation(&a,&[revoked],50),Err(IgacmsError::RevokedRoot));}
#[test]fn mutation_requires_owner_and_independent_review(){assert_eq!(authorize_mutation(MutationClass::M4,&MutationEvidence::default()),Err(IgacmsError::MutationDenied));let e=MutationEvidence{owner_approved:true,independent_review:true,migration_rollback_ready:true,dual_control:true,..Default::default()};assert!(authorize_mutation(MutationClass::M5,&e).is_ok());}
#[test]fn preserves_dna045_outside_genesis(){let a=HistoricalArtifact{id:"DNA-045".into(),commit:"abc".into(),blob_sha:"def".into(),bytes:b"immutable".to_vec()};assert_eq!(preserve_historical(&a).unwrap().disposition,"EXTENSION-REVIEW");}
#[test]fn rejects_epoch_rollback(){assert_eq!(verify_epoch_transition(1,"d",1,None),Err(IgacmsError::Epoch));assert!(verify_epoch_transition(1,"d",2,Some("d")).is_ok());}
}