//! Durable G05 consent and organizational reviewer registries.
//! Consent is granted by a G01-verified subject, scoped to a Kernel-resolved
//! tenant and authorized by G02. Reviewer designation is G02-authorized and
//! the target identity/key binding is verified by G01. Approval proof
//! cryptography remains in G01; this registry enforces current designation
//! and one-time use. SQLite is single-node only.

use std::path::Path;
use std::sync::{Arc, Mutex};
use iroka_kernel::{TenantContext, VerifiedPrincipal};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json;
use sha2::Digest;
use crate::{AuthorizationRequest, Classification, DesignatedReviewerAuthority,
    DurableApprovalReceipt, EpisodicConsentAuthority, G02AuthorizationAuthority,
    G05Error, Operation, Purpose};

#[derive(Clone)]
pub struct SqliteG05AuthorityRegistry { connection: Arc<Mutex<Connection>> }

impl SqliteG05AuthorityRegistry {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, G05Error> {
        let c = Connection::open(path).map_err(|_| G05Error::AuthorityUnavailable)?;
        Self::from_connection(c)
    }
    pub fn open_in_memory() -> Result<Self, G05Error> {
        let c = Connection::open_in_memory().map_err(|_| G05Error::AuthorityUnavailable)?;
        Self::from_connection(c)
    }
    fn from_connection(c: Connection) -> Result<Self, G05Error> {
        c.busy_timeout(std::time::Duration::from_secs(5)).map_err(|_| G05Error::AuthorityUnavailable)?;
        c.execute_batch("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
          CREATE TABLE IF NOT EXISTS g05_episodic_consents(
            consent_ref TEXT PRIMARY KEY, tenant_ref TEXT NOT NULL, subject_ref TEXT NOT NULL,
            purpose TEXT NOT NULL, grant_issuer TEXT NOT NULL, grant_credential_id TEXT NOT NULL,
            granted_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER,
            version INTEGER NOT NULL CHECK(version>0), action_ref TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS g05_consent_scope ON g05_episodic_consents(tenant_ref,subject_ref,purpose);
          CREATE TABLE IF NOT EXISTS g05_reviewer_designations(
            designation_ref TEXT PRIMARY KEY, tenant_ref TEXT NOT NULL, organization_ref TEXT NOT NULL,
            reviewer_ref TEXT NOT NULL, reviewer_key_ref TEXT NOT NULL, designated_by TEXT NOT NULL,
            version INTEGER NOT NULL CHECK(version>0), valid_from INTEGER NOT NULL,
            valid_until INTEGER NOT NULL, created_at INTEGER NOT NULL, revoked_at INTEGER,
            UNIQUE(tenant_ref,organization_ref,reviewer_ref,version));
          CREATE INDEX IF NOT EXISTS g05_reviewer_scope ON g05_reviewer_designations
            (tenant_ref,organization_ref,reviewer_ref,version);
          CREATE TABLE IF NOT EXISTS g05_consumed_reviewer_approvals(
            approval_ref TEXT PRIMARY KEY, receipt_digest BLOB NOT NULL CHECK(length(receipt_digest)=32),
            designation_ref TEXT NOT NULL, designation_version INTEGER NOT NULL, consumed_at INTEGER NOT NULL);")
          .map_err(|_| G05Error::AuthorityUnavailable)?;
        Ok(Self { connection: Arc::new(Mutex::new(c)) })
    }

    /// Explicit authenticated user action only; do not call from passive signup.
    pub fn grant_episodic_consent<G: G02AuthorizationAuthority>(
        &self, actor: &VerifiedPrincipal, tenant: &TenantContext, purpose: Purpose,
        consent_ref: &str, action_ref: &str, expires_at: u64, now: u64,
        max_ttl_secs: u64, g02: &G,
    ) -> Result<(), G05Error> {
        if actor.subject()!=tenant.subject() || consent_ref.trim().is_empty()
            || action_ref.trim().is_empty() || expires_at<=now || max_ttl_secs==0
            || expires_at.saturating_sub(now)>max_ttl_secs { return Err(G05Error::MalformedRecord); }
        let req = AuthorizationRequest { operation: Operation::GrantEpisodicConsent,
            principal_ref: actor.subject().into(), tenant_ref: tenant.tenant_id().into(),
            subject_ref: actor.subject().into(), purpose, classification: Classification::Internal,
            memory_id: None, recipient_refs: Vec::new(), correlation_ref: action_ref.into() };
        g02.authorize_g05(&req)?;
        let mut c=self.connection.lock().map_err(|_|G05Error::AuthorityUnavailable)?;
        let tx=c.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|_|G05Error::AuthorityUnavailable)?;
        tx.execute("INSERT INTO g05_episodic_consents
          (consent_ref,tenant_ref,subject_ref,purpose,grant_issuer,grant_credential_id,granted_at,expires_at,revoked_at,version,action_ref)
          VALUES(?1,?2,?3,?4,?5,?6,?7,?8,NULL,1,?9)",
          params![consent_ref,tenant.tenant_id(),actor.subject(),purpose_key(purpose),actor.issuer(),
            actor.credential_id(),to_i64(now)?,to_i64(expires_at)?,action_ref])
          .map_err(|_|G05Error::DuplicateRecord)?;
        tx.commit().map_err(|_|G05Error::AuthorityUnavailable)
    }

    /// Withdrawal is self-only and permanent for this consent reference.
    pub fn withdraw_episodic_consent<G: G02AuthorizationAuthority>(
        &self, actor:&VerifiedPrincipal, tenant:&TenantContext, consent_ref:&str,
        action_ref:&str, now:u64, g02:&G,
    )->Result<(),G05Error>{
        if actor.subject()!=tenant.subject() || consent_ref.trim().is_empty() || action_ref.trim().is_empty()
            {return Err(G05Error::MalformedRecord);}
        let req=AuthorizationRequest{operation:Operation::WithdrawEpisodicConsent,
            principal_ref:actor.subject().into(),tenant_ref:tenant.tenant_id().into(),
            subject_ref:actor.subject().into(),purpose:Purpose::TaskContinuity,
            classification:Classification::Internal,memory_id:None,recipient_refs:Vec::new(),
            correlation_ref:action_ref.into()};
        g02.authorize_g05(&req)?;
        let c=self.connection.lock().map_err(|_|G05Error::AuthorityUnavailable)?;
        let n=c.execute("UPDATE g05_episodic_consents SET revoked_at=?1,version=version+1
          WHERE consent_ref=?2 AND tenant_ref=?3 AND subject_ref=?4 AND revoked_at IS NULL",
          params![to_i64(now)?,consent_ref,tenant.tenant_id(),actor.subject()])
          .map_err(|_|G05Error::AuthorityUnavailable)?;
        if n!=1{return Err(G05Error::EpisodicOptInRequired);} Ok(())
    }

    /// G02 authorizes the organizational action; G01 verifies that the target
    /// reviewer and key reference are a valid current identity/key binding.
    #[allow(clippy::too_many_arguments)]
    pub fn designate_reviewer<G,I>(&self, actor:&VerifiedPrincipal, tenant:&TenantContext,
        organization_ref:&str, reviewer_ref:&str, reviewer_key_ref:&str, designation_ref:&str,
        version:u64, valid_from:u64, valid_until:u64, now:u64, g02:&G, g01:&I,
    )->Result<(),G05Error>
    where G:G02AuthorizationAuthority,I:G01ReviewerProofAuthority {
        if actor.subject()!=tenant.subject() || organization_ref.trim().is_empty()
            || reviewer_ref.trim().is_empty() || reviewer_key_ref.trim().is_empty()
            || designation_ref.trim().is_empty() || version==0 || valid_from>now
            || valid_until<=now || valid_until<=valid_from {return Err(G05Error::MalformedRecord);}
        g01.validate_reviewer_key_binding(reviewer_ref,reviewer_key_ref,now)?;
        let req=AuthorizationRequest{operation:Operation::DesignateReviewer,
            principal_ref:actor.subject().into(),tenant_ref:tenant.tenant_id().into(),
            subject_ref:organization_ref.into(),purpose:Purpose::OrganizationalContext,
            classification:Classification::Confidential,memory_id:None,
            recipient_refs:vec![reviewer_ref.into()],correlation_ref:designation_ref.into()};
        g02.authorize_g05(&req)?;
        let mut c=self.connection.lock().map_err(|_|G05Error::AuthorityUnavailable)?;
        let tx=c.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|_|G05Error::AuthorityUnavailable)?;
        let high:Option<i64>=tx.query_row("SELECT MAX(version) FROM g05_reviewer_designations
          WHERE tenant_ref=?1 AND organization_ref=?2 AND reviewer_ref=?3",
          params![tenant.tenant_id(),organization_ref,reviewer_ref],|r|r.get(0))
          .map_err(|_|G05Error::AuthorityUnavailable)?;
        if high.is_some_and(|v|i64::try_from(version).map_or(true,|n|n<=v)){return Err(G05Error::VersionConflict);}
        tx.execute("INSERT INTO g05_reviewer_designations
          (designation_ref,tenant_ref,organization_ref,reviewer_ref,reviewer_key_ref,designated_by,version,valid_from,valid_until,created_at,revoked_at)
          VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,NULL)",
          params![designation_ref,tenant.tenant_id(),organization_ref,reviewer_ref,reviewer_key_ref,
            actor.subject(),to_i64(version)?,to_i64(valid_from)?,to_i64(valid_until)?,to_i64(now)?])
          .map_err(|_|G05Error::DuplicateRecord)?;
        tx.commit().map_err(|_|G05Error::AuthorityUnavailable)
    }

    pub fn revoke_reviewer_designation<G:G02AuthorizationAuthority>(&self,actor:&VerifiedPrincipal,
        tenant:&TenantContext,organization_ref:&str,designation_ref:&str,action_ref:&str,
        now:u64,g02:&G)->Result<(),G05Error>{
        if actor.subject()!=tenant.subject() || organization_ref.trim().is_empty()
            || designation_ref.trim().is_empty() || action_ref.trim().is_empty()
            {return Err(G05Error::MalformedRecord);}
        let req=AuthorizationRequest{operation:Operation::RevokeReviewerDesignation,
            principal_ref:actor.subject().into(),tenant_ref:tenant.tenant_id().into(),
            subject_ref:organization_ref.into(),purpose:Purpose::OrganizationalContext,
            classification:Classification::Confidential,memory_id:None,recipient_refs:Vec::new(),
            correlation_ref:action_ref.into()};
        g02.authorize_g05(&req)?;
        let c=self.connection.lock().map_err(|_|G05Error::AuthorityUnavailable)?;
        let n=c.execute("UPDATE g05_reviewer_designations SET revoked_at=?1
          WHERE designation_ref=?2 AND tenant_ref=?3 AND organization_ref=?4 AND revoked_at IS NULL",
          params![to_i64(now)?,designation_ref,tenant.tenant_id(),organization_ref])
          .map_err(|_|G05Error::AuthorityUnavailable)?;
        if n!=1{return Err(G05Error::ReviewerNotAuthorized);} Ok(())
    }

    fn active_designation(&self,tenant:&str,org:&str,reviewer:&str,now:u64)->Result<ReviewerDesignation,G05Error>{
        let c=self.connection.lock().map_err(|_|G05Error::AuthorityUnavailable)?;
        c.query_row("SELECT designation_ref,tenant_ref,organization_ref,reviewer_ref,reviewer_key_ref,version,valid_from,valid_until
          FROM g05_reviewer_designations WHERE tenant_ref=?1 AND organization_ref=?2 AND reviewer_ref=?3
          AND revoked_at IS NULL AND valid_from<=?4 AND valid_until>?4 ORDER BY version DESC LIMIT 1",
          params![tenant,org,reviewer,to_i64(now)?],|r|Ok(ReviewerDesignation{
            designation_ref:r.get(0)?,tenant_ref:r.get(1)?,organization_ref:r.get(2)?,
            reviewer_ref:r.get(3)?,reviewer_key_ref:r.get(4)?,version:r.get::<_,i64>(5)? as u64,
            valid_from:r.get::<_,i64>(6)? as u64,valid_until:r.get::<_,i64>(7)? as u64}))
          .optional().map_err(|_|G05Error::AuthorityUnavailable)?
          .ok_or(G05Error::ReviewerNotAuthorized)
    }

    fn consume_approval(&self,receipt:&DurableApprovalReceipt,d:&ReviewerDesignation,now:u64)->Result<(),G05Error>{
        let bytes=serde_json::to_vec(receipt).map_err(|_|G05Error::MalformedRecord)?;
        let digest:[u8;32]=sha2::Sha256::digest(&bytes).into();
        let mut c=self.connection.lock().map_err(|_|G05Error::AuthorityUnavailable)?;
        let tx=c.transaction_with_behavior(TransactionBehavior::Immediate).map_err(|_|G05Error::AuthorityUnavailable)?;
        let active:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM g05_reviewer_designations
          WHERE designation_ref=?1 AND tenant_ref=?2 AND organization_ref=?3 AND reviewer_ref=?4
          AND reviewer_key_ref=?5 AND version=?6 AND revoked_at IS NULL AND valid_from<=?7 AND valid_until>?7)",
          params![d.designation_ref,d.tenant_ref,d.organization_ref,d.reviewer_ref,d.reviewer_key_ref,
            to_i64(d.version)?,to_i64(now)?],|r|r.get(0)).map_err(|_|G05Error::AuthorityUnavailable)?;
        if !active{return Err(G05Error::ReviewerNotAuthorized);}
        let n=tx.execute("INSERT OR IGNORE INTO g05_consumed_reviewer_approvals
          (approval_ref,receipt_digest,designation_ref,designation_version,consumed_at) VALUES(?1,?2,?3,?4,?5)",
          params![receipt.approval_ref,digest.as_slice(),d.designation_ref,to_i64(d.version)?,to_i64(now)?])
          .map_err(|_|G05Error::AuthorityUnavailable)?;
        if n!=1{return Err(G05Error::ApprovalReplay);}
        tx.commit().map_err(|_|G05Error::AuthorityUnavailable)
    }
}

impl EpisodicConsentAuthority for SqliteG05AuthorityRegistry {
    fn verify_active_opt_in(&self,reference:&str,tenant:&str,subject:&str,purpose:Purpose,now:u64)->Result<(),G05Error>{
        let c=self.connection.lock().map_err(|_|G05Error::AuthorityUnavailable)?;
        let row:Option<(String,String,String,i64,i64,Option<i64>)>=c.query_row(
          "SELECT tenant_ref,subject_ref,purpose,granted_at,expires_at,revoked_at FROM g05_episodic_consents WHERE consent_ref=?1",
          [reference],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))
          .optional().map_err(|_|G05Error::AuthorityUnavailable)?;
        let(t,s,p,g,e,rev)=row.ok_or(G05Error::EpisodicOptInRequired)?;
        if t!=tenant||s!=subject||p!=purpose_key(purpose){return Err(G05Error::ConsentScopeMismatch);}
        if rev.is_some()||now<from_i64(g)?||now>=from_i64(e)?{return Err(G05Error::EpisodicOptInRequired);}
        Ok(())
    }
}

/// G01 identity/key boundary. Implementations resolve current key state and
/// revocation; proof_ref is only a selector into the trusted proof service.
pub trait G01ReviewerProofAuthority:Send+Sync{
    fn validate_reviewer_key_binding(&self,reviewer:&str,key_ref:&str,now:u64)->Result<(),G05Error>;
    fn verify_approval_proof(&self,receipt:&DurableApprovalReceipt,
        designation:&ReviewerDesignation,now:u64)->Result<(),G05Error>;
}
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct ReviewerDesignation{
    pub designation_ref:String,pub tenant_ref:String,pub organization_ref:String,
    pub reviewer_ref:String,pub reviewer_key_ref:String,pub version:u64,
    pub valid_from:u64,pub valid_until:u64,
}
pub struct RegistryDesignatedReviewerAuthority<P>{registry:SqliteG05AuthorityRegistry,g01:P}
impl<P> RegistryDesignatedReviewerAuthority<P>{
    pub fn new(registry:SqliteG05AuthorityRegistry,g01:P)->Self{Self{registry,g01}}
}
impl<P:G01ReviewerProofAuthority> DesignatedReviewerAuthority for RegistryDesignatedReviewerAuthority<P>{
    fn verify_designated_reviewer(&self,receipt:&DurableApprovalReceipt,org:&str,now:u64)->Result<(),G05Error>{
        if receipt.subject_ref!=org||receipt.expires_at<=now||receipt.issued_at>now
            ||receipt.expires_at<=receipt.issued_at{return Err(G05Error::ApprovalExpired);}
        let d=self.registry.active_designation(&receipt.tenant_ref,org,&receipt.reviewer_ref,now)?;
        if receipt.issued_at<d.valid_from||receipt.expires_at>d.valid_until{return Err(G05Error::ReviewerNotAuthorized);}
        self.g01.verify_approval_proof(receipt,&d,now)?;
        self.registry.consume_approval(receipt,&d,now)
    }
}

/// Concrete G02 adapter over the canonical Kernel composition. The credential,
/// tenant selector, genesis, verifier, Owner verifier and audit sink are
/// server-side session dependencies; request fields cannot replace them.
/// A policy requiring a separate Owner approval is denied here rather than
/// silently bypassed. Construct a fresh adapter per request with current time.
pub struct KernelG02AuthorizationAdapter<'a, R: iroka_kernel::RevocationChecker> {
    compact_credential: &'a str,
    expected_audience: &'a str,
    requested_tenant_id: &'a str,
    genesis: &'a iroka_kernel::VerifiedGenesis,
    credential_verifier: &'a iroka_kernel::Ed25519CredentialVerifier<R>,
    owner_verifier: &'a iroka_kernel::OwnerApprovalVerifier,
    audit_sink: &'a iroka_kernel::SqliteAuditSink,
    now: u64,
    max_membership_age_secs: u64,
}
impl<'a, R: iroka_kernel::RevocationChecker> KernelG02AuthorizationAdapter<'a, R> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(compact_credential: &'a str, expected_audience: &'a str,
        requested_tenant_id: &'a str, genesis: &'a iroka_kernel::VerifiedGenesis,
        credential_verifier: &'a iroka_kernel::Ed25519CredentialVerifier<R>,
        owner_verifier: &'a iroka_kernel::OwnerApprovalVerifier,
        audit_sink: &'a iroka_kernel::SqliteAuditSink, now: u64,
        max_membership_age_secs: u64) -> Self {
        Self { compact_credential, expected_audience, requested_tenant_id, genesis,
            credential_verifier, owner_verifier, audit_sink, now, max_membership_age_secs }
    }
}
impl<R: iroka_kernel::RevocationChecker> G02AuthorizationAuthority
    for KernelG02AuthorizationAdapter<'_, R> {
    fn authorize_g05(&self, request: &AuthorizationRequest) -> Result<(), G05Error> {
        let capability = g05_capability(request.operation);
        let resource = format!("g05:{}:{}:{}:{}", operation_key(request.operation),
            request.tenant_ref, request.subject_ref,
            request.memory_id.as_deref().unwrap_or("registry"));
        let risk = match request.operation {
            Operation::DesignateReviewer | Operation::RevokeReviewerDesignation => iroka_kernel::RiskLevel::High,
            Operation::GrantEpisodicConsent | Operation::WithdrawEpisodicConsent => iroka_kernel::RiskLevel::Moderate,
            _ => iroka_kernel::RiskLevel::Moderate,
        };
        let kernel_request = iroka_kernel::AuthorizationRequest::new(
            request.principal_ref.clone(), capability, resource, risk);
        let event_id = format!("g05-authz:{}:{}", operation_key(request.operation), request.correlation_ref);
        let decision = iroka_kernel::authorize_compact_in_tenant(
            self.compact_credential, self.expected_audience, self.requested_tenant_id,
            &kernel_request, self.genesis, None, self.credential_verifier,
            self.owner_verifier, self.audit_sink, self.now, self.max_membership_age_secs,
            &event_id, &request.correlation_ref);
        if decision.code() == iroka_kernel::DecisionCode::Allow {
            Ok(())
        } else {
            Err(G05Error::AuthorizationDenied)
        }
    }
}
fn operation_key(operation: Operation) -> &'static str {
    match operation {
        Operation::Propose => "propose", Operation::CreateWorking => "working.create",
        Operation::CreateEpisodic => "episodic.create", Operation::ActivateDurable => "durable.activate",
        Operation::Retrieve => "retrieve", Operation::InspectMetadata => "metadata.inspect",
        Operation::Correct => "correct", Operation::Restrict => "restrict",
        Operation::RequestDeletion => "deletion.request", Operation::VerifyDeletion => "deletion.verify",
        Operation::Share => "share", Operation::GrantEpisodicConsent => "consent.grant",
        Operation::WithdrawEpisodicConsent => "consent.withdraw",
        Operation::DesignateReviewer => "reviewer.designate",
        Operation::RevokeReviewerDesignation => "reviewer.revoke",
    }
}
fn g05_capability(operation: Operation) -> &'static str {
    match operation {
        Operation::Propose => "g05.memory.propose",
        Operation::CreateWorking => "g05.memory.working.create",
        Operation::CreateEpisodic => "g05.memory.episodic.create",
        Operation::ActivateDurable => "g05.memory.durable.activate",
        Operation::Retrieve => "g05.memory.retrieve",
        Operation::InspectMetadata => "g05.memory.metadata.inspect",
        Operation::Correct => "g05.memory.correct",
        Operation::Restrict => "g05.memory.restrict",
        Operation::RequestDeletion => "g05.memory.deletion.request",
        Operation::VerifyDeletion => "g05.memory.deletion.verify",
        Operation::Share => "g05.memory.share",
        Operation::GrantEpisodicConsent => "g05.memory.consent.grant",
        Operation::WithdrawEpisodicConsent => "g05.memory.consent.withdraw",
        Operation::DesignateReviewer => "g05.memory.reviewer.designate",
        Operation::RevokeReviewerDesignation => "g05.memory.reviewer.revoke",
    }
}

fn purpose_key(p:Purpose)->&'static str{match p{
    Purpose::TaskContinuity=>"TASK_CONTINUITY",Purpose::UserPreference=>"USER_PREFERENCE",
    Purpose::ProjectContext=>"PROJECT_CONTEXT",Purpose::OrganizationalContext=>"ORGANIZATIONAL_CONTEXT",
    Purpose::OperationalHistory=>"OPERATIONAL_HISTORY",Purpose::AuthorizedSystemAssurance=>"AUTHORIZED_SYSTEM_ASSURANCE"}}
fn to_i64(v:u64)->Result<i64,G05Error>{i64::try_from(v).map_err(|_|G05Error::MalformedRecord)}
fn from_i64(v:i64)->Result<u64,G05Error>{u64::try_from(v).map_err(|_|G05Error::AuthorityUnavailable)}

#[cfg(test)]
mod tests{
 use super::*;
 struct G01;
 impl G01ReviewerProofAuthority for G01{
  fn validate_reviewer_key_binding(&self,r:&str,k:&str,_:u64)->Result<(),G05Error>{
   if r=="reviewer:1"&&k=="key:1"{Ok(())}else{Err(G05Error::ReviewerNotAuthorized)}}
  fn verify_approval_proof(&self,r:&DurableApprovalReceipt,d:&ReviewerDesignation,_:u64)->Result<(),G05Error>{
   if r.proof_ref=="proof:valid"&&r.reviewer_ref==d.reviewer_ref{Ok(())}else{Err(G05Error::ReviewerNotAuthorized)}}
 }
 #[test] fn consent_scope_purpose_expiry_and_revocation_fail_closed(){
  let r=SqliteG05AuthorityRegistry::open_in_memory().unwrap();
  {let c=r.connection.lock().unwrap();c.execute("INSERT INTO g05_episodic_consents VALUES
   ('c1','t1','s1','TASK_CONTINUITY','iss','cred',100,200,NULL,1,'action')",[]).unwrap();}
  assert_eq!(r.verify_active_opt_in("c1","t1","s1",Purpose::TaskContinuity,150),Ok(()));
  assert_eq!(r.verify_active_opt_in("c1","t2","s1",Purpose::TaskContinuity,150),Err(G05Error::ConsentScopeMismatch));
  assert_eq!(r.verify_active_opt_in("c1","t1","s1",Purpose::UserPreference,150),Err(G05Error::ConsentScopeMismatch));
  assert_eq!(r.verify_active_opt_in("c1","t1","s1",Purpose::TaskContinuity,200),Err(G05Error::EpisodicOptInRequired));
  let c=r.connection.lock().unwrap();c.execute("UPDATE g05_episodic_consents SET revoked_at=160 WHERE consent_ref='c1'",[]).unwrap();
  drop(c);assert_eq!(r.verify_active_opt_in("c1","t1","s1",Purpose::TaskContinuity,170),Err(G05Error::EpisodicOptInRequired));
 }
 #[test] fn reviewer_scope_expiry_revocation_and_replay_fail_closed(){
  let r=SqliteG05AuthorityRegistry::open_in_memory().unwrap();
  {let c=r.connection.lock().unwrap();c.execute("INSERT INTO g05_reviewer_designations VALUES
   ('d1','t1','org1','reviewer:1','key:1','admin',1,100,300,100,NULL)",[]).unwrap();}
  let receipt=DurableApprovalReceipt{approval_ref:"a1".into(),memory_id:"m1".into(),tenant_ref:"t1".into(),
   subject_ref:"org1".into(),content_sha256:"a".repeat(64),reviewer_ref:"reviewer:1".into(),
   issued_at:120,expires_at:200,proof_ref:"proof:valid".into()};
  let a=RegistryDesignatedReviewerAuthority::new(r.clone(),G01);
  assert_eq!(a.verify_designated_reviewer(&receipt,"org1",150),Ok(()));
  assert_eq!(a.verify_designated_reviewer(&receipt,"org1",151),Err(G05Error::ApprovalReplay));
  let mut wrong=receipt.clone();wrong.tenant_ref="t2".into();
  assert_eq!(a.verify_designated_reviewer(&wrong,"org1",152),Err(G05Error::ReviewerNotAuthorized));
  let c=r.connection.lock().unwrap();c.execute("UPDATE g05_reviewer_designations SET revoked_at=153 WHERE designation_ref='d1'",[]).unwrap();
  drop(c);let next=DurableApprovalReceipt{approval_ref:"a2".into(),..receipt};
  assert_eq!(a.verify_designated_reviewer(&next,"org1",154),Err(G05Error::ReviewerNotAuthorized));
 }
}
