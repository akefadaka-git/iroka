//! Canonical G02 Owner signature verification and atomic PostgreSQL command application.
//!
//! Signing inputs intentionally match iroka-kernel's canonical G02 contracts:
//! policy snapshots use RFC 8785 JCS + the policy domain separator; security
//! commands use the existing serde_json struct serialization. Private keys
//! are never loaded here. Trust roots are provisioned public keys only.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use iroka_kernel::{Policy, RiskLevel};
use postgres::Client;
use postgres_native_tls::MakeTlsConnector;
use native_tls::TlsConnector;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{G02PolicySnapshot, G02PolicySnapshotVerifier, G05Error};

const OWNER_ISSUER: &str = "iroka:owner-authority";
const POLICY_DOMAIN: &[u8] = b"IROKA:G02:POLICY-SNAPSHOT:V1\0";
const MAX_COMMAND_TTL: u64 = 900;
const CLOCK_SKEW: u64 = 30;
const COMMAND_LOCK_ID: i64 = 77305113;

#[derive(Debug, Clone)]
pub struct G02TrustedOwnerKey {
    pub owner_subject: String,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Debug, Clone)]
struct OwnerKey {
    owner_subject: String,
    verifying_key: VerifyingKey,
    not_before: u64,
    not_after: u64,
}

#[derive(Clone)]
pub struct PostgresOwnerSignatureVerifier {
    client: Arc<Mutex<Client>>,
    keys: Arc<HashMap<String, OwnerKey>>,
}

impl PostgresOwnerSignatureVerifier {
    #[cfg(test)]
    pub(crate) fn from_client_for_test(
        client: Client,
        trusted_keys: Vec<G02TrustedOwnerKey>,
    ) -> Result<Self, G02CommandError> {
        let mut keys = HashMap::new();
        for key in trusted_keys {
            let verifying_key = VerifyingKey::from_bytes(&key.public_key)
                .map_err(|_| G02CommandError::Malformed)?;
            keys.insert(key.key_id, OwnerKey {
                owner_subject: key.owner_subject,
                verifying_key,
                not_before: key.not_before,
                not_after: key.not_after,
            });
        }
        Ok(Self { client: Arc::new(Mutex::new(client)), keys: Arc::new(keys) })
    }

    pub fn connect(
        connection_string: &str,
        trusted_keys: Vec<G02TrustedOwnerKey>,
    ) -> Result<Self, G02CommandError> {
        if !connection_string.contains("sslmode=verify-full") || trusted_keys.is_empty() {
            return Err(G02CommandError::Configuration);
        }
        let mut keys = HashMap::new();
        for key in trusted_keys {
            if key.owner_subject.trim().is_empty()
                || key.key_id.trim().is_empty()
                || key.not_before >= key.not_after
            {
                return Err(G02CommandError::Malformed);
            }
            let verifying_key = VerifyingKey::from_bytes(&key.public_key)
                .map_err(|_| G02CommandError::Malformed)?;
            if keys.insert(key.key_id, OwnerKey {
                owner_subject: key.owner_subject,
                verifying_key,
                not_before: key.not_before,
                not_after: key.not_after,
            }).is_some() {
                return Err(G02CommandError::Malformed);
            }
        }
        let tls = TlsConnector::builder().build().map_err(|_| G02CommandError::Unavailable)?;
        let client = Client::connect(connection_string, MakeTlsConnector::new(tls))
            .map_err(|_| G02CommandError::Unavailable)?;
        Ok(Self { client: Arc::new(Mutex::new(client)), keys: Arc::new(keys) })
    }

    pub fn verify_schema(&self) -> Result<(), G02CommandError> {
        let mut client = self.client.lock().map_err(|_| G02CommandError::Unavailable)?;
        let row = client.query_one(
            "SELECT to_regclass('public.g02_owner_commands') IS NOT NULL
              AND to_regclass('public.g02_policy_snapshots') IS NOT NULL
              AND to_regclass('public.g02_signing_key_revocations') IS NOT NULL
              AND to_regclass('public.g02_credential_revocations') IS NOT NULL
              AND to_regclass('public.g02_approval_revocations') IS NOT NULL
              AND to_regclass('public.g02_authority_outbox') IS NOT NULL",
            &[],
        ).map_err(|_| G02CommandError::Unavailable)?;
        if row.get::<_, bool>(0) { Ok(()) } else { Err(G02CommandError::Unavailable) }
    }

    fn owner_key(&self, owner_subject: &str, key_id: &str, issued_at: u64, now: u64)
        -> Result<&OwnerKey, G02CommandError> {
        let key = self.keys.get(key_id).ok_or(G02CommandError::UnknownKey)?;
        if key.owner_subject != owner_subject {
            return Err(G02CommandError::ScopeMismatch);
        }
        if now < key.not_before || now >= key.not_after
            || issued_at < key.not_before || issued_at >= key.not_after {
            return Err(G02CommandError::KeyOutsideValidity);
        }
        Ok(key)
    }

    fn ensure_key_active(&self, client: &mut Client, key_id: &str) -> Result<(), G02CommandError> {
        let revoked: bool = client.query_one(
            "SELECT EXISTS(SELECT 1 FROM g02_signing_key_revocations
             WHERE issuer=$1 AND key_id=$2)",
            &[&OWNER_ISSUER, &key_id],
        ).map_err(|_| G02CommandError::Unavailable)?.get(0);
        if revoked { Err(G02CommandError::Revoked) } else { Ok(()) }
    }

    pub fn apply_security_command(
        &self,
        command: &SignedG02SecurityCommand,
        now: u64,
    ) -> Result<String, G02CommandError> {
        let p = &command.payload;
        validate_command_time(p, now)?;
        let key = self.owner_key(&p.owner_subject, &p.key_id, p.issued_at, now)?;
        let signing_bytes = serde_json::to_vec(p).map_err(|_| G02CommandError::Malformed)?;
        let signature = Signature::from_slice(&command.signature)
            .map_err(|_| G02CommandError::Malformed)?;
        key.verifying_key.verify(&signing_bytes, &signature)
            .map_err(|_| G02CommandError::InvalidSignature)?;
        let digest: [u8; 32] = Sha256::digest(&signing_bytes).into();
        let digest_hex = hex(&digest);
        let payload_json = serde_json::json!({
            "payload": p,
            "signature": &command.signature,
        });
        let mut client = self.client.lock().map_err(|_| G02CommandError::Unavailable)?;
        let mut tx = client.transaction().map_err(|_| G02CommandError::Unavailable)?;
        tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&COMMAND_LOCK_ID])
            .map_err(|_| G02CommandError::Unavailable)?;
        let revoked: bool = tx.query_one(
            "SELECT EXISTS(SELECT 1 FROM g02_signing_key_revocations
             WHERE issuer=$1 AND key_id=$2)",
            &[&OWNER_ISSUER, &p.key_id],
        ).map_err(|_| G02CommandError::Unavailable)?.get(0);
        if revoked { return Err(G02CommandError::Revoked); }
        let exists: bool = tx.query_one(
            "SELECT EXISTS(SELECT 1 FROM g02_owner_commands WHERE command_id=$1)",
            &[&p.command_id],
        ).map_err(|_| G02CommandError::Unavailable)?.get(0);
        if exists { return Err(G02CommandError::Replay); }

        tx.execute(
            "INSERT INTO g02_owner_commands
             (command_id,owner_subject,signer_issuer,signer_key_id,issued_at,expires_at,
              payload_canonical,payload_sha256,signature,command_kind)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            &[&p.command_id,&p.owner_subject,&OWNER_ISSUER,&p.key_id,
              &(p.issued_at as i64),&(p.expires_at as i64),&signing_bytes,
              &digest_hex,&command.signature,&action_kind(&p.action)],
        ).map_err(|_| G02CommandError::Unavailable)?;

        apply_action(&mut tx, p, &digest_hex, &payload_json, now)?;
        let event_id = format!("g02-command:{}", p.command_id);
        tx.execute(
            "INSERT INTO g02_authority_outbox
             (event_id,command_id,event_kind,payload_sha256,payload_json,occurred_at)
             VALUES($1,$2,$3,$4,$5,$6)",
            &[&event_id,&p.command_id,&action_kind(&p.action),&digest_hex,
              &payload_json,&(p.issued_at as i64)],
        ).map_err(|_| G02CommandError::Unavailable)?;
        tx.commit().map_err(|_| G02CommandError::Unavailable)?;
        Ok(event_id)
    }
}

impl G02PolicySnapshotVerifier for PostgresOwnerSignatureVerifier {
    fn verify_snapshot(&self, snapshot: &G02PolicySnapshot, now: u64) -> Result<Policy, G05Error> {
        let payload: PolicySnapshotPayload = serde_json::from_slice(&snapshot.canonical_payload)
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        payload.validate(snapshot, now).map_err(|_| G05Error::AuthorityUnavailable)?;
        let canonical = serde_jcs::to_vec(&payload).map_err(|_| G05Error::AuthorityUnavailable)?;
        if canonical != snapshot.canonical_payload {
            return Err(G05Error::AuthorityUnavailable);
        }
        let key = self.owner_key(&payload.owner_subject, &payload.key_id, payload.issued_at, now)
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        if payload.expires_at > key.not_after {
            return Err(G05Error::AuthorityUnavailable);
        }
        let mut signing = Vec::with_capacity(POLICY_DOMAIN.len() + canonical.len());
        signing.extend_from_slice(POLICY_DOMAIN);
        signing.extend_from_slice(&canonical);
        let signature = Signature::from_slice(&snapshot.signature)
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        key.verifying_key.verify(&signing, &signature)
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        let mut client = self.client.lock().map_err(|_| G05Error::AuthorityUnavailable)?;
        let revoked: bool = client.query_one(
            "SELECT EXISTS(SELECT 1 FROM g02_signing_key_revocations
             WHERE issuer=$1 AND key_id=$2)",
            &[&OWNER_ISSUER, &payload.key_id],
        ).map_err(|_| G05Error::AuthorityUnavailable)?.get(0);
        if revoked { return Err(G05Error::AuthorityUnavailable); }
        Ok(Policy::new(payload.policy_version, payload.allowed_capabilities,
            payload.approval_required, payload.maximum_risk.into()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySnapshotPayload {
    pub schema_id: String,
    pub contract_version: String,
    pub owner_subject: String,
    pub key_id: String,
    pub policy_epoch: u64,
    pub policy_version: String,
    pub allowed_capabilities: Vec<String>,
    pub approval_required: Vec<String>,
    pub maximum_risk: PolicyRiskLevel,
    pub emergency_stop_active: bool,
    pub issued_at: u64,
    pub expires_at: u64,
}
impl PolicySnapshotPayload {
    fn validate(&self, row: &G02PolicySnapshot, now: u64) -> Result<(), G02CommandError> {
        if row.signer_issuer != OWNER_ISSUER
            || self.schema_id != "iroka.g02.policy-snapshot" || self.contract_version != "1.0"
            || self.owner_subject != row.owner_subject || self.key_id != row.signer_key_id
            || self.policy_epoch != row.epoch || self.policy_version != row.policy_version
            || self.policy_version.trim().is_empty() || self.policy_version.len() > 128
            || self.issued_at != row.issued_at || self.expires_at != row.expires_at
            || self.issued_at > now.saturating_add(CLOCK_SKEW)
            || self.expires_at <= now || self.issued_at >= self.expires_at
            || self.expires_at - self.issued_at > 86_400
            || self.allowed_capabilities.len() > 512 || self.approval_required.len() > 512
            || !sorted_unique(&self.allowed_capabilities) || !sorted_unique(&self.approval_required)
            || self.approval_required.iter().any(|x| !self.allowed_capabilities.contains(x))
            || self.allowed_capabilities.iter().chain(self.approval_required.iter())
                .any(|x| x.trim().is_empty() || x.len() > 256)
        { return Err(G02CommandError::Malformed); }
        let digest = Sha256::digest(&row.canonical_payload);
        if hex(&digest) != row.payload_sha256.to_ascii_lowercase() {
            return Err(G02CommandError::DigestMismatch);
        }
        Ok(())
    }
}
fn sorted_unique(v: &[String]) -> bool { v.windows(2).all(|w| w[0] < w[1]) }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyRiskLevel { Low, Moderate, High, Critical }
impl From<PolicyRiskLevel> for RiskLevel {
    fn from(v: PolicyRiskLevel) -> Self { match v {
        PolicyRiskLevel::Low=>Self::Low, PolicyRiskLevel::Moderate=>Self::Moderate,
        PolicyRiskLevel::High=>Self::High, PolicyRiskLevel::Critical=>Self::Critical
    }}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum G02SecurityAction {
    RevokeCredential { issuer: String, credential_id: String, reason: String },
    RevokeSigningKey { issuer: String, key_id: String, reason: String },
    RevokeApproval { approval_id: String, reason: String },
    SetTenantMembership { subject: String, tenant_id: String, active: bool, version: u64, reason: String },
    RevokePolicy { policy_epoch: u64, reason: String },
    SetEmergencyStop { active: bool, version: u64, reason: String },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct G02SecurityCommandPayload {
    pub command_id: String,
    pub owner_subject: String,
    pub key_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub action: G02SecurityAction,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedG02SecurityCommand {
    pub payload: G02SecurityCommandPayload,
    pub signature: Vec<u8>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum G02CommandError {
    Configuration, Malformed, UnknownKey, KeyOutsideValidity, InvalidSignature,
    Expired, NotYetValid, Revoked, Replay, Rollback, DigestMismatch,
    ScopeMismatch, Unavailable,
}
fn validate_command_time(p: &G02SecurityCommandPayload, now: u64) -> Result<(), G02CommandError> {
    if p.command_id.trim().is_empty() || p.owner_subject.trim().is_empty() || p.key_id.trim().is_empty()
        || p.issued_at >= p.expires_at || p.expires_at.saturating_sub(p.issued_at) > MAX_COMMAND_TTL
    { return Err(G02CommandError::Malformed); }
    if p.issued_at > now.saturating_add(CLOCK_SKEW) { return Err(G02CommandError::NotYetValid); }
    if p.expires_at <= now { return Err(G02CommandError::Expired); }
    Ok(())
}
fn action_kind(a: &G02SecurityAction) -> &'static str {
    match a {
        G02SecurityAction::RevokeCredential{..}=>"revoke_credential",
        G02SecurityAction::RevokeSigningKey{..}=>"revoke_signing_key",
        G02SecurityAction::RevokeApproval{..}=>"revoke_approval",
        G02SecurityAction::SetTenantMembership{..}=>"set_tenant_membership",
        G02SecurityAction::RevokePolicy{..}=>"revoke_policy",
        G02SecurityAction::SetEmergencyStop{..}=>"set_emergency_stop",
    }
}
fn apply_action(
    tx: &mut postgres::Transaction<'_>, p: &G02SecurityCommandPayload, digest: &str,
    payload: &serde_json::Value, now: u64,
) -> Result<(), G02CommandError> {
    match &p.action {
        G02SecurityAction::RevokeCredential{issuer,credential_id,reason} => {
            if issuer.trim().is_empty() || credential_id.trim().is_empty() || reason.trim().is_empty() || reason.len()>1024 { return Err(G02CommandError::Malformed); }
            tx.execute("INSERT INTO g02_credential_revocations(issuer,credential_id,reason,revoked_by_command_id,revoked_at) VALUES($1,$2,$3,$4,$5)",
                &[issuer,credential_id,reason,&p.command_id,&(now as i64)]).map_err(|_|G02CommandError::Unavailable)?;
        },
        G02SecurityAction::RevokeSigningKey{issuer,key_id,reason} => {
            if issuer.trim().is_empty() || key_id.trim().is_empty() || reason.trim().is_empty() || reason.len()>1024 { return Err(G02CommandError::Malformed); }
            tx.execute("INSERT INTO g02_signing_key_revocations(issuer,key_id,reason,revoked_by_command_id,revoked_at) VALUES($1,$2,$3,$4,$5)",
                &[issuer,key_id,reason,&p.command_id,&(now as i64)]).map_err(|_|G02CommandError::Unavailable)?;
        },
        G02SecurityAction::RevokeApproval{approval_id,reason} => {
            if approval_id.trim().is_empty() || reason.trim().is_empty() || reason.len()>1024 { return Err(G02CommandError::Malformed); }
            tx.execute("INSERT INTO g02_approval_revocations(approval_id,reason,revoked_by_command_id,revoked_at) VALUES($1,$2,$3,$4)",
                &[approval_id,reason,&p.command_id,&(now as i64)]).map_err(|_|G02CommandError::Unavailable)?;
        },
        G02SecurityAction::SetTenantMembership{subject,tenant_id,active,version,reason} => {
            if subject.trim().is_empty() || tenant_id.trim().is_empty() || reason.trim().is_empty()
                || subject.len()>256 || tenant_id.len()>256 || reason.len()>1024 || *version==0 {
                return Err(G02CommandError::Malformed);
            }
            let changed=tx.execute("INSERT INTO g02_tenant_memberships(subject_ref,tenant_ref,active,version,updated_at,command_id) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(subject_ref,tenant_ref) DO UPDATE SET active=EXCLUDED.active,version=EXCLUDED.version,updated_at=EXCLUDED.updated_at,command_id=EXCLUDED.command_id WHERE g02_tenant_memberships.version < EXCLUDED.version",
                &[subject,tenant_id,active,&(*version as i64),&(now as i64),&p.command_id]).map_err(|_|G02CommandError::Unavailable)?;
            if changed != 1 { return Err(G02CommandError::Rollback); }
        },
        G02SecurityAction::RevokePolicy{policy_epoch,reason} => {
            if *policy_epoch==0 || reason.trim().is_empty() || reason.len()>1024 { return Err(G02CommandError::Malformed); }
            let changed = tx.execute("INSERT INTO g02_policy_revocations(policy_id,epoch,reason_code,revoked_by_command_id,revoked_at) SELECT policy_id,$1,$2,$3,$4 FROM g02_policy_heads WHERE current_epoch=$1 ON CONFLICT(policy_id,epoch) DO NOTHING",
                &[&(*policy_epoch as i64),reason,&p.command_id,&(now as i64)]).map_err(|_|G02CommandError::Unavailable)?;
            if changed != 1 { return Err(G02CommandError::Rollback); }
        },
        G02SecurityAction::SetEmergencyStop{active,version,reason} => {
            if *version==0 || reason.trim().is_empty() || reason.len()>1024 { return Err(G02CommandError::Malformed); }
            let changed=tx.execute("INSERT INTO g02_emergency_stop(singleton,active,version,reason_code,changed_by_command_id,changed_at) VALUES(TRUE,$1,$2,$3,$4,$5) ON CONFLICT(singleton) DO UPDATE SET active=EXCLUDED.active,version=EXCLUDED.version,reason_code=EXCLUDED.reason_code,changed_by_command_id=EXCLUDED.changed_by_command_id,changed_at=EXCLUDED.changed_at WHERE g02_emergency_stop.version < EXCLUDED.version",
                &[active,&(*version as i64),reason,&p.command_id,&(now as i64)]).map_err(|_|G02CommandError::Unavailable)?;
            if changed != 1 { return Err(G02CommandError::Rollback); }
        },
    }
    let _ = (digest, payload);
    Ok(())
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_ttl_and_expiry_are_bounded() {
        let p=G02SecurityCommandPayload{command_id:"c1".into(),owner_subject:"owner".into(),key_id:"k1".into(),issued_at:100,expires_at:200,action:G02SecurityAction::SetEmergencyStop{active:true,version:1,reason:"incident".into()}};
        assert_eq!(validate_command_time(&p,150),Ok(()));
        assert_eq!(validate_command_time(&p,201),Err(G02CommandError::Expired));
        let mut bad=p.clone(); bad.expires_at=2_000;
        assert_eq!(validate_command_time(&bad,150),Err(G02CommandError::Malformed));
    }
}
