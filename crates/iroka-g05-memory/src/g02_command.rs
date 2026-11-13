//! Root-verified G02 Owner-key registry and transactional signed-command processor.
//! Root public keys are pinned out-of-band. No private key material is accepted.
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use iroka_kernel::TrustRoot;
use native_tls::TlsConnector;
use postgres::Client;
use postgres_native_tls::MakeTlsConnector;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

const REGISTRY_DOMAIN: &[u8] = b"IROKA-G02-OWNER-REGISTRY-v1\0";
const COMMAND_DOMAIN: &[u8] = b"IROKA-G02-OWNER-COMMAND-v1\0";
const POLICY_DOMAIN: &[u8] = b"IROKA-G02-POLICY-SNAPSHOT-v1\0";
const MAX_REGISTRY_TTL: u64 = 31_536_000;
const MAX_COMMAND_TTL: u64 = 900;
const MAX_PAYLOAD_BYTES: usize = 1_048_576;
const REGISTRY_LOCK: i64 = 77305113;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerKeyBinding {
    pub owner_subject: String,
    pub issuer: String,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerKeyRegistryPayload {
    pub version: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub keys: Vec<OwnerKeyBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedOwnerKeyRegistry {
    pub root_key_id: String,
    pub payload: OwnerKeyRegistryPayload,
    pub signature: Vec<u8>,
}

impl SignedOwnerKeyRegistry {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, G02AuthorityError> {
        let body = serde_jcs::to_vec(&(self.root_key_id.as_str(), &self.payload))
            .map_err(|_| G02AuthorityError::Malformed)?;
        let mut bytes = REGISTRY_DOMAIN.to_vec();
        bytes.extend(body);
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerCommandAction {
    PublishPolicy {
        policy_id: String,
        epoch: u64,
        policy_version: String,
        issued_at: u64,
        expires_at: u64,
        canonical_payload: Vec<u8>,
        payload_sha256: String,
        policy_signature: Vec<u8>,
    },
    SetTenantMembership {
        subject_ref: String,
        tenant_ref: String,
        active: bool,
        version: u64,
    },
    SetEmergencyStop {
        active: bool,
        version: u64,
        reason_code: String,
    },
    RevokeOwnerKey {
        issuer: String,
        key_id: String,
        reason_code: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerCommandPayload {
    pub command_id: String,
    pub owner_subject: String,
    pub issuer: String,
    pub key_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub action: OwnerCommandAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedOwnerCommand {
    pub payload: OwnerCommandPayload,
    pub signature: Vec<u8>,
}

impl SignedOwnerCommand {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, G02AuthorityError> {
        let body = serde_jcs::to_vec(&self.payload).map_err(|_| G02AuthorityError::Malformed)?;
        let mut bytes = COMMAND_DOMAIN.to_vec();
        bytes.extend(body);
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum G02AuthorityError {
    Malformed,
    InvalidRoot,
    InvalidRootSignature,
    RegistryExpired,
    RegistryRollback,
    InvalidOwnerSignature,
    UnknownOwnerKey,
    OwnerKeyOutsideValidity,
    OwnerKeyRevoked,
    RevocationUnavailable,
    CommandExpired,
    Replay,
    VersionConflict,
    InvalidTransition,
    DatabaseUnavailable,
}

pub struct PostgresG02Authority {
    client: Client,
    roots: Vec<TrustRoot>,
}

impl PostgresG02Authority {
    /// Production connections require TLS chain and hostname validation.
    pub fn connect(
        connection_string: &str,
        roots: Vec<TrustRoot>,
    ) -> Result<Self, G02AuthorityError> {
        if !connection_string.contains("sslmode=verify-full") || roots.is_empty() {
            return Err(G02AuthorityError::InvalidRoot);
        }
        for root in &roots {
            if root.key_id.trim().is_empty()
                || root.provenance_ref.trim().is_empty()
                || root.not_before >= root.not_after
                || VerifyingKey::from_bytes(&root.public_key).is_err()
            {
                return Err(G02AuthorityError::InvalidRoot);
            }
        }
        let tls = TlsConnector::builder()
            .build()
            .map_err(|_| G02AuthorityError::DatabaseUnavailable)?;
        let client = Client::connect(connection_string, MakeTlsConnector::new(tls))
            .map_err(|_| G02AuthorityError::DatabaseUnavailable)?;
        Ok(Self { client, roots })
    }

    /// Installs only a root-signed, bounded, sorted registry. The DB high-water
    /// mark and key rows commit together, preventing registry rollback.
    pub fn install_registry(
        &mut self,
        registry: &SignedOwnerKeyRegistry,
        now: u64,
    ) -> Result<(), G02AuthorityError> {
        let root = self
            .roots
            .iter()
            .find(|r| r.key_id == registry.root_key_id)
            .ok_or(G02AuthorityError::InvalidRoot)?;
        if now < root.not_before || now >= root.not_after {
            return Err(G02AuthorityError::InvalidRoot);
        }
        let p = &registry.payload;
        if p.version == 0
            || p.issued_at > now.saturating_add(30)
            || p.expires_at <= now
            || p.expires_at <= p.issued_at
            || p.expires_at - p.issued_at > MAX_REGISTRY_TTL
            || p.keys.is_empty()
            || p.keys.len() > 256
            || p.keys
                .windows(2)
                .any(|w| (&w[0].issuer, &w[0].key_id) >= (&w[1].issuer, &w[1].key_id))
        {
            return Err(G02AuthorityError::Malformed);
        }
        for k in &p.keys {
            if k.owner_subject.trim().is_empty()
                || k.issuer.trim().is_empty()
                || k.key_id.trim().is_empty()
                || k.not_before >= k.not_after
                || k.not_after > p.expires_at
                || VerifyingKey::from_bytes(&k.public_key).is_err()
            {
                return Err(G02AuthorityError::Malformed);
            }
        }
        let bytes = registry.signing_bytes()?;
        let sig = Signature::from_slice(&registry.signature)
            .map_err(|_| G02AuthorityError::InvalidRootSignature)?;
        VerifyingKey::from_bytes(&root.public_key)
            .map_err(|_| G02AuthorityError::InvalidRoot)?
            .verify(&bytes, &sig)
            .map_err(|_| G02AuthorityError::InvalidRootSignature)?;
        let digest = hex(&Sha256::digest(&bytes));
        let mut tx = self
            .client
            .transaction()
            .map_err(|_| G02AuthorityError::DatabaseUnavailable)?;
        tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&REGISTRY_LOCK])
            .map_err(|_| G02AuthorityError::DatabaseUnavailable)?;
        let current: Option<i64> = tx
            .query_one(
                "SELECT max(version) FROM g02_owner_key_registry_versions",
                &[],
            )
            .map_err(|_| G02AuthorityError::DatabaseUnavailable)?
            .get(0);
        if current.is_some_and(|v| p.version <= v as u64) {
            return Err(G02AuthorityError::RegistryRollback);
        }
        tx.execute(
            "INSERT INTO g02_owner_key_registry_versions(version,root_key_id,issued_at,expires_at,payload_sha256,signed_payload,signature) VALUES($1,$2,$3,$4,$5,$6,$7)",
            &[&to_i64(p.version)?, &registry.root_key_id, &to_i64(p.issued_at)?, &to_i64(p.expires_at)?, &digest, &bytes, &registry.signature])
            .map_err(|_| G02AuthorityError::DatabaseUnavailable)?;
        for k in &p.keys {
            tx.execute(
                "INSERT INTO g02_owner_keys(registry_version,owner_subject,issuer,key_id,public_key,not_before,not_after) VALUES($1,$2,$3,$4,$5,$6,$7)",
                &[&to_i64(p.version)?, &k.owner_subject, &k.issuer, &k.key_id, &&k.public_key[..], &to_i64(k.not_before)?, &to_i64(k.not_after)?])
                .map_err(|_| G02AuthorityError::DatabaseUnavailable)?;
        }
        tx.commit()
            .map_err(|_| G02AuthorityError::DatabaseUnavailable)
    }

    /// Re-checks the current registry and revocation while holding the signer
    /// row lock, then writes signed evidence, projection and G11 outbox atomically.
    pub fn execute(
        &mut self,
        command: &SignedOwnerCommand,
        now: u64,
    ) -> Result<String, G02AuthorityError> {
        let p = &command.payload;
        if p.command_id.trim().is_empty()
            || p.command_id.len() > 128
            || p.owner_subject.trim().is_empty()
            || p.issuer.trim().is_empty()
            || p.key_id.trim().is_empty()
            || p.issued_at > now.saturating_add(30)
            || p.expires_at <= now
            || p.expires_at <= p.issued_at
            || p.expires_at - p.issued_at > MAX_COMMAND_TTL
        {
            return Err(G02AuthorityError::CommandExpired);
        }
        let bytes = command.signing_bytes()?;
        let digest = hex(&Sha256::digest(&bytes));
        let signature = Signature::from_slice(&command.signature)
            .map_err(|_| G02AuthorityError::InvalidOwnerSignature)?;
        let mut tx = self
            .client
            .transaction()
            .map_err(|_| G02AuthorityError::DatabaseUnavailable)?;
        tx.batch_execute("SELECT pg_advisory_xact_lock_shared(77305113)")
            .map_err(|_| G02AuthorityError::DatabaseUnavailable)?;
        let key = tx.query_opt(
            "SELECT k.public_key,k.not_before,k.not_after,v.expires_at
             FROM g02_owner_keys k JOIN g02_owner_key_registry_versions v ON v.version=k.registry_version
             WHERE k.registry_version=(SELECT max(version) FROM g02_owner_key_registry_versions)
               AND k.issuer=$1 AND k.key_id=$2 AND k.owner_subject=$3 FOR UPDATE OF k",
            &[&p.issuer,&p.key_id,&p.owner_subject])
            .map_err(|_| G02AuthorityError::DatabaseUnavailable)?.ok_or(G02AuthorityError::UnknownOwnerKey)?;
        let public_key: Vec<u8> = key.get(0);
        let not_before: i64 = key.get(1);
        let not_after: i64 = key.get(2);
        let registry_expiry: i64 = key.get(3);
        if now < not_before as u64 || now >= not_after as u64 || now >= registry_expiry as u64 {
            return Err(G02AuthorityError::OwnerKeyOutsideValidity);
        }
        let revoked: bool = tx.query_one(
            "SELECT EXISTS(SELECT 1 FROM g02_owner_key_revocations WHERE issuer=$1 AND key_id=$2)",
            &[&p.issuer,&p.key_id]).map_err(|_| G02AuthorityError::RevocationUnavailable)?.get(0);
        if revoked {
            return Err(G02AuthorityError::OwnerKeyRevoked);
        }
        if public_key.len() != 32 {
            return Err(G02AuthorityError::UnknownOwnerKey);
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&public_key);
        VerifyingKey::from_bytes(&pk)
            .map_err(|_| G02AuthorityError::UnknownOwnerKey)?
            .verify(&bytes, &signature)
            .map_err(|_| G02AuthorityError::InvalidOwnerSignature)?;

        let kind = match &p.action {
            OwnerCommandAction::PublishPolicy { .. } => "policy.published",
            OwnerCommandAction::SetTenantMembership { .. } => "membership.changed",
            OwnerCommandAction::SetEmergencyStop { active, .. } => {
                if *active {
                    "emergency_stop.activated"
                } else {
                    "emergency_stop.deactivated"
                }
            }
            OwnerCommandAction::RevokeOwnerKey { .. } => "owner_key.revoked",
        };
        tx.execute(
            "INSERT INTO g02_owner_commands(command_id,owner_subject,signer_issuer,signer_key_id,issued_at,expires_at,payload_canonical,payload_sha256,signature,command_kind) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            &[&p.command_id,&p.owner_subject,&p.issuer,&p.key_id,&to_i64(p.issued_at)?,&to_i64(p.expires_at)?,&bytes,&digest,&command.signature,&kind])
            .map_err(|e| if e.as_db_error().is_some_and(|db| db.code().code()=="23505") { G02AuthorityError::Replay } else { G02AuthorityError::DatabaseUnavailable })?;

        match &p.action {
            OwnerCommandAction::PublishPolicy {
                policy_id,
                epoch,
                policy_version,
                issued_at,
                expires_at,
                canonical_payload,
                payload_sha256,
                policy_signature,
            } => {
                if policy_id.trim().is_empty()
                    || policy_version.trim().is_empty()
                    || *epoch == 0
                    || canonical_payload.is_empty()
                    || canonical_payload.len() > MAX_PAYLOAD_BYTES
                    || *expires_at <= *issued_at
                    || *expires_at <= now
                    || *issued_at > now.saturating_add(30)
                    || hex(&Sha256::digest(canonical_payload))
                        != payload_sha256.to_ascii_lowercase()
                {
                    return Err(G02AuthorityError::Malformed);
                }
                let mut signed = POLICY_DOMAIN.to_vec();
                signed.extend(canonical_payload);
                VerifyingKey::from_bytes(&pk)
                    .map_err(|_| G02AuthorityError::UnknownOwnerKey)?
                    .verify(
                        &signed,
                        &Signature::from_slice(policy_signature)
                            .map_err(|_| G02AuthorityError::InvalidOwnerSignature)?,
                    )
                    .map_err(|_| G02AuthorityError::InvalidOwnerSignature)?;
                tx.execute("INSERT INTO g02_policy_snapshots(policy_id,epoch,policy_version,owner_subject,signer_issuer,signer_key_id,issued_at,expires_at,canonical_payload,payload_sha256,signature) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
                    &[policy_id,&to_i64(*epoch)?,policy_version,&p.owner_subject,&p.issuer,&p.key_id,&to_i64(*issued_at)?,&to_i64(*expires_at)?,canonical_payload,payload_sha256,policy_signature])
                    .map_err(|_| G02AuthorityError::VersionConflict)?;
                let changed=tx.execute("INSERT INTO g02_policy_heads(policy_id,current_epoch,current_payload_sha256) VALUES($1,$2,$3) ON CONFLICT(policy_id) DO UPDATE SET current_epoch=EXCLUDED.current_epoch,current_payload_sha256=EXCLUDED.current_payload_sha256,updated_at=clock_timestamp() WHERE g02_policy_heads.current_epoch < EXCLUDED.current_epoch",
                    &[policy_id,&to_i64(*epoch)?,payload_sha256]).map_err(|_| G02AuthorityError::DatabaseUnavailable)?;
                if changed != 1 {
                    return Err(G02AuthorityError::VersionConflict);
                }
            }
            OwnerCommandAction::SetTenantMembership {
                subject_ref,
                tenant_ref,
                active,
                version,
            } => {
                if subject_ref.trim().is_empty() || tenant_ref.trim().is_empty() || *version == 0 {
                    return Err(G02AuthorityError::Malformed);
                }
                let changed=tx.execute("INSERT INTO g02_tenant_memberships(subject_ref,tenant_ref,active,version,updated_at,command_id) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(subject_ref,tenant_ref) DO UPDATE SET active=EXCLUDED.active,version=EXCLUDED.version,updated_at=EXCLUDED.updated_at,command_id=EXCLUDED.command_id WHERE g02_tenant_memberships.version < EXCLUDED.version",
                    &[subject_ref,tenant_ref,active,&to_i64(*version)?,&to_i64(now)?,&p.command_id]).map_err(|_| G02AuthorityError::DatabaseUnavailable)?;
                if changed != 1 {
                    return Err(G02AuthorityError::VersionConflict);
                }
            }
            OwnerCommandAction::SetEmergencyStop {
                active,
                version,
                reason_code,
            } => {
                if *version == 0 || reason_code.trim().is_empty() {
                    return Err(G02AuthorityError::Malformed);
                }
                let current=tx.query_opt("SELECT active,version FROM g02_emergency_stop WHERE singleton=TRUE FOR UPDATE", &[])
                    .map_err(|_| G02AuthorityError::DatabaseUnavailable)?;
                match current {
                    None if *version != 1 => return Err(G02AuthorityError::VersionConflict),
                    None => {}
                    Some(row) => {
                        let old_active: bool = row.get(0);
                        let old_version: i64 = row.get(1);
                        if *active == old_active
                            || *version != (old_version as u64).saturating_add(1)
                        {
                            return Err(G02AuthorityError::InvalidTransition);
                        }
                    }
                }
                let changed=tx.execute("INSERT INTO g02_emergency_stop(singleton,active,version,reason_code,changed_by_command_id,changed_at) VALUES(TRUE,$1,$2,$3,$4,$5)",
                    &[active,&to_i64(*version)?,reason_code,&p.command_id,&to_i64(now)?]).map_err(|_| G02AuthorityError::DatabaseUnavailable)?;
                if changed != 1 {
                    return Err(G02AuthorityError::VersionConflict);
                }
            }
            OwnerCommandAction::RevokeOwnerKey {
                issuer,
                key_id,
                reason_code,
            } => {
                let target = tx.query_opt("SELECT key_id FROM g02_owner_keys WHERE registry_version=(SELECT max(version) FROM g02_owner_key_registry_versions) AND issuer=$1 AND key_id=$2 FOR UPDATE", &[issuer,key_id]).map_err(|_| G02AuthorityError::DatabaseUnavailable)?;
                if target.is_none() {
                    return Err(G02AuthorityError::UnknownOwnerKey);
                }
                if issuer.trim().is_empty()
                    || key_id.trim().is_empty()
                    || reason_code.trim().is_empty()
                    || (issuer == &p.issuer && key_id == &p.key_id)
                {
                    return Err(G02AuthorityError::InvalidTransition);
                }
                tx.execute("INSERT INTO g02_owner_key_revocations(issuer,key_id,revoked_at,reason_code,revoked_by_command_id) VALUES($1,$2,$3,$4,$5)",
                    &[issuer,key_id,&to_i64(now)?,reason_code,&p.command_id]).map_err(|_| G02AuthorityError::InvalidTransition)?;
            }
        }
        let outbox = json!({"command_id":p.command_id,"command_kind":kind,"payload_sha256":digest});
        tx.execute("INSERT INTO g02_authority_outbox(event_id,command_id,event_kind,payload_sha256,payload_json,occurred_at) VALUES($1,$2,$3,$4,$5,$6)",
            &[&format!("g02:{}",p.command_id),&p.command_id,&kind,&digest,&outbox,&to_i64(now)?])
            .map_err(|_| G02AuthorityError::DatabaseUnavailable)?;
        tx.commit()
            .map_err(|_| G02AuthorityError::DatabaseUnavailable)?;
        Ok(digest)
    }
}

fn to_i64(v: u64) -> Result<i64, G02AuthorityError> {
    i64::try_from(v).map_err(|_| G02AuthorityError::Malformed)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use postgres::NoTls;

    fn test_authority(url: &str, roots: Vec<TrustRoot>) -> PostgresG02Authority {
        let mut client = Client::connect(url, NoTls).expect("test PostgreSQL connection");
        client
            .batch_execute(include_str!(
                "../migrations/postgres/0001_shared_g05_g11.sql"
            ))
            .expect("shared G05/G11 migration");
        client
            .batch_execute(include_str!(
                "../migrations/postgres/0002_g02_authority.sql"
            ))
            .expect("G02 base migration");
        client
            .batch_execute(include_str!(
                "../migrations/postgres/0003_g02_owner_key_registry.sql"
            ))
            .expect("G02 Owner registry migration");
        client
            .batch_execute(include_str!(
                "../migrations/postgres/0004_g02_revocation_projections.sql"
            ))
            .expect("G02 revocation projections migration");
        drop(client);
        PostgresG02Authority {
            client: Client::connect(url, NoTls).expect("authority PostgreSQL connection"),
            roots,
        }
    }

    fn signed_command(payload: OwnerCommandPayload, key: &SigningKey) -> SignedOwnerCommand {
        let mut command = SignedOwnerCommand {
            payload,
            signature: Vec::new(),
        };
        command.signature = key
            .sign(&command.signing_bytes().expect("canonical command"))
            .to_bytes()
            .to_vec();
        command
    }

    #[test]
    fn postgres_owner_registry_revocation_and_atomic_command_path() {
        let Ok(url) = std::env::var("IROKA_TEST_DATABASE_URL") else {
            return;
        };
        let root_signer = SigningKey::from_bytes(&[71u8; 32]);
        let owner_a = SigningKey::from_bytes(&[72u8; 32]);
        let owner_b = SigningKey::from_bytes(&[73u8; 32]);
        let root = TrustRoot {
            key_id: "test-root".into(),
            public_key: root_signer.verifying_key().to_bytes(),
            not_before: 900,
            not_after: 10_000,
            provenance_ref: "test-only-root-provenance".into(),
        };
        let mut authority = test_authority(&url, vec![root.clone()]);
        let current: Option<i64> = authority
            .client
            .query_one(
                "SELECT max(version) FROM g02_owner_key_registry_versions",
                &[],
            )
            .expect("registry high-water mark")
            .get(0);
        let version = current.unwrap_or(0) as u64 + 1;
        let suffix = unique_test_suffix();
        let subject_ref = format!("subject:test:{suffix}");
        let tenant_ref = format!("tenant:test:{suffix}");
        let payload = OwnerKeyRegistryPayload {
            version,
            issued_at: 1_000,
            expires_at: 5_000,
            keys: vec![
                OwnerKeyBinding {
                    owner_subject: "owner:iroka-test".into(),
                    issuer: "iroka:owner-authority".into(),
                    key_id: "owner-a".into(),
                    public_key: owner_a.verifying_key().to_bytes(),
                    not_before: 1_000,
                    not_after: 5_000,
                },
                OwnerKeyBinding {
                    owner_subject: "owner:iroka-test".into(),
                    issuer: "iroka:owner-authority".into(),
                    key_id: "owner-b".into(),
                    public_key: owner_b.verifying_key().to_bytes(),
                    not_before: 1_000,
                    not_after: 5_000,
                },
            ],
        };
        let mut registry = SignedOwnerKeyRegistry {
            root_key_id: root.key_id.clone(),
            payload,
            signature: Vec::new(),
        };
        registry.signature = root_signer
            .sign(&registry.signing_bytes().expect("registry bytes"))
            .to_bytes()
            .to_vec();
        authority
            .install_registry(&registry, 1_100)
            .expect("root-verified registry");

        let membership = signed_command(
            OwnerCommandPayload {
                command_id: format!("g02-membership-{}", unique_test_suffix()),
                owner_subject: "owner:iroka-test".into(),
                issuer: "iroka:owner-authority".into(),
                key_id: "owner-a".into(),
                issued_at: 1_100,
                expires_at: 1_200,
                action: OwnerCommandAction::SetTenantMembership {
                    subject_ref: subject_ref.clone(),
                    tenant_ref: tenant_ref.clone(),
                    active: true,
                    version: 1,
                },
            },
            &owner_a,
        );
        let membership_id = membership.payload.command_id.clone();
        let digest = authority
            .execute(&membership, 1_101)
            .expect("signed membership command");
        let row = authority.client.query_one(
            "SELECT active,version FROM g02_tenant_memberships WHERE subject_ref=$1 AND tenant_ref=$2",
            &[&subject_ref, &tenant_ref]).expect("membership projection");
        assert!(row.get::<_, bool>(0));
        assert_eq!(row.get::<_, i64>(1), 1);
        let outbox: i64 = authority.client.query_one(
            "SELECT count(*) FROM g02_authority_outbox WHERE command_id=$1 AND payload_sha256=$2",
            &[&membership_id,&digest]).expect("atomic G11 outbox").get(0);
        assert_eq!(outbox, 1);

        // Inject an outbox failure after the command and projection writes.
        // All three writes must roll back as one transaction.
        let rollback_command_id = format!("g02-rollback-{}", unique_test_suffix());
        let rollback_subject = format!("subject:rollback:{suffix}");
        let trigger_sql = format!(
            "CREATE OR REPLACE FUNCTION g02_test_fail_authority_outbox() RETURNS trigger
             LANGUAGE plpgsql AS $g02test$
             BEGIN
               IF NEW.command_id = '{rollback_command_id}' THEN
                 RAISE EXCEPTION 'injected G11 outbox failure';
               END IF;
               RETURN NEW;
             END;
             $g02test$;
             CREATE TRIGGER g02_test_fail_authority_outbox
             BEFORE INSERT ON g02_authority_outbox
             FOR EACH ROW EXECUTE FUNCTION g02_test_fail_authority_outbox();"
        );
        authority
            .client
            .batch_execute(&trigger_sql)
            .expect("install rollback fault");
        let rollback_command = signed_command(
            OwnerCommandPayload {
                command_id: rollback_command_id.clone(),
                owner_subject: "owner:iroka-test".into(),
                issuer: "iroka:owner-authority".into(),
                key_id: "owner-a".into(),
                issued_at: 1_105,
                expires_at: 1_200,
                action: OwnerCommandAction::SetTenantMembership {
                    subject_ref: rollback_subject.clone(),
                    tenant_ref: tenant_ref.clone(),
                    active: true,
                    version: 1,
                },
            },
            &owner_a,
        );
        assert_eq!(
            authority.execute(&rollback_command, 1_106),
            Err(G02AuthorityError::DatabaseUnavailable)
        );
        let rolled_back: i64 = authority
            .client
            .query_one(
                "SELECT count(*) FROM g02_owner_commands WHERE command_id=$1",
                &[&rollback_command_id],
            )
            .expect("rolled-back command history")
            .get(0);
        let rolled_back_projection: i64 = authority.client.query_one(
            "SELECT count(*) FROM g02_tenant_memberships WHERE subject_ref=$1 AND tenant_ref=$2",
            &[&rollback_subject, &tenant_ref],
        ).expect("rolled-back membership projection").get(0);
        assert_eq!(rolled_back, 0);
        assert_eq!(rolled_back_projection, 0);
        authority
            .client
            .batch_execute(
                "DROP TRIGGER g02_test_fail_authority_outbox ON g02_authority_outbox;
             DROP FUNCTION g02_test_fail_authority_outbox();",
            )
            .expect("remove rollback fault");

        assert_eq!(
            authority.execute(&membership, 1_101),
            Err(G02AuthorityError::Replay)
        );

        let revoke = signed_command(
            OwnerCommandPayload {
                command_id: format!("g02-revoke-{}", unique_test_suffix()),
                owner_subject: "owner:iroka-test".into(),
                issuer: "iroka:owner-authority".into(),
                key_id: "owner-b".into(),
                issued_at: 1_110,
                expires_at: 1_200,
                action: OwnerCommandAction::RevokeOwnerKey {
                    issuer: "iroka:owner-authority".into(),
                    key_id: "owner-a".into(),
                    reason_code: "test-compromise".into(),
                },
            },
            &owner_b,
        );
        authority
            .execute(&revoke, 1_111)
            .expect("second Owner key revokes first");
        let after_revocation = signed_command(
            OwnerCommandPayload {
                command_id: format!("g02-after-revoke-{}", unique_test_suffix()),
                owner_subject: "owner:iroka-test".into(),
                issuer: "iroka:owner-authority".into(),
                key_id: "owner-a".into(),
                issued_at: 1_120,
                expires_at: 1_200,
                action: OwnerCommandAction::SetTenantMembership {
                    subject_ref: format!("subject:test-revoked:{suffix}"),
                    tenant_ref: tenant_ref.clone(),
                    active: true,
                    version: 1,
                },
            },
            &owner_a,
        );
        assert_eq!(
            authority.execute(&after_revocation, 1_121),
            Err(G02AuthorityError::OwnerKeyRevoked)
        );
    }


    #[test]
    fn postgres_g09_policy_verification_uses_root_signed_owner_registry() {
        let Ok(url) = std::env::var("IROKA_TEST_DATABASE_URL") else { return; };
        let root_signer = SigningKey::from_bytes(&[74u8; 32]);
        let owner_signer = SigningKey::from_bytes(&[75u8; 32]);
        let root = TrustRoot {
            key_id: "g02-test-root".into(),
            public_key: root_signer.verifying_key().to_bytes(),
            not_before: 900,
            not_after: 10_000,
            provenance_ref: "test-only-root-provenance".into(),
        };
        let mut authority = test_authority(&url, vec![root.clone()]);
        let registry_payload = OwnerKeyRegistryPayload {
            version: unique_test_suffix() as u64,
            issued_at: 1_000,
            expires_at: 5_000,
            keys: vec![OwnerKeyBinding {
                owner_subject: "owner:g02-test".into(),
                issuer: "iroka:owner-authority".into(),
                key_id: "owner-g09-key".into(),
                public_key: owner_signer.verifying_key().to_bytes(),
                not_before: 1_000,
                not_after: 4_000,
            }],
        };
        let mut registry = SignedOwnerKeyRegistry {
            root_key_id: root.key_id.clone(),
            payload: registry_payload,
            signature: Vec::new(),
        };
        registry.signature = root_signer.sign(&registry.signing_bytes().unwrap()).to_bytes().to_vec();
        authority.install_registry(&registry, 1_100).unwrap();

        let snapshot_payload = crate::PostgresPolicySnapshotPayload {
            schema_id: "iroka.g02.policy-snapshot".into(),
            contract_version: "1.0".into(),
            owner_subject: "owner:g02-test".into(),
            key_id: "owner-g09-key".into(),
            policy_epoch: 1,
            policy_version: "g09-registry-policy-v1".into(),
            allowed_capabilities: vec!["g05.memory.retrieve".into()],
            approval_required: vec![],
            maximum_risk: crate::PostgresPolicyRiskLevel::High,
            emergency_stop_active: false,
            issued_at: 1_100,
            expires_at: 2_000,
        };
        let canonical = serde_jcs::to_vec(&snapshot_payload).unwrap();
        let mut signing_bytes = b"IROKA:G02:POLICY-SNAPSHOT:V1\\0".to_vec();
        signing_bytes.extend_from_slice(&canonical);
        let snapshot = crate::G02PolicySnapshot {
            policy_id: "test-policy".into(),
            epoch: 1,
            policy_version: "g09-registry-policy-v1".into(),
            owner_subject: "owner:g02-test".into(),
            signer_issuer: "iroka:owner-authority".into(),
            signer_key_id: "owner-g09-key".into(),
            issued_at: 1_100,
            expires_at: 2_000,
            payload_sha256: hex(&Sha256::digest(&canonical)),
            canonical_payload: canonical,
            signature: owner_signer.sign(&signing_bytes).to_bytes().to_vec(),
        };
        let verifier = PostgresG02RegistrySnapshotVerifier::from_client_for_test(
            Client::connect(&url, NoTls).unwrap(),
            vec![root],
        );
        let policy = crate::G02PolicySnapshotVerifier::verify_snapshot(&verifier, &snapshot, 1_200)
            .expect("G09 snapshot must validate against installed root-signed registry");
        assert_eq!(policy.version(), "g09-registry-policy-v1");
    }

    fn unique_test_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    }
}


/// G09 snapshot verifier backed by the same root-signed Owner registry used by
/// PostgresG02Authority. It never accepts a caller-supplied Owner-key list.
pub struct PostgresG02RegistrySnapshotVerifier {
    client: Arc<Mutex<Client>>,
    roots: Vec<TrustRoot>,
}

impl PostgresG02RegistrySnapshotVerifier {
    #[cfg(test)]
    pub(crate) fn from_client_for_test(client: Client, roots: Vec<TrustRoot>) -> Self {
        Self { client: Arc::new(Mutex::new(client)), roots }
    }

    /// Production connections require certificate-chain and hostname validation.
    pub fn connect(connection_string: &str, roots: Vec<TrustRoot>)
        -> Result<Self, G02AuthorityError>
    {
        if !connection_string.contains("sslmode=verify-full") || roots.is_empty() {
            return Err(G02AuthorityError::InvalidRoot);
        }
        for root in &roots {
            if root.key_id.trim().is_empty()
                || root.provenance_ref.trim().is_empty()
                || root.not_before >= root.not_after
                || VerifyingKey::from_bytes(&root.public_key).is_err()
            {
                return Err(G02AuthorityError::InvalidRoot);
            }
        }
        let tls = TlsConnector::builder().build()
            .map_err(|_| G02AuthorityError::DatabaseUnavailable)?;
        let client = Client::connect(connection_string, MakeTlsConnector::new(tls))
            .map_err(|_| G02AuthorityError::DatabaseUnavailable)?;
        Ok(Self { client: Arc::new(Mutex::new(client)), roots })
    }
}

impl crate::G02PolicySnapshotVerifier for PostgresG02RegistrySnapshotVerifier {
    fn verify_snapshot(
        &self,
        snapshot: &crate::G02PolicySnapshot,
        now: u64,
    ) -> Result<iroka_kernel::Policy, crate::G05Error> {
        use ed25519_dalek::{Signature, Verifier};
        use sha2::{Digest, Sha256};

        const POLICY_DOMAIN: &[u8] = b"IROKA:G02:POLICY-SNAPSHOT:V1\\0";
        const OWNER_ISSUER: &str = "iroka:owner-authority";

        let payload: crate::PostgresPolicySnapshotPayload =
            serde_json::from_slice(&snapshot.canonical_payload)
                .map_err(|_| crate::G05Error::AuthorityUnavailable)?;
        let canonical = serde_jcs::to_vec(&payload)
            .map_err(|_| crate::G05Error::AuthorityUnavailable)?;
        if canonical != snapshot.canonical_payload
            || snapshot.signer_issuer != OWNER_ISSUER
            || payload.schema_id != "iroka.g02.policy-snapshot"
            || payload.contract_version != "1.0"
            || payload.owner_subject != snapshot.owner_subject
            || payload.key_id != snapshot.signer_key_id
            || payload.policy_epoch != snapshot.epoch
            || payload.policy_version != snapshot.policy_version
            || payload.policy_version.trim().is_empty()
            || payload.policy_version.len() > 128
            || payload.issued_at != snapshot.issued_at
            || payload.expires_at != snapshot.expires_at
            || payload.issued_at > now.saturating_add(30)
            || payload.expires_at <= now
            || payload.issued_at >= payload.expires_at
            || payload.expires_at - payload.issued_at > 86_400
            || payload.allowed_capabilities.len() > 512
            || payload.approval_required.len() > 512
            || !payload.allowed_capabilities.windows(2).all(|w| w[0] < w[1])
            || !payload.approval_required.windows(2).all(|w| w[0] < w[1])
            || payload.approval_required.iter().any(|x| !payload.allowed_capabilities.contains(x))
            || payload.allowed_capabilities.iter().chain(payload.approval_required.iter())
                .any(|x| x.trim().is_empty() || x.len() > 256)
        {
            return Err(crate::G05Error::AuthorityUnavailable);
        }
        let digest = hex(&Sha256::digest(&canonical));
        if digest != snapshot.payload_sha256.to_ascii_lowercase() {
            return Err(crate::G05Error::AuthorityUnavailable);
        }

        let mut client = self.client.lock()
            .map_err(|_| crate::G05Error::AuthorityUnavailable)?;
        // Only the latest installed registry is authoritative. Expiry or
        // corruption of that registry fails closed; older versions are not fallback roots.
        let row = client.query_opt(
            "SELECT v.root_key_id,v.issued_at,v.expires_at,v.payload_sha256,
                    v.signed_payload,v.signature,k.owner_subject,k.issuer,k.key_id,
                    k.public_key,k.not_before,k.not_after
             FROM g02_owner_key_registry_versions v
             JOIN g02_owner_keys k ON k.registry_version=v.version
             WHERE v.version=(SELECT max(version) FROM g02_owner_key_registry_versions)
               AND k.issuer=$1 AND k.key_id=$2 AND k.owner_subject=$3",
            &[&snapshot.signer_issuer, &snapshot.signer_key_id, &snapshot.owner_subject],
        ).map_err(|_| crate::G05Error::AuthorityUnavailable)?
         .ok_or(crate::G05Error::AuthorityUnavailable)?;

        let root_id: String = row.get(0);
        let registry_issued: i64 = row.get(1);
        let registry_expires: i64 = row.get(2);
        let registry_digest: String = row.get(3);
        let signed_payload: Vec<u8> = row.get(4);
        let registry_signature: Vec<u8> = row.get(5);
        let owner_subject: String = row.get(6);
        let issuer: String = row.get(7);
        let key_id: String = row.get(8);
        let public_key: Vec<u8> = row.get(9);
        let not_before: i64 = row.get(10);
        let not_after: i64 = row.get(11);

        let root = self.roots.iter().find(|root| root.key_id == root_id)
            .ok_or(crate::G05Error::AuthorityUnavailable)?;
        if now < root.not_before || now >= root.not_after
            || registry_issued < 0 || registry_expires <= now as i64
            || registry_issued as u64 > now.saturating_add(30)
            || signed_payload.len() <= REGISTRY_DOMAIN.len()
            || hex(&Sha256::digest(&signed_payload)) != registry_digest.trim().to_ascii_lowercase()
        {
            return Err(crate::G05Error::AuthorityUnavailable);
        }
        let root_key = VerifyingKey::from_bytes(&root.public_key)
            .map_err(|_| crate::G05Error::AuthorityUnavailable)?;
        let root_signature = Signature::from_slice(&registry_signature)
            .map_err(|_| crate::G05Error::AuthorityUnavailable)?;
        root_key.verify(&signed_payload, &root_signature)
            .map_err(|_| crate::G05Error::AuthorityUnavailable)?;

        let registry_json = &signed_payload[REGISTRY_DOMAIN.len()..];
        let (signed_root_id, registry): (String, OwnerKeyRegistryPayload) =
            serde_json::from_slice(registry_json)
                .map_err(|_| crate::G05Error::AuthorityUnavailable)?;
        let binding = registry.keys.iter().find(|binding|
            binding.issuer == issuer && binding.key_id == key_id
        ).ok_or(crate::G05Error::AuthorityUnavailable)?;
        if signed_root_id != root_id
            || registry.version <= 0
            || registry.issued_at != registry_issued as u64
            || registry.expires_at != registry_expires as u64
            || registry.expires_at <= now
            || binding.owner_subject != owner_subject
            || binding.public_key.as_slice() != public_key.as_slice()
            || binding.not_before != not_before as u64
            || binding.not_after != not_after as u64
            || now < binding.not_before
            || now >= binding.not_after
            || payload.issued_at < binding.not_before
            || payload.expires_at > binding.not_after
        {
            return Err(crate::G05Error::AuthorityUnavailable);
        }

        let revoked: bool = client.query_one(
            "SELECT EXISTS(
                SELECT 1 FROM g02_owner_key_revocations
                 WHERE issuer=$1 AND key_id=$2
                UNION ALL
                SELECT 1 FROM g02_signing_key_revocations
                 WHERE issuer=$1 AND key_id=$2
             )",
            &[&snapshot.signer_issuer, &snapshot.signer_key_id],
        ).map_err(|_| crate::G05Error::AuthorityUnavailable)?.get(0);
        if revoked {
            return Err(crate::G05Error::AuthorityUnavailable);
        }

        let mut signing_bytes = POLICY_DOMAIN.to_vec();
        signing_bytes.extend_from_slice(&canonical);
        let signature = Signature::from_slice(&snapshot.signature)
            .map_err(|_| crate::G05Error::AuthorityUnavailable)?;
        VerifyingKey::from_bytes(&public_key.try_into()
            .map_err(|_| crate::G05Error::AuthorityUnavailable)?)
            .map_err(|_| crate::G05Error::AuthorityUnavailable)?
            .verify(&signing_bytes, &signature)
            .map_err(|_| crate::G05Error::AuthorityUnavailable)?;

        Ok(iroka_kernel::Policy::new(
            payload.policy_version,
            payload.allowed_capabilities,
            payload.approval_required,
            payload.maximum_risk.into(),
        ))
    }
}
