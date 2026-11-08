//! Owner-rooted, signed and monotonic policy loading for CIW.
//! The root is supplied only by trusted application composition; it is not
//! derived from a credential trust bundle or from request/model data.

use std::sync::Mutex;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use iroka_kernel::{Policy, RiskLevel};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    InvalidRoot,
    RootOutsideValidity,
    Malformed,
    InvalidSignature,
    NotYetValid,
    Expired,
    ExcessiveLifetime,
    Rollback,
    Equivocation,
    StoreUnavailable,
}

#[derive(Debug, Clone)]
pub struct PolicyTrustRoot {
    key_id: String,
    public_key: [u8; 32],
    not_before: u64,
    not_after: u64,
    _provenance: String,
}
impl PolicyTrustRoot {
    /// Provision this value from a separately Owner-authorized policy-signing root.
    pub fn provisioned(
        key_id: String,
        public_key: [u8; 32],
        not_before: u64,
        not_after: u64,
        provenance: String,
    ) -> Result<Self, PolicyError> {
        if key_id.trim().is_empty()
            || provenance.trim().is_empty()
            || not_before >= not_after
            || VerifyingKey::from_bytes(&public_key).is_err()
        {
            return Err(PolicyError::InvalidRoot);
        }
        Ok(Self {
            key_id,
            public_key,
            not_before,
            not_after,
            _provenance: provenance,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetLimits {
    pub max_input_bytes: u64,
    pub max_output_tokens: u32,
    pub max_concurrent_per_subject: u32,
    pub max_concurrent_per_tenant: u32,
    pub requests_per_minute: u32,
    pub max_wall_clock_ms: u64,
    pub max_retries: u32,
    pub max_spend_micro_units_per_day: u64,
}
impl BudgetLimits {
    fn is_valid(&self) -> bool {
        self.max_input_bytes > 0
            && self.max_output_tokens > 0
            && self.max_concurrent_per_subject > 0
            && self.max_concurrent_per_tenant > 0
            && self.requests_per_minute > 0
            && self.max_wall_clock_ms > 0
            && self.max_retries > 0
            && self.max_spend_micro_units_per_day > 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPayload {
    pub schema_version: u32,
    pub epoch: u64,
    pub version: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub allowed_capabilities: Vec<String>,
    pub approval_required: Vec<String>,
    pub maximum_risk: String,
    pub budget_limits: BudgetLimits,
}

#[derive(Debug, Clone)]
pub struct SignedPolicyBundle {
    pub root_key_id: String,
    pub payload: PolicyPayload,
    pub signature: Vec<u8>,
}
impl SignedPolicyBundle {
    pub fn signing_bytes(payload: &PolicyPayload) -> Result<Vec<u8>, PolicyError> {
        serde_json::to_vec(payload).map_err(|_| PolicyError::Malformed)
    }
}

pub struct PolicyVersionStore {
    db: Mutex<Connection>,
}
impl PolicyVersionStore {
    pub fn open(path: &str) -> Result<Self, PolicyError> {
        let db = Connection::open(path).map_err(|_| PolicyError::StoreUnavailable)?;
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS policy_versions(
          singleton INTEGER PRIMARY KEY CHECK(singleton=1), epoch INTEGER NOT NULL,
          digest TEXT NOT NULL, version TEXT NOT NULL);",
        )
        .map_err(|_| PolicyError::StoreUnavailable)?;
        Ok(Self { db: Mutex::new(db) })
    }
    pub fn open_in_memory() -> Result<Self, PolicyError> {
        let db = Connection::open_in_memory().map_err(|_| PolicyError::StoreUnavailable)?;
        db.execute_batch(
            "CREATE TABLE policy_versions(
          singleton INTEGER PRIMARY KEY CHECK(singleton=1), epoch INTEGER NOT NULL,
          digest TEXT NOT NULL, version TEXT NOT NULL);",
        )
        .map_err(|_| PolicyError::StoreUnavailable)?;
        Ok(Self { db: Mutex::new(db) })
    }
    fn accept(&self, epoch: u64, digest: &str, version: &str) -> Result<(), PolicyError> {
        let db = self.db.lock().map_err(|_| PolicyError::StoreUnavailable)?;
        let tx = db
            .unchecked_transaction()
            .map_err(|_| PolicyError::StoreUnavailable)?;
        let current: Option<(u64, String)> = tx
            .query_row(
                "SELECT epoch,digest FROM policy_versions WHERE singleton=1",
                [],
                |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?)),
            )
            .optional()
            .map_err(|_| PolicyError::StoreUnavailable)?;
        if let Some((old, old_digest)) = current {
            if epoch < old {
                return Err(PolicyError::Rollback);
            }
            if epoch == old && digest != old_digest {
                return Err(PolicyError::Equivocation);
            }
        }
        tx.execute(
            "INSERT INTO policy_versions(singleton,epoch,digest,version)
          VALUES(1,?1,?2,?3) ON CONFLICT(singleton) DO UPDATE SET
          epoch=excluded.epoch,digest=excluded.digest,version=excluded.version
          WHERE excluded.epoch > policy_versions.epoch",
            params![epoch as i64, digest, version],
        )
        .map_err(|_| PolicyError::StoreUnavailable)?;
        tx.commit().map_err(|_| PolicyError::StoreUnavailable)?;
        Ok(())
    }
}

pub struct VerifiedPolicy {
    policy: Policy,
    epoch: u64,
    digest: String,
    version: String,
    budget_limits: BudgetLimits,
}
impl VerifiedPolicy {
    pub fn load(
        bundle: &SignedPolicyBundle,
        root: &PolicyTrustRoot,
        store: &PolicyVersionStore,
        now: u64,
    ) -> Result<Self, PolicyError> {
        if bundle.root_key_id != root.key_id {
            return Err(PolicyError::InvalidRoot);
        }
        if now < root.not_before || now >= root.not_after {
            return Err(PolicyError::RootOutsideValidity);
        }
        let p = &bundle.payload;
        if p.schema_version != 1
            || p.epoch == 0
            || p.version.trim().is_empty()
            || p.issued_at >= p.expires_at
            || p.allowed_capabilities.is_empty()
            || p.allowed_capabilities.iter().any(|x| x.trim().is_empty())
            || p.allowed_capabilities.windows(2).any(|w| w[0] >= w[1])
            || p.approval_required.windows(2).any(|w| w[0] >= w[1])
            || p.approval_required
                .iter()
                .any(|x| !p.allowed_capabilities.contains(x))
        {
            return Err(PolicyError::Malformed);
        }
        if p.issued_at > now.saturating_add(30) {
            return Err(PolicyError::NotYetValid);
        }
        if p.expires_at <= now {
            return Err(PolicyError::Expired);
        }
        if p.expires_at - p.issued_at > 2_592_000 {
            return Err(PolicyError::ExcessiveLifetime);
        }
        let risk = match p.maximum_risk.as_str() {
            "low" => RiskLevel::Low,
            "moderate" => RiskLevel::Moderate,
            "high" => RiskLevel::High,
            "critical" => RiskLevel::Critical,
            _ => return Err(PolicyError::Malformed),
        };
        let bytes = SignedPolicyBundle::signing_bytes(p)?;
        let key =
            VerifyingKey::from_bytes(&root.public_key).map_err(|_| PolicyError::InvalidRoot)?;
        let sig = Signature::from_slice(&bundle.signature).map_err(|_| PolicyError::Malformed)?;
        key.verify(&bytes, &sig)
            .map_err(|_| PolicyError::InvalidSignature)?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        store.accept(p.epoch, &digest, &p.version)?;
        Ok(Self {
            policy: Policy::new(
                p.version.clone(),
                p.allowed_capabilities.clone(),
                p.approval_required.clone(),
                risk,
            ),
            epoch: p.epoch,
            digest,
            version: p.version.clone(),
            budget_limits: p.budget_limits.clone(),
        })
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn budget_limits(&self) -> &BudgetLimits {
        &self.budget_limits
    }
    #[allow(dead_code)]
    fn _root_provenance_is_not_runtime_data(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed(epoch: u64, version: &str, signer: &SigningKey) -> SignedPolicyBundle {
        let payload = PolicyPayload {
            schema_version: 1,
            epoch,
            version: version.into(),
            issued_at: 10,
            expires_at: 500,
            allowed_capabilities: vec!["conversation.create".into(), "conversation.read".into()],
            approval_required: vec![],
            maximum_risk: "low".into(),
            budget_limits: BudgetLimits {
                max_input_bytes: 16_384,
                max_output_tokens: 2_048,
                max_concurrent_per_subject: 2,
                max_concurrent_per_tenant: 10,
                requests_per_minute: 20,
                max_wall_clock_ms: 30_000,
                max_retries: 1,
                max_spend_micro_units_per_day: 1_000_000,
            },
        };
        let signature = signer
            .sign(&SignedPolicyBundle::signing_bytes(&payload).unwrap())
            .to_bytes()
            .to_vec();
        SignedPolicyBundle {
            root_key_id: "policy-root".into(),
            payload,
            signature,
        }
    }
    fn root(signer: &SigningKey) -> PolicyTrustRoot {
        PolicyTrustRoot::provisioned(
            "policy-root".into(),
            signer.verifying_key().to_bytes(),
            1,
            1_000,
            "owner-authorized-test-root".into(),
        )
        .unwrap()
    }
    #[test]
    fn accepts_signed_policy_and_pins_digest() {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let store = PolicyVersionStore::open_in_memory().unwrap();
        let verified =
            VerifiedPolicy::load(&signed(1, "v1", &signer), &root(&signer), &store, 100).unwrap();
        assert_eq!(verified.epoch(), 1);
        assert_eq!(verified.version(), "v1");
        assert_eq!(verified.policy().version(), "v1");
        assert_eq!(verified.digest().len(), 64);
    }
    #[test]
    fn rejects_signature_tampering_and_epoch_rollback() {
        let signer = SigningKey::from_bytes(&[8u8; 32]);
        let root = root(&signer);
        let store = PolicyVersionStore::open_in_memory().unwrap();
        let current = signed(2, "v2", &signer);
        VerifiedPolicy::load(&current, &root, &store, 100).unwrap();
        let older = signed(1, "v1", &signer);
        assert_eq!(
            VerifiedPolicy::load(&older, &root, &store, 100).err(),
            Some(PolicyError::Rollback)
        );
        let mut tampered = signed(3, "v3", &signer);
        tampered.payload.version = "changed".into();
        assert_eq!(
            VerifiedPolicy::load(&tampered, &root, &store, 100).err(),
            Some(PolicyError::InvalidSignature)
        );
    }
    #[test]
    fn rejects_expired_and_ambiguous_policy_documents() {
        let signer = SigningKey::from_bytes(&[9u8; 32]);
        let root = root(&signer);
        let store = PolicyVersionStore::open_in_memory().unwrap();
        let mut expired = signed(1, "v1", &signer);
        expired.payload.expires_at = 20;
        expired.signature = signer
            .sign(&SignedPolicyBundle::signing_bytes(&expired.payload).unwrap())
            .to_bytes()
            .to_vec();
        assert_eq!(
            VerifiedPolicy::load(&expired, &root, &store, 100).err(),
            Some(PolicyError::Expired)
        );
        let mut malformed = signed(1, "v1", &signer);
        malformed.payload.allowed_capabilities.reverse();
        malformed.signature = signer
            .sign(&SignedPolicyBundle::signing_bytes(&malformed.payload).unwrap())
            .to_bytes()
            .to_vec();
        assert_eq!(
            VerifiedPolicy::load(&malformed, &root, &store, 100).err(),
            Some(PolicyError::Malformed)
        );
    }
}
