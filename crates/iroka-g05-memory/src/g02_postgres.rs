//! PostgreSQL-backed G09 policy and tenant-scope resolver.
//!
//! Every lookup uses the primary connection configured with verify-full TLS.
//! Snapshot authenticity is delegated to an injected verifier backed by the
//! canonical G02 pinned trust-root/revocation authority; database rows alone
//! are never treated as authorization evidence.
use std::sync::{Arc, Mutex};

use native_tls::TlsConnector;
use postgres::{Client, Row};
use sha2::{Digest, Sha256};
use postgres_native_tls::MakeTlsConnector;
use iroka_kernel::{Policy, VerifiedPrincipal};

use crate::{AuthorizationRequest, G05Error, G09PolicyResolver};

/// Must verify the exact canonical payload, digest, domain-separated signature,
/// Owner subject/key validity and current key revocation against canonical G02
/// trust roots, then decode only the verified payload into a kernel Policy.
pub trait G02PolicySnapshotVerifier: Send + Sync {
    fn verify_snapshot(&self, snapshot: &G02PolicySnapshot, now: u64)
        -> Result<Policy, G05Error>;
}

#[derive(Debug, Clone)]
pub struct G02PolicySnapshot {
    pub policy_id: String,
    pub epoch: u64,
    pub policy_version: String,
    pub owner_subject: String,
    pub signer_issuer: String,
    pub signer_key_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub canonical_payload: Vec<u8>,
    pub payload_sha256: String,
    pub signature: Vec<u8>,
}

#[derive(Clone)]
pub struct PostgresG09PolicyResolver<V> {
    client: Arc<Mutex<Client>>,
    policy_id: String,
    verifier: Arc<V>,
}

impl<V: G02PolicySnapshotVerifier> PostgresG09PolicyResolver<V> {
    /// Remote connections require PostgreSQL verify-full TLS (chain + hostname).
    pub fn connect(
        connection_string: &str,
        policy_id: impl Into<String>,
        verifier: Arc<V>,
    ) -> Result<Self, G05Error> {
        let policy_id = policy_id.into();
        if !connection_string.contains("sslmode=verify-full")
            || policy_id.trim().is_empty()
            || policy_id.len() > 128
        {
            return Err(G05Error::RepositoryUnavailable);
        }
        let tls = TlsConnector::builder()
            .build()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let client = Client::connect(connection_string, MakeTlsConnector::new(tls))
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        Ok(Self { client: Arc::new(Mutex::new(client)), policy_id, verifier })
    }

    /// Fail readiness unless all required G02 authority tables exist.
    pub fn verify_schema(&self) -> Result<(), G05Error> {
        let mut client = self.client.lock().map_err(|_| G05Error::AuthorityUnavailable)?;
        let row = client.query_one(
            "SELECT to_regclass('public.g02_policy_snapshots') IS NOT NULL
                AND to_regclass('public.g02_policy_heads') IS NOT NULL
                AND to_regclass('public.g02_policy_revocations') IS NOT NULL
                AND to_regclass('public.g02_emergency_stop') IS NOT NULL
                AND to_regclass('public.g02_tenant_memberships') IS NOT NULL",
            &[],
        ).map_err(|_| G05Error::AuthorityUnavailable)?;
        if row.get::<_, bool>(0) { Ok(()) } else { Err(G05Error::AuthorityUnavailable) }
    }

    fn snapshot_from_row(row: &Row) -> Result<G02PolicySnapshot, G05Error> {
        let epoch: i64 = row.get("epoch");
        let issued_at: i64 = row.get("issued_at");
        let expires_at: i64 = row.get("expires_at");
        let digest: String = row.get("payload_sha256");
        let canonical_payload: Vec<u8> = row.get("canonical_payload");
        let signature: Vec<u8> = row.get("signature");
        if !valid_snapshot_shape(epoch, issued_at, expires_at, &digest, &canonical_payload, &signature) {
            return Err(G05Error::AuthorityUnavailable);
        }
        let computed = Sha256::digest(&canonical_payload);
        let computed_hex = computed.iter().map(|b| format!("{b:02x}")).collect::<String>();
        if computed_hex != digest.trim().to_ascii_lowercase() {
            return Err(G05Error::AuthorityUnavailable);
        }
        Ok(G02PolicySnapshot {
            policy_id: row.get("policy_id"),
            epoch: u64::try_from(epoch).map_err(|_| G05Error::AuthorityUnavailable)?,
            policy_version: row.get("policy_version"),
            owner_subject: row.get("owner_subject"),
            signer_issuer: row.get("signer_issuer"),
            signer_key_id: row.get("signer_key_id"),
            issued_at: u64::try_from(issued_at).map_err(|_| G05Error::AuthorityUnavailable)?,
            expires_at: u64::try_from(expires_at).map_err(|_| G05Error::AuthorityUnavailable)?,
            canonical_payload,
            payload_sha256: digest.trim().to_owned(),
            signature,
        })
    }
}

fn valid_snapshot_shape(epoch: i64, issued_at: i64, expires_at: i64, digest: &str, payload: &[u8], signature: &[u8]) -> bool {
    epoch > 0
        && issued_at >= 0
        && expires_at > issued_at
        && digest.trim().len() == 64
        && digest.trim().bytes().all(|b| b.is_ascii_hexdigit())
        && !payload.is_empty()
        && signature.len() == 64
}

impl<V: G02PolicySnapshotVerifier> G09PolicyResolver for PostgresG09PolicyResolver<V> {
    fn current_policy(&self, now: u64) -> Result<(Policy, bool), G05Error> {
        let now_i = i64::try_from(now).map_err(|_| G05Error::AuthorityUnavailable)?;
        let mut client = self.client.lock().map_err(|_| G05Error::AuthorityUnavailable)?;
        let mut tx = client.transaction().map_err(|_| G05Error::AuthorityUnavailable)?;
        tx.batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .map_err(|_| G05Error::AuthorityUnavailable)?;
        // Both policy and emergency-stop reads share one MVCC snapshot.
        let row = tx.query_opt(
            "SELECT s.policy_id,s.epoch,s.policy_version,s.owner_subject,
                    s.signer_issuer,s.signer_key_id,s.issued_at,s.expires_at,
                    s.canonical_payload,s.payload_sha256,s.signature
             FROM g02_policy_heads h
             JOIN g02_policy_snapshots s
               ON s.policy_id=h.policy_id AND s.epoch=h.current_epoch
              AND s.payload_sha256=h.current_payload_sha256
             WHERE h.policy_id=$1 AND s.issued_at <= $2 AND s.expires_at > $2
               AND NOT EXISTS (
                 SELECT 1 FROM g02_policy_revocations r
                 WHERE r.policy_id=s.policy_id AND r.epoch=s.epoch
               )",
            &[&self.policy_id, &now_i],
        ).map_err(|_| G05Error::AuthorityUnavailable)?
         .ok_or(G05Error::AuthorizationDenied)?;
        let snapshot = Self::snapshot_from_row(&row)?;
        let policy = self.verifier.verify_snapshot(&snapshot, now)?;
        let emergency = tx.query_opt(
            "SELECT active,version,changed_at FROM g02_emergency_stop WHERE singleton=TRUE",
            &[],
        ).map_err(|_| G05Error::AuthorityUnavailable)?
         .ok_or(G05Error::AuthorityUnavailable)?;
        let active: bool = emergency.get(0);
        let version: i64 = emergency.get(1);
        let changed_at: i64 = emergency.get(2);
        if version <= 0 || changed_at < 0 || changed_at > now_i {
            return Err(G05Error::AuthorityUnavailable);
        }
        tx.commit().map_err(|_| G05Error::AuthorityUnavailable)?;
        Ok((policy, active))
    }

    fn authorize_resource_scope(
        &self,
        principal: &VerifiedPrincipal,
        request: &AuthorizationRequest,
        _now: u64,
    ) -> Result<(), G05Error> {
        if request.principal_ref != principal.subject()
            || request.tenant_ref.trim().is_empty()
        {
            return Err(G05Error::AuthorizationDenied);
        }
        let mut client = self.client.lock().map_err(|_| G05Error::AuthorityUnavailable)?;
        let row = client.query_opt(
            "SELECT active,version FROM g02_tenant_memberships
             WHERE subject_ref=$1 AND tenant_ref=$2",
            &[&request.principal_ref, &request.tenant_ref],
        ).map_err(|_| G05Error::AuthorityUnavailable)?
         .ok_or(G05Error::TenantScopeMismatch)?;
        let active: bool = row.get(0);
        let version: i64 = row.get(1);
        if !active || version <= 0 {
            return Err(G05Error::TenantScopeMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::valid_snapshot_shape;

    #[test]
    fn malformed_snapshot_rows_fail_closed() {
        let payload = b"{\"policy\":\"signed\"}";
        let signature = [9u8; 64];
        assert!(valid_snapshot_shape(1, 10, 20, &"a".repeat(64), payload, &signature));
        assert!(!valid_snapshot_shape(0, 10, 20, &"a".repeat(64), payload, &signature));
        assert!(!valid_snapshot_shape(1, 20, 20, &"a".repeat(64), payload, &signature));
        assert!(!valid_snapshot_shape(1, 10, 20, "bad", payload, &signature));
        assert!(!valid_snapshot_shape(1, 10, 20, &"a".repeat(64), &[], &signature));
        assert!(!valid_snapshot_shape(1, 10, 20, &"a".repeat(64), payload, &[1u8; 63]));
    }
}
