//! PostgreSQL multi-worker lease operations for the G05 -> G11 outbox.
//! Claims are committed before network I/O; delivery is at-least-once and G11
//! must deduplicate stable event IDs and payload digests.
use crate::{audit_event_sha256, AuditEvent, G05Error, G11Acknowledgment};
use native_tls::TlsConnector;
use postgres::{Client, Row};
use postgres_native_tls::MakeTlsConnector;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeasedG11Event {
    pub event: AuditEvent,
    pub lease_owner: String,
    pub lease_token: String,
}

#[derive(Clone)]
pub struct PostgresG11OutboxStore {
    client: Arc<Mutex<Client>>,
}

impl PostgresG11OutboxStore {
    /// Connect using system trust roots and certificate/hostname validation.
    /// The connection string must use sslmode=require or verify-full; callers
    /// should use verify-full in production.
    pub fn connect(connection_string: &str) -> Result<Self, G05Error> {
        if !(connection_string.contains("sslmode=require")
            || connection_string.contains("sslmode=verify-ca")
            || connection_string.contains("sslmode=verify-full"))
        {
            return Err(G05Error::RepositoryUnavailable);
        }
        let tls = TlsConnector::builder()
            .build()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let connector = MakeTlsConnector::new(tls);
        let client = Client::connect(connection_string, connector)
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        Ok(Self {
            client: Arc::new(Mutex::new(client)),
        })
    }

    /// Atomically claim a bounded batch. PostgreSQL's SKIP LOCKED permits
    /// concurrent workers without handing the same live lease to two workers.
    /// Expired leases are reclaimable after a worker crash/restart.
    pub fn claim_batch(
        &self,
        worker_id: &str,
        limit: i64,
        lease_seconds: i64,
    ) -> Result<Vec<LeasedG11Event>, G05Error> {
        if worker_id.trim().is_empty()
            || worker_id.len() > 256
            || !(1..=500).contains(&limit)
            || !(5..=900).contains(&lease_seconds)
        {
            return Err(G05Error::MalformedRecord);
        }
        let mut client = self.client.lock().map_err(|_| G05Error::RepositoryUnavailable)?;
        let rows = client
            .query(
                "WITH picked AS (
                    SELECT event_id
                    FROM g05_memory_g11_outbox
                    WHERE delivered_at IS NULL
                      AND next_attempt_at <= clock_timestamp()
                      AND (lease_token IS NULL OR lease_expires_at <= clock_timestamp())
                    ORDER BY occurred_at, event_id
                    FOR UPDATE SKIP LOCKED
                    LIMIT $2
                 )
                 UPDATE g05_memory_g11_outbox AS o
                 SET lease_owner = $1,
                     lease_token = gen_random_uuid(),
                     lease_expires_at = clock_timestamp() + ($3 * interval '1 second'),
                     attempt_count = o.attempt_count + 1
                 FROM picked
                 WHERE o.event_id = picked.event_id
                 RETURNING o.payload_json::text, o.lease_token::text",
                &[&worker_id, &limit, &lease_seconds],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        rows.into_iter()
            .map(|row| decode_claim(row, worker_id))
            .collect()
    }

    /// Accept only the current lease owner/token and exact event digest.
    /// Repeated acknowledgments for the same digest are idempotent.
    pub fn acknowledge(
        &self,
        claim: &LeasedG11Event,
        acknowledgment: &G11Acknowledgment,
    ) -> Result<(), G05Error> {
        if acknowledgment.event_id() != claim.event.event_id
            || acknowledgment.payload_sha256() != audit_event_sha256(&claim.event)
            || acknowledgment.accepted_at() < claim.event.occurred_at
        {
            return Err(G05Error::AuditUnavailable);
        }
        let mut client = self.client.lock().map_err(|_| G05Error::RepositoryUnavailable)?;
        let tx = client.transaction().map_err(|_| G05Error::RepositoryUnavailable)?;
        let stored = tx
            .query_opt(
                "SELECT payload_sha256, delivered_at, acknowledgment_sha256,
                        lease_owner, lease_token::text, lease_expires_at
                 FROM g05_memory_g11_outbox WHERE event_id = $1 FOR UPDATE",
                &[&claim.event.event_id],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?
            .ok_or(G05Error::RecordNotFound)?;
        let digest: String = stored.get(0);
        let delivered_at: Option<i64> = stored.get(1);
        let old_ack: Option<String> = stored.get(2);
        if digest != audit_event_sha256(&claim.event) {
            return Err(G05Error::AuditUnavailable);
        }
        if let Some(old_ack) = old_ack {
            if old_ack == acknowledgment.payload_sha256() && delivered_at.is_some() {
                return Ok(());
            }
            return Err(G05Error::AuditUnavailable);
        }
        let owner: Option<String> = stored.get(3);
        let token: Option<String> = stored.get(4);
        let lease_expiry: Option<std::time::SystemTime> = stored.get(5);
        if owner.as_deref() != Some(claim.lease_owner.as_str())
            || token.as_deref() != Some(claim.lease_token.as_str())
            || lease_expiry.is_none()
        {
            return Err(G05Error::AuditUnavailable);
        }
        let updated = tx
            .execute(
                "UPDATE g05_memory_g11_outbox
                 SET delivered_at = $4, acknowledgment_sha256 = $5,
                     lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL,
                     last_error_code = NULL
                 WHERE event_id = $1 AND lease_owner = $2 AND lease_token = $3::uuid
                   AND delivered_at IS NULL AND lease_expires_at > clock_timestamp()",
                &[
                    &claim.event.event_id,
                    &claim.lease_owner,
                    &claim.lease_token,
                    &(acknowledgment.accepted_at() as i64),
                    &acknowledgment.payload_sha256(),
                ],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        if updated != 1 {
            return Err(G05Error::AuditUnavailable);
        }
        tx.commit().map_err(|_| G05Error::RepositoryUnavailable)
    }

    /// Release a failed claim and schedule bounded retry. The caller supplies
    /// a capped delay; database time determines the actual retry deadline.
    pub fn schedule_retry(
        &self,
        claim: &LeasedG11Event,
        error_code: &str,
        retry_after_seconds: i64,
    ) -> Result<(), G05Error> {
        if error_code.trim().is_empty()
            || error_code.len() > 96
            || !(1..=86_400).contains(&retry_after_seconds)
        {
            return Err(G05Error::MalformedRecord);
        }
        let mut client = self.client.lock().map_err(|_| G05Error::RepositoryUnavailable)?;
        let updated = client
            .execute(
                "UPDATE g05_memory_g11_outbox
                 SET next_attempt_at = clock_timestamp() + ($4 * interval '1 second'),
                     last_error_code = $5,
                     lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL
                 WHERE event_id = $1 AND lease_owner = $2 AND lease_token = $3::uuid
                   AND delivered_at IS NULL",
                &[
                    &claim.event.event_id,
                    &claim.lease_owner,
                    &claim.lease_token,
                    &retry_after_seconds,
                    &error_code,
                ],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        if updated != 1 {
            return Err(G05Error::VersionConflict);
        }
        Ok(())
    }
}

fn decode_claim(row: Row, worker_id: &str) -> Result<LeasedG11Event, G05Error> {
    let payload: String = row.get(0);
    let lease_token: String = row.get(1);
    let event = serde_json::from_str(&payload).map_err(|_| G05Error::RepositoryUnavailable)?;
    Ok(LeasedG11Event {
        event,
        lease_owner: worker_id.to_owned(),
        lease_token,
    })
}
