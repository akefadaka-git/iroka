//! Multi-worker delivery for the transactional G02 authority outbox.
//! Claim leases use PostgreSQL time and SKIP LOCKED; sinks must deduplicate by
//! event_id because delivery is at-least-once.
use std::sync::{Arc, Mutex};

use native_tls::TlsConnector;
use postgres::{Client, Row};
use postgres_native_tls::MakeTlsConnector;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum G02OutboxError {
    Configuration,
    Unavailable,
    LeaseLost,
    Malformed,
}

#[derive(Debug, Clone, PartialEq)]
pub struct G02AuthorityOutboxEvent {
    pub event_id: String,
    pub command_id: String,
    pub event_kind: String,
    pub payload_sha256: String,
    pub payload_json: Value,
    pub occurred_at: i64,
    pub attempt_count: i64,
    pub lease_token: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct G02OutboxDispatchStats {
    pub claimed: usize,
    pub acknowledged: usize,
    pub retry_scheduled: usize,
}

pub trait G02AuthorityEventSink: Send + Sync {
    /// Return a SHA-256 digest of the sink's durable acknowledgement.
    /// Implementations must deduplicate on event_id.
    fn deliver(&self, event: &G02AuthorityOutboxEvent) -> Result<String, G02OutboxError>;
}

#[derive(Clone)]
pub struct PostgresG02AuthorityOutboxWorker {
    client: Arc<Mutex<Client>>,
}

impl PostgresG02AuthorityOutboxWorker {
    pub fn connect(connection_string: &str) -> Result<Self, G02OutboxError> {
        if !connection_string.contains("sslmode=verify-full") {
            return Err(G02OutboxError::Configuration);
        }
        let tls = TlsConnector::builder().build().map_err(|_| G02OutboxError::Unavailable)?;
        let client = Client::connect(connection_string, MakeTlsConnector::new(tls))
            .map_err(|_| G02OutboxError::Unavailable)?;
        Ok(Self { client: Arc::new(Mutex::new(client)) })
    }

    pub fn verify_schema(&self) -> Result<(), G02OutboxError> {
        let mut client = self.client.lock().map_err(|_| G02OutboxError::Unavailable)?;
        let row = client.query_one(
            "SELECT to_regclass('public.g02_authority_outbox') IS NOT NULL
              AND EXISTS (SELECT 1 FROM information_schema.columns
                          WHERE table_schema='public' AND table_name='g02_authority_outbox'
                            AND column_name='acknowledgment_sha256')
              AND EXISTS (SELECT 1 FROM information_schema.columns
                          WHERE table_schema='public' AND table_name='g02_authority_outbox'
                            AND column_name='last_error_code')",
            &[],
        ).map_err(|_| G02OutboxError::Unavailable)?;
        if row.get::<_, bool>(0) { Ok(()) } else { Err(G02OutboxError::Unavailable) }
    }

    #[cfg(test)]
    pub(crate) fn from_client_for_test(client: Client) -> Self {
        Self { client: Arc::new(Mutex::new(client)) }
    }

    pub fn claim_batch(
        &self,
        worker_id: &str,
        lease_token: &str,
        limit: usize,
        lease_secs: u64,
    ) -> Result<Vec<G02AuthorityOutboxEvent>, G02OutboxError> {
        if worker_id.trim().is_empty() || worker_id.len() > 128
            || !valid_uuid(lease_token) || limit == 0 || limit > 500
            || lease_secs == 0 || lease_secs > 3_600
        {
            return Err(G02OutboxError::Malformed);
        }
        let limit = i64::try_from(limit).map_err(|_| G02OutboxError::Malformed)?;
        let lease_secs = i64::try_from(lease_secs).map_err(|_| G02OutboxError::Malformed)?;
        let mut client = self.client.lock().map_err(|_| G02OutboxError::Unavailable)?;
        let mut tx = client.transaction().map_err(|_| G02OutboxError::Unavailable)?;
        let rows = tx.query(
            "WITH ready AS (
                SELECT event_id
                FROM g02_authority_outbox
                WHERE delivered_at IS NULL
                  AND next_attempt_at <= clock_timestamp()
                  AND (lease_token IS NULL OR lease_expires_at <= clock_timestamp())
                ORDER BY occurred_at,event_id
                LIMIT $1
                FOR UPDATE SKIP LOCKED
             )
             UPDATE g02_authority_outbox AS o
             SET lease_owner=$2,
                 lease_token=$3::uuid,
                 lease_expires_at=clock_timestamp()+($4 * INTERVAL '1 second'),
                 attempt_count=o.attempt_count+1
             FROM ready
             WHERE o.event_id=ready.event_id
             RETURNING o.event_id,o.command_id,o.event_kind,o.payload_sha256,
                       o.payload_json,o.occurred_at,o.attempt_count",
            &[&limit, &worker_id, &lease_token, &lease_secs],
        ).map_err(|error| {
            #[cfg(test)]
            eprintln!("G02 outbox claim SQL error: {error}");
            G02OutboxError::Unavailable
        })?;
        let events = rows.iter().map(|row| event_from_row(row, lease_token))
            .collect::<Result<Vec<_>, _>>()?;
        tx.commit().map_err(|_| G02OutboxError::Unavailable)?;
        Ok(events)
    }

    pub fn acknowledge(
        &self,
        event_id: &str,
        lease_token: &str,
        acknowledgment_sha256: &str,
    ) -> Result<(), G02OutboxError> {
        if event_id.trim().is_empty() || !valid_uuid(lease_token) || !valid_digest(acknowledgment_sha256) {
            return Err(G02OutboxError::Malformed);
        }
        let mut client = self.client.lock().map_err(|_| G02OutboxError::Unavailable)?;
        let changed = client.execute(
            "UPDATE g02_authority_outbox
             SET delivered_at=clock_timestamp(),acknowledgment_sha256=$3,
                 lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,last_error_code=NULL
             WHERE event_id=$1 AND lease_token=$2::uuid AND delivered_at IS NULL",
            &[&event_id,&lease_token,&acknowledgment_sha256],
        ).map_err(|_| G02OutboxError::Unavailable)?;
        if changed == 1 { Ok(()) } else { Err(G02OutboxError::LeaseLost) }
    }

    pub fn schedule_retry(
        &self,
        event_id: &str,
        lease_token: &str,
        error_code: &str,
        retry_delay_secs: u64,
    ) -> Result<(), G02OutboxError> {
        if event_id.trim().is_empty() || !valid_uuid(lease_token)
            || !valid_error_code(error_code) || retry_delay_secs == 0 || retry_delay_secs > 86_400
        {
            return Err(G02OutboxError::Malformed);
        }
        let delay = i64::try_from(retry_delay_secs).map_err(|_| G02OutboxError::Malformed)?;
        let mut client = self.client.lock().map_err(|_| G02OutboxError::Unavailable)?;
        let changed = client.execute(
            "UPDATE g02_authority_outbox
             SET next_attempt_at=clock_timestamp()+($3 * INTERVAL '1 second'),
                 lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,last_error_code=$4
             WHERE event_id=$1 AND lease_token=$2::uuid AND delivered_at IS NULL",
            &[&event_id,&lease_token,&delay,&error_code],
        ).map_err(|_| G02OutboxError::Unavailable)?;
        if changed == 1 { Ok(()) } else { Err(G02OutboxError::LeaseLost) }
    }

    pub fn dispatch_once<S: G02AuthorityEventSink>(
        &self,
        worker_id: &str,
        lease_token: &str,
        limit: usize,
        lease_secs: u64,
        retry_delay_secs: u64,
        sink: &S,
    ) -> Result<G02OutboxDispatchStats, G02OutboxError> {
        let events = self.claim_batch(worker_id, lease_token, limit, lease_secs)?;
        let mut stats = G02OutboxDispatchStats { claimed: events.len(), ..Default::default() };
        for event in events {
            match sink.deliver(&event) {
                Ok(ack) => {
                    self.acknowledge(&event.event_id, &event.lease_token, &ack)?;
                    stats.acknowledged += 1;
                }
                Err(_) => {
                    self.schedule_retry(
                        &event.event_id,
                        &event.lease_token,
                        "sink_delivery_failed",
                        retry_delay_secs,
                    )?;
                    stats.retry_scheduled += 1;
                }
            }
        }
        Ok(stats)
    }
}

fn event_from_row(row: &Row, lease_token: &str) -> Result<G02AuthorityOutboxEvent, G02OutboxError> {
    let payload: postgres::types::Json<Value> = row.get("payload_json");
    let payload_sha256: String = row.get("payload_sha256");
    if !valid_digest(payload_sha256.trim()) {
        return Err(G02OutboxError::Malformed);
    }
    Ok(G02AuthorityOutboxEvent {
        event_id: row.get("event_id"),
        command_id: row.get("command_id"),
        event_kind: row.get("event_kind"),
        payload_sha256: payload_sha256.trim().to_owned(),
        payload_json: payload.0,
        occurred_at: row.get("occurred_at"),
        attempt_count: row.get("attempt_count"),
        lease_token: lease_token.to_owned(),
    })
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i,b)| {
            if [8,13,18,23].contains(&i) { b == b'-' } else { b.is_ascii_hexdigit() }
        })
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn valid_error_code(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64
        && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_and_ack_inputs_are_strictly_bounded() {
        assert!(valid_uuid("11111111-1111-4111-8111-111111111111"));
        assert!(!valid_uuid("not-a-uuid"));
        assert!(valid_digest(&"a".repeat(64)));
        assert!(!valid_digest("short"));
        assert!(valid_error_code("sink_delivery_failed"));
        assert!(!valid_error_code("bad\r\n"));
    }
}
