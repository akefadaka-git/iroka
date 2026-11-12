//! Shared PostgreSQL persistence for G05 memory records and G11 outbox.
//! G05 mutations and their content-free outbox events commit in one database
//! transaction. G11 workers use separate, durable leases for at-least-once
//! delivery across processes and hosts.
use crate::{
    audit_event_sha256, AuditEvent, G05Error, G11Acknowledgment, G11MemoryAuditAuthority,
    LifecycleState, MemoryMetadata, MemoryRecord, MemoryRepository,
};
use native_tls::TlsConnector;
use postgres::{Client, Row};
use postgres_native_tls::MakeTlsConnector;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct PostgresMemoryRepository {
    client: Arc<Mutex<Client>>,
}

impl PostgresMemoryRepository {
    /// Connect using TLS with full certificate-chain and hostname validation.
    /// Remote connection strings must explicitly use sslmode=verify-full.
    pub fn connect(connection_string: &str) -> Result<Self, G05Error> {
        if !connection_string.contains("sslmode=verify-full") {
            return Err(G05Error::RepositoryUnavailable);
        }
        let tls = TlsConnector::builder()
            .build()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let client = Client::connect(connection_string, MakeTlsConnector::new(tls))
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        Ok(Self {
            client: Arc::new(Mutex::new(client)),
        })
    }

    /// Check that the shared schema migration has been applied before serving.
    pub fn verify_schema(&self) -> Result<(), G05Error> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let row = client
            .query_one(
                "SELECT to_regclass('public.g05_memory_records') IS NOT NULL
                     AND to_regclass('public.g05_memory_g11_outbox') IS NOT NULL
                     AND to_regclass('public.g11_memory_receipts') IS NOT NULL",
                &[],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        if row.get::<_, bool>(0) {
            Ok(())
        } else {
            Err(G05Error::RepositoryUnavailable)
        }
    }
}

fn metadata(record: &MemoryRecord) -> Result<MemoryMetadata, G05Error> {
    Ok(MemoryMetadata {
        memory_id: record.candidate.memory_id.clone(),
        tenant_ref: record.candidate.tenant_ref.clone(),
        subject_ref: record.candidate.subject_ref.clone(),
        memory_class: record.candidate.memory_class,
        content_sha256: record.candidate.content_sha256.clone(),
        purpose: record.candidate.purpose,
        classification: record.candidate.classification,
        lifecycle_state: record.lifecycle_state,
        expires_at: record.candidate.expires_at,
        record_version: record.candidate.record_version,
        retention_policy_ref: record.candidate.retention_policy_ref.clone(),
    })
}

fn validate_event(record: &MemoryRecord, event: &AuditEvent) -> Result<(), G05Error> {
    if event.event_id.trim().is_empty()
        || event.memory_id != record.candidate.memory_id
        || event.tenant_ref != record.candidate.tenant_ref
        || event.record_version != record.candidate.record_version
        || event.content_sha256 != record.candidate.content_sha256
    {
        return Err(G05Error::ApprovalBindingMismatch);
    }
    Ok(())
}

fn json_value<T: serde::Serialize>(value: &T) -> Result<Value, G05Error> {
    serde_json::to_value(value).map_err(|_| G05Error::RepositoryUnavailable)
}

fn insert_outbox(tx: &mut postgres::Transaction<'_>, event: &AuditEvent) -> Result<(), G05Error> {
    if event.event_id.trim().is_empty()
        || event.memory_id.trim().is_empty()
        || event.tenant_ref.trim().is_empty()
        || event.record_version == 0
    {
        return Err(G05Error::MalformedRecord);
    }
    let payload = json_value(event)?;
    let digest = audit_event_sha256(event);
    tx.execute(
        "INSERT INTO g05_memory_g11_outbox
         (event_id,memory_id,tenant_ref,payload_sha256,payload_json,occurred_at)
         VALUES($1,$2,$3,$4,$5,$6)",
        &[
            &event.event_id,
            &event.memory_id,
            &event.tenant_ref,
            &digest,
            &payload,
            &(event.occurred_at as i64),
        ],
    )
    .map_err(|_| G05Error::AuditUnavailable)?;
    Ok(())
}

fn record_columns(record: &MemoryRecord) -> Result<(Value, Value), G05Error> {
    Ok((json_value(&metadata(record)?)?, json_value(record)?))
}

fn enum_text<T: serde::Serialize>(value: &T) -> Result<String, G05Error> {
    serde_json::to_string(value).map_err(|_| G05Error::RepositoryUnavailable)
}

impl MemoryRepository for PostgresMemoryRepository {
    fn insert_with_audit(
        &mut self,
        record: MemoryRecord,
        event: AuditEvent,
    ) -> Result<(), G05Error> {
        validate_event(&record, &event)?;
        if record.candidate.record_version == 0 {
            return Err(G05Error::MalformedRecord);
        }
        let (metadata_json, record_json) = record_columns(&record)?;
        let memory_class = enum_text(&record.candidate.memory_class)?;
        let purpose = enum_text(&record.candidate.purpose)?;
        let classification = enum_text(&record.candidate.classification)?;
        let lifecycle = enum_text(&record.lifecycle_state)?;
        let mut client = self
            .client
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let mut tx = client
            .transaction()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        tx.execute(
            "INSERT INTO g05_memory_records
             (memory_id,tenant_ref,subject_ref,memory_class,content_sha256,purpose,
              classification,lifecycle_state,expires_at,record_version,retention_policy_ref,
              metadata_json,record_json)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
            &[
                &record.candidate.memory_id,
                &record.candidate.tenant_ref,
                &record.candidate.subject_ref,
                &memory_class,
                &record.candidate.content_sha256,
                &purpose,
                &classification,
                &lifecycle,
                &record.candidate.expires_at.map(|v| v as i64),
                &(record.candidate.record_version as i64),
                &record.candidate.retention_policy_ref,
                &metadata_json,
                &record_json,
            ],
        )
        .map_err(|error| {
            if error
                .as_db_error()
                .is_some_and(|db| db.code().code() == "23505")
            {
                G05Error::DuplicateRecord
            } else {
                G05Error::RepositoryUnavailable
            }
        })?;
        insert_outbox(&mut tx, &event)?;
        tx.commit().map_err(|_| G05Error::RepositoryUnavailable)
    }

    fn get_metadata(&self, memory_id: &str) -> Result<Option<MemoryMetadata>, G05Error> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let row = client
            .query_opt(
                "SELECT metadata_json FROM g05_memory_records WHERE memory_id=$1",
                &[&memory_id],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        row.map(|row| {
            let value: Value = row.get(0);
            serde_json::from_value(value).map_err(|_| G05Error::RepositoryUnavailable)
        })
        .transpose()
    }

    fn get_content(&self, memory_id: &str) -> Result<Option<MemoryRecord>, G05Error> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let row = client
            .query_opt(
                "SELECT record_json FROM g05_memory_records WHERE memory_id=$1",
                &[&memory_id],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        row.map(|row| {
            let value: Value = row.get(0);
            serde_json::from_value(value).map_err(|_| G05Error::RepositoryUnavailable)
        })
        .transpose()
    }

    fn replace_with_audit(
        &mut self,
        record: MemoryRecord,
        expected_version: u64,
        event: AuditEvent,
    ) -> Result<(), G05Error> {
        validate_event(&record, &event)?;
        if expected_version == 0
            || record.candidate.record_version != expected_version.saturating_add(1)
        {
            return Err(G05Error::VersionConflict);
        }
        let (metadata_json, record_json) = record_columns(&record)?;
        let lifecycle = enum_text(&record.lifecycle_state)?;
        let purpose = enum_text(&record.candidate.purpose)?;
        let classification = enum_text(&record.candidate.classification)?;
        let mut client = self
            .client
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let mut tx = client
            .transaction()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let current: Option<String> = tx
            .query_opt(
                "SELECT lifecycle_state FROM g05_memory_records
                 WHERE memory_id=$1 AND tenant_ref=$2 AND record_version=$3 FOR UPDATE",
                &[
                    &record.candidate.memory_id,
                    &record.candidate.tenant_ref,
                    &(expected_version as i64),
                ],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?
            .map(|row| row.get(0));
        let current = current.ok_or(G05Error::VersionConflict)?;
        let current: LifecycleState =
            serde_json::from_str(&current).map_err(|_| G05Error::RepositoryUnavailable)?;
        if current == LifecycleState::PendingAudit
            && record.lifecycle_state == LifecycleState::Active
        {
            return Err(G05Error::InvalidLifecycleTransition);
        }
        let changed = tx
            .execute(
                "UPDATE g05_memory_records
                 SET lifecycle_state=$4,record_version=$5,content_sha256=$6,purpose=$7,
                     classification=$8,expires_at=$9,metadata_json=$10,record_json=$11,
                     updated_at=clock_timestamp()
                 WHERE memory_id=$1 AND tenant_ref=$2 AND record_version=$3",
                &[
                    &record.candidate.memory_id,
                    &record.candidate.tenant_ref,
                    &(expected_version as i64),
                    &lifecycle,
                    &(record.candidate.record_version as i64),
                    &record.candidate.content_sha256,
                    &purpose,
                    &classification,
                    &record.candidate.expires_at.map(|v| v as i64),
                    &metadata_json,
                    &record_json,
                ],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        if changed != 1 {
            return Err(G05Error::VersionConflict);
        }
        insert_outbox(&mut tx, &event)?;
        tx.commit().map_err(|_| G05Error::RepositoryUnavailable)
    }

    fn finalize_pending_activation(
        &mut self,
        record: MemoryRecord,
        expected_version: u64,
        event: AuditEvent,
    ) -> Result<(), G05Error> {
        if record.lifecycle_state != LifecycleState::Active
            || record.candidate.record_version != expected_version
            || record.candidate.memory_class != crate::MemoryClass::Durable
            || event.event_type != "memory.durable.activated"
            || event.record_version != expected_version
        {
            return Err(G05Error::InvalidLifecycleTransition);
        }
        validate_event(&record, &event)?;
        let approval = record
            .approval_ref
            .as_deref()
            .ok_or(G05Error::DurableApprovalRequired)?;
        let pending_event_id = format!(
            "g05:durable-activation:{}:{}:{}",
            record.candidate.memory_id, expected_version, approval
        );
        let (metadata_json, record_json) = record_columns(&record)?;
        let mut client = self
            .client
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let mut tx = client
            .transaction()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let state: Option<String> = tx
            .query_opt(
                "SELECT lifecycle_state FROM g05_memory_records
                 WHERE memory_id=$1 AND tenant_ref=$2 AND record_version=$3 FOR UPDATE",
                &[
                    &record.candidate.memory_id,
                    &record.candidate.tenant_ref,
                    &(expected_version as i64),
                ],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?
            .map(|row| row.get(0));
        let state = state.ok_or(G05Error::VersionConflict)?;
        let state: LifecycleState =
            serde_json::from_str(&state).map_err(|_| G05Error::RepositoryUnavailable)?;
        if state != LifecycleState::PendingAudit {
            return Err(G05Error::VersionConflict);
        }
        let receipt = tx
            .query_opt(
                "SELECT payload_json,payload_sha256,delivered_at,acknowledgment_sha256
                 FROM g05_memory_g11_outbox WHERE event_id=$1 FOR UPDATE",
                &[&pending_event_id],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?
            .ok_or(G05Error::AuditUnavailable)?;
        let payload: Value = receipt.get(0);
        let digest: String = receipt.get(1);
        let delivered_at: Option<i64> = receipt.get(2);
        let ack_digest: Option<String> = receipt.get(3);
        let pending: AuditEvent =
            serde_json::from_value(payload).map_err(|_| G05Error::RepositoryUnavailable)?;
        if digest != audit_event_sha256(&pending)
            || pending.event_type != "memory.durable.activation.pending"
            || pending.memory_id != record.candidate.memory_id
            || pending.tenant_ref != record.candidate.tenant_ref
            || pending.record_version != expected_version
            || delivered_at.map_or(true, |accepted| accepted < pending.occurred_at as i64)
            || ack_digest.as_deref() != Some(digest.as_str())
        {
            return Err(G05Error::AuditUnavailable);
        }
        let changed = tx
            .execute(
                "UPDATE g05_memory_records
                 SET lifecycle_state='\"active\"',metadata_json=$4,record_json=$5,
                     updated_at=clock_timestamp()
                 WHERE memory_id=$1 AND tenant_ref=$2 AND record_version=$3
                   AND lifecycle_state='\"pending_audit\"'",
                &[
                    &record.candidate.memory_id,
                    &record.candidate.tenant_ref,
                    &(expected_version as i64),
                    &metadata_json,
                    &record_json,
                ],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        if changed != 1 {
            return Err(G05Error::VersionConflict);
        }
        insert_outbox(&mut tx, &event)?;
        tx.commit().map_err(|_| G05Error::RepositoryUnavailable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeasedG11Event {
    pub event: AuditEvent,
    pub lease_owner: String,
    pub lease_token: String,
    pub attempt_count: i64,
}

/// Multi-process G11 outbox worker. Claims are durable and use database time;
/// network delivery must happen after claim_batch returns and outside SQL
/// transactions. G11 receipt creation must be idempotent by event ID + digest.
#[derive(Clone)]
pub struct PostgresG11OutboxWorker {
    client: Arc<Mutex<Client>>,
}

impl PostgresG11OutboxWorker {
    pub fn connect(connection_string: &str) -> Result<Self, G05Error> {
        if !connection_string.contains("sslmode=verify-full") {
            return Err(G05Error::RepositoryUnavailable);
        }
        let tls = TlsConnector::builder()
            .build()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let client = Client::connect(connection_string, MakeTlsConnector::new(tls))
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        Ok(Self {
            client: Arc::new(Mutex::new(client)),
        })
    }

    /// Atomically claim eligible events. SKIP LOCKED prevents simultaneous
    /// workers from claiming the same live event; expired leases are reclaimed.
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
        let limit = limit as i32;
        let lease_seconds = lease_seconds as f64;
        let mut client = self.client.lock().map_err(|_| {
            eprintln!("claim client mutex poisoned");
            G05Error::RepositoryUnavailable
        })?;
        let mut tx = client.transaction().map_err(|error| {
            eprintln!("claim transaction failed: {error}");
            G05Error::RepositoryUnavailable
        })?;
        let rows = tx
            .query(
                "WITH picked AS (
                    SELECT event_id FROM g05_memory_g11_outbox
                    WHERE delivered_at IS NULL
                      AND next_attempt_at <= clock_timestamp()
                      AND (lease_token IS NULL OR lease_expires_at <= clock_timestamp())
                    ORDER BY occurred_at,event_id
                    LIMIT $1 FOR UPDATE SKIP LOCKED
                 )
                 UPDATE g05_memory_g11_outbox AS o
                 SET lease_owner=pg_backend_pid()::text,lease_token=gen_random_uuid(),
                     lease_expires_at=clock_timestamp()+($2 * interval '1 second'),
                     attempt_count=o.attempt_count+1
                 FROM picked WHERE o.event_id=picked.event_id
                 RETURNING o.payload_json,o.lease_owner,o.lease_token::text,o.attempt_count",
                &[&limit, &lease_seconds],
            )
            .map_err(|error| {
                eprintln!("claim query failed: {error}");
                G05Error::RepositoryUnavailable
            })?;
        let mut claims = Vec::with_capacity(rows.len());
        for row in rows {
            claims.push(decode_claim(row).map_err(|error| {
                eprintln!("claim decode failed: {error:?}");
                error
            })?);
        }
        tx.commit().map_err(|error| {
            eprintln!("claim commit failed: {error}");
            G05Error::RepositoryUnavailable
        })?;
        Ok(claims)
    }

    /// Persist an exact G11 receipt only while this claim's lease is current.
    /// Duplicate matching receipts are accepted idempotently.
    pub fn acknowledge(
        &self,
        claim: &LeasedG11Event,
        acknowledgment: &G11Acknowledgment,
    ) -> Result<(), G05Error> {
        let digest = audit_event_sha256(&claim.event);
        if acknowledgment.event_id() != claim.event.event_id
            || acknowledgment.payload_sha256() != digest
            || acknowledgment.accepted_at() < claim.event.occurred_at
        {
            return Err(G05Error::AuditUnavailable);
        }
        let mut client = self
            .client
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let mut tx = client
            .transaction()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let row = tx
            .query_opt(
                "SELECT payload_sha256,delivered_at,acknowledgment_sha256,lease_owner,
                        lease_token::text,(lease_expires_at > clock_timestamp())
                 FROM g05_memory_g11_outbox WHERE event_id=$1 FOR UPDATE",
                &[&claim.event.event_id],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?
            .ok_or(G05Error::RecordNotFound)?;
        let stored_digest: String = row.get(0);
        let delivered_at: Option<i64> = row.get(1);
        let old_ack: Option<String> = row.get(2);
        if stored_digest != digest {
            return Err(G05Error::AuditUnavailable);
        }
        if let Some(old_ack) = old_ack {
            if old_ack == acknowledgment.payload_sha256() && delivered_at.is_some() {
                return Ok(());
            }
            return Err(G05Error::AuditUnavailable);
        }
        let owner: Option<String> = row.get(3);
        let token: Option<String> = row.get(4);
        let lease_valid: Option<bool> = row.get(5);
        if owner.as_deref() != Some(claim.lease_owner.as_str())
            || token.as_deref() != Some(claim.lease_token.as_str())
            || lease_valid != Some(true)
            || delivered_at.is_some()
        {
            return Err(G05Error::AuditUnavailable);
        }
        let changed = tx
            .execute(
                "UPDATE g05_memory_g11_outbox
                 SET delivered_at=$4,acknowledgment_sha256=$5,
                     lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,last_error_code=NULL
                 WHERE event_id=$1 AND lease_owner=$2 AND lease_token=$3::uuid
                   AND delivered_at IS NULL AND lease_expires_at > clock_timestamp()",
                &[
                    &claim.event.event_id,
                    &claim.lease_owner,
                    &claim.lease_token,
                    &(acknowledgment.accepted_at() as i64),
                    &digest,
                ],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        if changed != 1 {
            return Err(G05Error::AuditUnavailable);
        }
        tx.commit().map_err(|_| G05Error::RepositoryUnavailable)
    }

    /// Deterministic capped exponential backoff with event-specific jitter.
    /// After twelve attempts, the event is retained and marked exhausted for
    /// operator inspection; it is never silently deleted or acknowledged.
    pub fn schedule_retry(&self, claim: &LeasedG11Event, error_code: &str) -> Result<(), G05Error> {
        if error_code.trim().is_empty() || error_code.len() > 96 {
            return Err(G05Error::MalformedRecord);
        }
        let mut hasher = Sha256::new();
        hasher.update(claim.event.event_id.as_bytes());
        let hash = hasher.finalize();
        let jitter = u16::from_be_bytes([hash[0], hash[1]]) as i64 % 7;
        let exponent = claim.attempt_count.saturating_sub(1).clamp(0, 10) as u32;
        let delay = ((2_i64.saturating_pow(exponent)).min(3_600) + jitter) as f64;
        let exhausted = claim.attempt_count >= 12;
        let final_error = if exhausted {
            format!("retry_exhausted:{error_code}")
        } else {
            error_code.to_owned()
        };
        let mut client = self
            .client
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let changed = client
            .execute(
                "UPDATE g05_memory_g11_outbox
                 SET next_attempt_at=CASE WHEN $4 THEN 'infinity'::timestamptz
                     ELSE clock_timestamp()+($5 * interval '1 second') END,
                     last_error_code=$6,lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL
                 WHERE event_id=$1 AND lease_owner=$2 AND lease_token=$3::uuid
                   AND delivered_at IS NULL AND lease_expires_at > clock_timestamp()",
                &[
                    &claim.event.event_id,
                    &claim.lease_owner,
                    &claim.lease_token,
                    &exhausted,
                    &delay,
                    &final_error,
                ],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        if changed != 1 {
            return Err(G05Error::VersionConflict);
        }
        Ok(())
    }

    /// Return exhausted event identifiers and error codes for operational
    /// alerting; the content-free payload remains available for controlled replay.
    pub fn exhausted_events(&self, limit: i64) -> Result<Vec<(String, String)>, G05Error> {
        if !(1..=500).contains(&limit) {
            return Err(G05Error::MalformedRecord);
        }
        let limit = limit as i32;
        let mut client = self
            .client
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let rows = client
            .query(
                "SELECT event_id,last_error_code FROM g05_memory_g11_outbox
                 WHERE delivered_at IS NULL AND next_attempt_at='infinity'::timestamptz
                 ORDER BY occurred_at,event_id LIMIT $1",
                &[&limit],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        Ok(rows
            .into_iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect())
    }
}

fn decode_claim(row: Row) -> Result<LeasedG11Event, G05Error> {
    let payload: Value = row.get(0);
    let event: AuditEvent = serde_json::from_value(payload).map_err(|error| {
        eprintln!("claim payload decode error: {error}");
        G05Error::RepositoryUnavailable
    })?;
    let lease_owner: String = row.get(1);
    let lease_token: String = row.get(2);
    let attempt_count: i64 = row.get(3);
    Ok(LeasedG11Event {
        event,
        lease_owner,
        lease_token,
        attempt_count,
    })
}

#[cfg(test)]
#[path = "postgres_repository_tests.rs"]
mod postgres_tests;

/// Shared G11 append-only receipt stream. This adapter serializes chain-head
/// advancement in PostgreSQL and makes receipt creation idempotent by event ID
/// and payload digest across workers and process restarts.
#[derive(Clone)]
pub struct PostgresG11MemoryAdapter {
    client: Arc<Mutex<Client>>,
}

impl PostgresG11MemoryAdapter {
    pub fn connect(connection_string: &str) -> Result<Self, G05Error> {
        if !connection_string.contains("sslmode=verify-full") {
            return Err(G05Error::RepositoryUnavailable);
        }
        let tls = TlsConnector::builder()
            .build()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let client = Client::connect(connection_string, MakeTlsConnector::new(tls))
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        Ok(Self {
            client: Arc::new(Mutex::new(client)),
        })
    }

    fn persist_pending_checkpoint(
        &self,
        checkpoint: &iroka_kernel::SignedCheckpoint,
    ) -> Result<iroka_kernel::SignedCheckpoint, G05Error> {
        let digest = checkpoint
            .digest()
            .map_err(|_| G05Error::AuditUnavailable)?;
        let payload = &checkpoint.payload;
        let sequence = i64::try_from(payload.sequence).map_err(|_| G05Error::MalformedRecord)?;
        let payload_json = json_value(payload)?;
        let mut client = self
            .client
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let mut tx = client
            .transaction()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        tx.execute(
            "INSERT INTO g11_signed_checkpoints
             (checkpoint_id,stream_id,sequence,previous_digest,checkpoint_digest,
              signer_key_id,payload_json,signature)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8)
             ON CONFLICT (stream_id,sequence) DO NOTHING",
            &[
                &digest,
                &payload.stream_id,
                &sequence,
                &payload.previous_checkpoint_digest,
                &digest,
                &payload.signer_key_id,
                &payload_json,
                &checkpoint.signature,
            ],
        )
        .map_err(|_| G05Error::VersionConflict)?;
        let row = tx
            .query_one(
                "SELECT checkpoint_digest,payload_json,signature
                 FROM g11_signed_checkpoints WHERE stream_id=$1 AND sequence=$2 FOR UPDATE",
                &[&payload.stream_id, &sequence],
            )
            .map_err(|error| {
                eprintln!("G11 pending checkpoint lookup failed: {error}");
                G05Error::RepositoryUnavailable
            })?;
        let stored_digest: String = row.get(0);
        let stored_payload: Value = row.get(1);
        let stored_signature: Vec<u8> = row.get(2);
        let stored_payload: iroka_kernel::CheckpointPayload =
            serde_json::from_value(stored_payload).map_err(|_| G05Error::AuditUnavailable)?;
        let stored = iroka_kernel::SignedCheckpoint {
            payload: stored_payload,
            signature: stored_signature,
        };
        if stored.digest().map_err(|_| G05Error::AuditUnavailable)? != stored_digest
            || stored.payload.stream_id != payload.stream_id
            || stored.payload.sequence != payload.sequence
            || stored.payload.audit_head_digest != payload.audit_head_digest
        {
            return Err(G05Error::VersionConflict);
        }
        tx.commit().map_err(|_| G05Error::RepositoryUnavailable)?;
        Ok(stored)
    }

    /// Persist an externally published checkpoint. If a matching pending
    /// envelope exists, this atomically attaches the receipt; repeated calls
    /// are idempotent for the same exact receipt.
    pub fn store_published_checkpoint(
        &self,
        published: &iroka_kernel::PublishedCheckpoint,
    ) -> Result<String, G05Error> {
        if published.checkpoint.payload.schema_id != iroka_kernel::G11_CHECKPOINT_SCHEMA_ID {
            return Err(G05Error::MalformedRecord);
        }
        let digest = published
            .checkpoint
            .digest()
            .map_err(|_| G05Error::AuditUnavailable)?;
        if published.publication.checkpoint_digest != digest
            || published.publication.provider.trim().is_empty()
            || published.publication.receipt_id.trim().is_empty()
            || published.publication.proof_ref.trim().is_empty()
            || published.publication.published_at < published.checkpoint.payload.issued_at
        {
            return Err(G05Error::AuditUnavailable);
        }
        let published_at = i64::try_from(published.publication.published_at)
            .map_err(|_| G05Error::MalformedRecord)? as f64;
        let sequence = i64::try_from(published.checkpoint.payload.sequence)
            .map_err(|_| G05Error::MalformedRecord)?;
        let receipt_json = json_value(published)?;
        let payload_json = json_value(&published.checkpoint.payload)?;
        let payload = &published.checkpoint.payload;
        let mut client = self
            .client
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let mut tx = client
            .transaction()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        if let Some(existing) = tx
            .query_opt(
                "SELECT checkpoint_digest,signer_key_id,payload_json,signature,
                        publication_receipt,published_at
                 FROM g11_signed_checkpoints WHERE checkpoint_id=$1 FOR UPDATE",
                &[&digest],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?
        {
            let old_digest: String = existing.get(0);
            let old_key: String = existing.get(1);
            let old_payload: Value = existing.get(2);
            let old_signature: Vec<u8> = existing.get(3);
            let old_receipt: Option<Value> = existing.get(4);
            let old_published_at: Option<std::time::SystemTime> = existing.get(5);
            if old_digest != digest
                || old_key != payload.signer_key_id
                || old_payload != payload_json
                || old_signature != published.checkpoint.signature
            {
                return Err(G05Error::VersionConflict);
            }
            if let Some(old_receipt) = old_receipt {
                if old_receipt != receipt_json || old_published_at.is_none() {
                    return Err(G05Error::VersionConflict);
                }
                tx.commit().map_err(|_| G05Error::RepositoryUnavailable)?;
                return Ok(digest);
            }
            let changed = tx
                .execute(
                    "UPDATE g11_signed_checkpoints
                     SET published_at=to_timestamp($2::double precision),publication_receipt=$3
                     WHERE checkpoint_id=$1 AND published_at IS NULL AND publication_receipt IS NULL",
                    &[&digest, &published_at, &receipt_json],
                )
                .map_err(|_| G05Error::RepositoryUnavailable)?;
            if changed != 1 {
                return Err(G05Error::VersionConflict);
            }
            tx.commit().map_err(|_| G05Error::RepositoryUnavailable)?;
            return Ok(digest);
        }
        tx.execute(
            "INSERT INTO g11_signed_checkpoints
             (checkpoint_id,stream_id,sequence,previous_digest,checkpoint_digest,
              signer_key_id,payload_json,signature,published_at,publication_receipt)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,to_timestamp($9::double precision),$10)",
            &[
                &digest,
                &payload.stream_id,
                &sequence,
                &payload.previous_checkpoint_digest,
                &digest,
                &payload.signer_key_id,
                &payload_json,
                &published.checkpoint.signature,
                &published_at,
                &receipt_json,
            ],
        )
        .map_err(|_| G05Error::VersionConflict)?;
        tx.commit().map_err(|_| G05Error::RepositoryUnavailable)?;
        Ok(digest)
    }

    /// Load the exact externally published envelope. Callers must still invoke
    /// verify_published_checkpoint with an independently provisioned trust key
    /// and publication verifier before treating it as verified.
    pub fn load_published_checkpoint(
        &self,
        checkpoint_id: &str,
    ) -> Result<Option<iroka_kernel::PublishedCheckpoint>, G05Error> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let row = client
            .query_opt(
                "SELECT checkpoint_digest,stream_id,sequence,signer_key_id,signature,
                        publication_receipt
                 FROM g11_signed_checkpoints WHERE checkpoint_id=$1 AND published_at IS NOT NULL",
                &[&checkpoint_id],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        row.map(|row| {
            let digest: String = row.get(0);
            let stream_id: String = row.get(1);
            let sequence: i64 = row.get(2);
            let signer_key_id: String = row.get(3);
            let signature: Vec<u8> = row.get(4);
            let receipt: Value = row.get(5);
            let published: iroka_kernel::PublishedCheckpoint =
                serde_json::from_value(receipt).map_err(|_| G05Error::RepositoryUnavailable)?;
            if digest != checkpoint_id
                || published.checkpoint.payload.stream_id != stream_id
                || published.checkpoint.payload.sequence != sequence as u64
                || published.checkpoint.payload.signer_key_id != signer_key_id
                || published.checkpoint.signature != signature
                || published
                    .checkpoint
                    .digest()
                    .map_err(|_| G05Error::AuditUnavailable)?
                    != digest
            {
                return Err(G05Error::AuditUnavailable);
            }
            Ok(published)
        })
        .transpose()
    }

    /// Return the durable chain head for checkpoint signing and publication.
    pub fn head(&self) -> Result<(u64, String), G05Error> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let row = client
            .query_one(
                "SELECT sequence,digest FROM g11_memory_audit_head WHERE singleton=TRUE",
                &[],
            )
            .map_err(|error| {
                eprintln!("G11 head query failed: {error}");
                G05Error::RepositoryUnavailable
            })?;
        let sequence: i64 = row.get(0);
        let digest: String = row.get(1);
        Ok((sequence as u64, digest))
    }

    /// Publish the current G11 audit head as an externally anchored checkpoint.
    /// A signed pending envelope is committed before network I/O. Concurrent
    /// publishers and crash recovery reuse that exact envelope and digest.
    pub fn publish_checkpoint<C, S, P>(
        &self,
        stream_id: &str,
        signer_key_id: &str,
        clock: &C,
        signer: &S,
        publisher: &P,
    ) -> Result<iroka_kernel::PublishedCheckpoint, G05Error>
    where
        C: crate::TrustedClock,
        S: iroka_kernel::CheckpointSigner,
        P: iroka_kernel::ExternalCheckpointPublisher,
    {
        if stream_id.trim().is_empty() || signer_key_id.trim().is_empty() {
            return Err(G05Error::MalformedRecord);
        }
        let (sequence, audit_head_digest) = self.head()?;
        if sequence == 0 {
            return Err(G05Error::AuditUnavailable);
        }

        let mut client = self
            .client
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let latest = client
            .query_opt(
                "SELECT sequence,checkpoint_digest,published_at,payload_json,signature
                 FROM g11_signed_checkpoints WHERE stream_id=$1
                 ORDER BY sequence DESC LIMIT 1",
                &[&stream_id],
            )
            .map_err(|error| {
                eprintln!("G11 checkpoint latest query failed: {error}");
                G05Error::RepositoryUnavailable
            })?;

        let pending = if let Some(row) = latest {
            let latest_sequence: i64 = row.get(0);
            let latest_digest: String = row.get(1);
            let published_at: Option<std::time::SystemTime> = row.get(2);
            let payload_json: Value = row.get(3);
            let signature: Vec<u8> = row.get(4);
            if latest_sequence as u64 > sequence {
                return Err(G05Error::VersionConflict);
            }
            if published_at.is_some() && latest_sequence as u64 == sequence {
                drop(client);
                return self
                    .load_published_checkpoint(&latest_digest)?
                    .ok_or(G05Error::AuditUnavailable);
            }
            if published_at.is_none() {
                let payload: iroka_kernel::CheckpointPayload =
                    serde_json::from_value(payload_json).map_err(|_| G05Error::AuditUnavailable)?;
                Some(iroka_kernel::SignedCheckpoint { payload, signature })
            } else {
                None
            }
        } else {
            None
        };
        let previous_checkpoint_digest = if pending.is_none() {
            client
                .query_opt(
                    "SELECT checkpoint_digest FROM g11_signed_checkpoints
                     WHERE stream_id=$1 AND published_at IS NOT NULL
                     ORDER BY sequence DESC LIMIT 1",
                    &[&stream_id],
                )
                .map_err(|_| G05Error::RepositoryUnavailable)?
                .map(|row| row.get::<_, String>(0))
        } else {
            None
        };
        drop(client);

        let checkpoint = if let Some(pending) = pending {
            if pending.payload.sequence > sequence {
                return Err(G05Error::VersionConflict);
            }
            pending
        } else {
            let payload = iroka_kernel::CheckpointPayload {
                schema_id: iroka_kernel::G11_CHECKPOINT_SCHEMA_ID.into(),
                stream_id: stream_id.into(),
                sequence,
                previous_checkpoint_digest,
                audit_head_digest,
                issued_at: clock.now_unix_seconds()?,
                signer_key_id: signer_key_id.into(),
            };
            let message = payload
                .signing_bytes()
                .map_err(|_| G05Error::AuditUnavailable)?;
            let signature = signer
                .sign(signer_key_id, &message)
                .map_err(|_| G05Error::AuditUnavailable)?;
            if signature.len() != 64 {
                return Err(G05Error::AuditUnavailable);
            }
            let candidate = iroka_kernel::SignedCheckpoint { payload, signature };
            self.persist_pending_checkpoint(&candidate)?
        };

        let digest = checkpoint
            .digest()
            .map_err(|_| G05Error::AuditUnavailable)?;
        let publication = publisher
            .publish(&checkpoint)
            .map_err(|_| G05Error::AuditUnavailable)?;
        if publication.checkpoint_digest != digest
            || publication.provider.trim().is_empty()
            || publication.receipt_id.trim().is_empty()
            || publication.proof_ref.trim().is_empty()
            || publication.published_at < checkpoint.payload.issued_at
        {
            return Err(G05Error::AuditUnavailable);
        }
        let published = iroka_kernel::PublishedCheckpoint {
            checkpoint,
            publication,
        };
        self.store_published_checkpoint(&published)?;
        Ok(published)
    }

    /// Recompute the full event chain and verify every durable receipt and head.
    pub fn verify_integrity(&self) -> Result<(), G05Error> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let rows = client
            .query(
                "SELECT sequence,event_id,payload_sha256,previous_digest,event_digest,
                        occurred_at,accepted_at,event_json
                 FROM g11_memory_audit_events ORDER BY sequence",
                &[],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let mut previous = "0".repeat(64);
        let mut expected_sequence = 0_i64;
        for row in rows {
            expected_sequence += 1;
            let sequence: i64 = row.get(0);
            let event_id: String = row.get(1);
            let payload_digest: String = row.get(2);
            let previous_digest: String = row.get(3);
            let event_digest: String = row.get(4);
            let occurred_at: i64 = row.get(5);
            let accepted_at: i64 = row.get(6);
            let event_json: Value = row.get(7);
            let event: AuditEvent =
                serde_json::from_value(event_json).map_err(|_| G05Error::AuditUnavailable)?;
            let canonical = format!(
                "IROKA:G11:MEMORY:AUDIT:V1\0{previous}\0{event_id}\0{payload_digest}\0{occurred_at}\0{accepted_at}"
            );
            let calculated = crate::sha256_hex(canonical.as_bytes());
            if sequence != expected_sequence
                || previous_digest != previous
                || event_digest != calculated
                || event.event_id != event_id
                || event.occurred_at as i64 != occurred_at
                || audit_event_sha256(&event) != payload_digest
            {
                return Err(G05Error::AuditUnavailable);
            }
            let receipt = client
                .query_opt(
                    "SELECT payload_sha256,accepted_at FROM g11_memory_receipts WHERE event_id=$1",
                    &[&event_id],
                )
                .map_err(|_| G05Error::RepositoryUnavailable)?
                .ok_or(G05Error::AuditUnavailable)?;
            let receipt_digest: String = receipt.get(0);
            let receipt_time: i64 = receipt.get(1);
            if receipt_digest != payload_digest || receipt_time != accepted_at {
                return Err(G05Error::AuditUnavailable);
            }
            previous = event_digest;
        }
        let head = client
            .query_one(
                "SELECT sequence,digest FROM g11_memory_audit_head WHERE singleton=TRUE",
                &[],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let head_sequence: i64 = head.get(0);
        let head_digest: String = head.get(1);
        if head_sequence != expected_sequence || head_digest != previous {
            return Err(G05Error::AuditUnavailable);
        }
        Ok(())
    }
}

impl G11MemoryAuditAuthority for PostgresG11MemoryAdapter {
    fn append_memory_event(&self, event: &AuditEvent) -> Result<G11Acknowledgment, G05Error> {
        if event.event_id.trim().is_empty()
            || event.event_id.len() > 256
            || event.memory_id.trim().is_empty()
            || event.tenant_ref.trim().is_empty()
            || event.record_version == 0
        {
            return Err(G05Error::MalformedRecord);
        }
        let payload_digest = audit_event_sha256(event);
        let event_json = json_value(event)?;
        let mut client = self
            .client
            .lock()
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let mut tx = client
            .transaction()
            .map_err(|_| G05Error::RepositoryUnavailable)?;

        // A singleton row lock serializes append and duplicate detection across
        // independent connections, not merely threads sharing one client.
        let head = tx
            .query_one(
                "SELECT sequence,digest FROM g11_memory_audit_head
                 WHERE singleton=TRUE FOR UPDATE",
                &[],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        let previous_sequence: i64 = head.get(0);
        let previous_digest: String = head.get(1);

        if let Some(existing) = tx
            .query_opt(
                "SELECT payload_sha256,accepted_at FROM g11_memory_receipts WHERE event_id=$1",
                &[&event.event_id],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?
        {
            let old_digest: String = existing.get(0);
            let accepted_at: i64 = existing.get(1);
            if old_digest != payload_digest || accepted_at < event.occurred_at as i64 {
                return Err(G05Error::AuditUnavailable);
            }
            tx.commit().map_err(|_| G05Error::RepositoryUnavailable)?;
            return Ok(G11Acknowledgment {
                event_id: event.event_id.clone(),
                payload_sha256: payload_digest,
                accepted_at: accepted_at as u64,
            });
        }

        let accepted_at: i64 = tx
            .query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
                &[],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?
            .get(0);
        if accepted_at < event.occurred_at as i64 {
            return Err(G05Error::AuditUnavailable);
        }
        let canonical = format!(
            "IROKA:G11:MEMORY:AUDIT:V1\0{previous_digest}\0{}\0{payload_digest}\0{}\0{accepted_at}",
            event.event_id, event.occurred_at
        );
        let event_digest = crate::sha256_hex(canonical.as_bytes());
        let inserted_sequence = previous_sequence + 1;
        tx.execute(
            "INSERT INTO g11_memory_audit_events
             (sequence,event_id,payload_sha256,previous_digest,event_digest,
              occurred_at,accepted_at,event_json)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            &[
                &inserted_sequence,
                &event.event_id,
                &payload_digest,
                &previous_digest,
                &event_digest,
                &(event.occurred_at as i64),
                &accepted_at,
                &event_json,
            ],
        )
        .map_err(|_| G05Error::AuditUnavailable)?;
        let changed = tx
            .execute(
                "UPDATE g11_memory_audit_head SET sequence=$1,digest=$2
                 WHERE singleton=TRUE AND sequence=$3 AND digest=$4",
                &[
                    &inserted_sequence,
                    &event_digest,
                    &previous_sequence,
                    &previous_digest,
                ],
            )
            .map_err(|_| G05Error::RepositoryUnavailable)?;
        if changed != 1 {
            return Err(G05Error::VersionConflict);
        }
        let receipt_json = serde_json::json!({
            "event_id": event.event_id,
            "payload_sha256": payload_digest,
            "accepted_at": accepted_at,
            "audit_sequence": inserted_sequence,
            "event_digest": event_digest
        });
        tx.execute(
            "INSERT INTO g11_memory_receipts(event_id,payload_sha256,accepted_at,receipt_json)
             VALUES($1,$2,$3,$4)",
            &[
                &event.event_id,
                &payload_digest,
                &accepted_at,
                &receipt_json,
            ],
        )
        .map_err(|_| G05Error::AuditUnavailable)?;
        tx.commit().map_err(|_| G05Error::RepositoryUnavailable)?;
        Ok(G11Acknowledgment {
            event_id: event.event_id.clone(),
            payload_sha256: payload_digest,
            accepted_at: accepted_at as u64,
        })
    }
}
