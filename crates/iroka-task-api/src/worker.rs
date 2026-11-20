//! Durable PostgreSQL worker leases for task lifecycle state.
//! These primitives do not execute models or protected effects; G11 gating remains separate.
use super::*;
use postgres::Transaction;

const LEASE_COLUMNS: &str = "task_id,tenant_ref,principal_ref,capability_id,capability_version,
    policy_version,idempotency_key,request_sha256,correlation_id,client_request_id,state,
    task_version,created_at,updated_at,expires_at,result_ref,error_code,
    lease_owner,lease_token::text AS lease_token,lease_expires_at,attempt_count";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskLease {
    pub task: TaskRecord,
    pub worker_ref: String,
    pub lease_token: String,
    pub lease_expires_at: u64,
    pub attempt: u32,
}

pub trait TaskWorkerRepository: Send + Sync {
    fn claim_next(&self, worker_ref: &str, now: u64, lease_seconds: u64, max_attempts: u32)
        -> Result<Option<TaskLease>, TaskApiError>;
    fn renew_lease(&self, lease: &TaskLease, now: u64, lease_seconds: u64)
        -> Result<TaskLease, TaskApiError>;
    fn complete_lease(&self, lease: &TaskLease, change: TaskTransition)
        -> Result<TaskRecord, TaskApiError>;
    fn acknowledge_cancel(&self, lease: &TaskLease, occurred_at: u64, metadata: Value)
        -> Result<TaskRecord, TaskApiError>;
}

fn valid_worker_ref(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_TASK_REF_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_lease_seconds(seconds: u64) -> bool {
    (5..=300).contains(&seconds)
}

fn lease_from_row(row: &Row) -> Result<TaskLease, TaskApiError> {
    let worker_ref: Option<String> = row.get("lease_owner");
    let lease_token: Option<String> = row.get("lease_token");
    let expires: Option<i64> = row.get("lease_expires_at");
    let attempt: i32 = row.get("attempt_count");
    Ok(TaskLease {
        task: task_from_row(row)?,
        worker_ref: worker_ref.ok_or(TaskApiError::Conflict)?,
        lease_token: lease_token.ok_or(TaskApiError::Conflict)?,
        lease_expires_at: u64::try_from(expires.ok_or(TaskApiError::Conflict)?)
            .map_err(|_| TaskApiError::RepositoryUnavailable)?,
        attempt: u32::try_from(attempt).map_err(|_| TaskApiError::RepositoryUnavailable)?,
    })
}

fn append_worker_event(
    tx: &mut Transaction<'_>, task: &TaskRecord, event_type: &str,
    actor_ref: &str, occurred_at: u64, metadata: &Value,
) -> Result<(), TaskApiError> {
    if !valid_worker_ref(actor_ref) || !valid_event_metadata(metadata) {
        return Err(TaskApiError::InvalidRequest);
    }
    let sequence = i64::try_from(task.task_version).map_err(|_| TaskApiError::Conflict)?;
    let occurred = i64::try_from(occurred_at).map_err(|_| TaskApiError::Conflict)?;
    let event_id = format!("{}:event:{}", task.task_id, task.task_version);
    tx.execute(
        "INSERT INTO iroka_task_events
         (task_id,sequence,event_id,event_type,task_state,task_version,actor_ref,occurred_at,metadata_json)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        &[&task.task_id,&sequence,&event_id,&event_type,&task.state.as_str(),
          &sequence,&actor_ref,&occurred,&metadata],
    ).map_err(|_| TaskApiError::RepositoryUnavailable)?;
    Ok(())
}

impl TaskWorkerRepository for PostgresTaskRepository {
    fn claim_next(&self, worker_ref: &str, now: u64, lease_seconds: u64, max_attempts: u32)
        -> Result<Option<TaskLease>, TaskApiError> {
        if !valid_worker_ref(worker_ref) || !valid_lease_seconds(lease_seconds)
            || !(1..=10).contains(&max_attempts) {
            return Err(TaskApiError::InvalidRequest);
        }
        let now_i = i64::try_from(now).map_err(|_| TaskApiError::InvalidRequest)?;
        let lease_until = now.checked_add(lease_seconds)
            .and_then(|v| i64::try_from(v).ok()).ok_or(TaskApiError::InvalidRequest)?;
        let max_attempts_i = i32::try_from(max_attempts).map_err(|_| TaskApiError::InvalidRequest)?;
        let mut client = self.client.lock().map_err(|_| TaskApiError::RepositoryUnavailable)?;
        let mut tx = client.transaction().map_err(|_| TaskApiError::RepositoryUnavailable)?;
        let sql = "WITH candidate AS (
                SELECT task_id,state FROM iroka_tasks
                WHERE ((state='queued' AND expires_at>$1 AND next_attempt_at<=$1 AND attempt_count<$2)
                       OR state='cancel_requested')
                  AND (lease_expires_at IS NULL OR lease_expires_at<=$1)
                ORDER BY CASE WHEN state='cancel_requested' THEN 0 ELSE 1 END,created_at,task_id
                LIMIT 1 FOR UPDATE SKIP LOCKED
             )
             UPDATE iroka_tasks AS t
             SET state=CASE WHEN candidate.state='queued' THEN 'running' ELSE 'cancel_requested' END,
                 task_version=t.task_version+1,updated_at=$1,lease_owner=$3,
                 lease_token=gen_random_uuid(),lease_expires_at=$4,
                 attempt_count=t.attempt_count+CASE WHEN candidate.state='queued' THEN 1 ELSE 0 END
             FROM candidate WHERE t.task_id=candidate.task_id
             RETURNING t.task_id,t.tenant_ref,t.principal_ref,t.capability_id,t.capability_version,
                 t.policy_version,t.idempotency_key,t.request_sha256,t.correlation_id,t.client_request_id,
                 t.state,t.task_version,t.created_at,t.updated_at,t.expires_at,t.result_ref,t.error_code,
                 t.lease_owner,t.lease_token::text AS lease_token,t.lease_expires_at,t.attempt_count";
        let row = tx.query_opt(sql,&[&now_i,&max_attempts_i,&worker_ref,&lease_until])
            .map_err(|_| TaskApiError::RepositoryUnavailable)?;
        let Some(row) = row else {
            tx.commit().map_err(|_| TaskApiError::RepositoryUnavailable)?;
            return Ok(None);
        };
        let lease = lease_from_row(&row)?;
        let event_type = if lease.task.state == TaskState::CancelRequested {
            "task.cancel_lease_acquired"
        } else { "task.running" };
        let metadata = json!({"worker_ref":worker_ref,"attempt":lease.attempt});
        append_worker_event(&mut tx,&lease.task,event_type,worker_ref,now,&metadata)?;
        tx.commit().map_err(|_| TaskApiError::RepositoryUnavailable)?;
        Ok(Some(lease))
    }

    fn renew_lease(&self, lease: &TaskLease, now: u64, lease_seconds: u64)
        -> Result<TaskLease, TaskApiError> {
        if !valid_worker_ref(&lease.worker_ref) || lease.lease_token.trim().is_empty()
            || !valid_lease_seconds(lease_seconds) {
            return Err(TaskApiError::InvalidRequest);
        }
        let now_i = i64::try_from(now).map_err(|_| TaskApiError::InvalidRequest)?;
        let lease_until = now.checked_add(lease_seconds)
            .and_then(|v| i64::try_from(v).ok()).ok_or(TaskApiError::InvalidRequest)?;
        let sql = format!(
            "UPDATE iroka_tasks SET lease_expires_at=$4
             WHERE task_id=$1 AND lease_owner=$2 AND lease_token::text=$3
               AND state IN ('running','cancel_requested')
               AND lease_expires_at>$5 AND expires_at>$5
             RETURNING {LEASE_COLUMNS}"
        );
        let mut client = self.client.lock().map_err(|_| TaskApiError::RepositoryUnavailable)?;
        let row = client.query_opt(&sql,&[
            &lease.task.task_id,&lease.worker_ref,&lease.lease_token,&lease_until,&now_i
        ]).map_err(|_| TaskApiError::RepositoryUnavailable)?
         .ok_or(TaskApiError::Conflict)?;
        lease_from_row(&row)
    }

    fn complete_lease(&self, lease: &TaskLease, change: TaskTransition)
        -> Result<TaskRecord, TaskApiError> {
        if change.task_id != lease.task.task_id || change.actor_ref != lease.worker_ref
            || !matches!(change.next_state,TaskState::Succeeded|TaskState::Failed)
            || !valid_event_metadata(&change.metadata)
            || (change.next_state == TaskState::Succeeded && change.result_ref.is_none())
            || (change.next_state == TaskState::Failed && change.error_code.is_none())
            || (change.next_state != TaskState::Succeeded && change.result_ref.is_some())
            || (change.next_state != TaskState::Failed && change.error_code.is_some())
            || change.result_ref.as_ref().is_some_and(|v| v.trim().is_empty()
                || v.len()>MAX_TASK_REF_BYTES || v.chars().any(char::is_control))
            || change.error_code.as_ref().is_some_and(|v| v.trim().is_empty()
                || v.len()>128 || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))) {
            return Err(TaskApiError::InvalidRequest);
        }
        let occurred = i64::try_from(change.occurred_at).map_err(|_| TaskApiError::InvalidRequest)?;
        let expected = i64::try_from(change.expected_version).map_err(|_| TaskApiError::Conflict)?;
        let mut client=self.client.lock().map_err(|_|TaskApiError::RepositoryUnavailable)?;
        let mut tx=client.transaction().map_err(|_|TaskApiError::RepositoryUnavailable)?;
        let sql=format!("SELECT {LEASE_COLUMNS} FROM iroka_tasks WHERE task_id=$1 FOR UPDATE");
        let row=tx.query_opt(&sql,&[&change.task_id]).map_err(|_|TaskApiError::RepositoryUnavailable)?
            .ok_or(TaskApiError::NotFound)?;
        let current=lease_from_row(&row)?;
        if current.task.state!=TaskState::Running || current.worker_ref!=lease.worker_ref
            || current.lease_token!=lease.lease_token || current.lease_expires_at<=change.occurred_at
            || current.task.expires_at<=change.occurred_at
            || current.task.task_version!=change.expected_version
            || !current.task.state.permits(change.next_state)
            || change.occurred_at<current.task.updated_at {
            return Err(TaskApiError::Conflict);
        }
        let next_version=current.task.task_version.checked_add(1).ok_or(TaskApiError::Conflict)?;
        let changed=tx.execute(
            "UPDATE iroka_tasks SET state=$2,task_version=$3,updated_at=$4,result_ref=$5,error_code=$6,
                lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL
             WHERE task_id=$1 AND task_version=$7",
            &[&change.task_id,&change.next_state.as_str(),&(next_version as i64),&occurred,
              &change.result_ref,&change.error_code,&expected],
        ).map_err(|_|TaskApiError::RepositoryUnavailable)?;
        if changed!=1 { return Err(TaskApiError::Conflict); }
        let updated_sql=format!("SELECT {TASK_COLUMNS} FROM iroka_tasks WHERE task_id=$1");
        let updated=tx.query_one(&updated_sql,&[&change.task_id]).map_err(|_|TaskApiError::RepositoryUnavailable)?;
        let task=task_from_row(&updated)?;
        append_worker_event(&mut tx,&task,&format!("task.{}",task.state.as_str()),
            &change.actor_ref,change.occurred_at,&change.metadata)?;
        tx.commit().map_err(|_|TaskApiError::RepositoryUnavailable)?;
        Ok(task)
    }

    fn acknowledge_cancel(&self, lease: &TaskLease, occurred_at: u64, metadata: Value)
        -> Result<TaskRecord, TaskApiError> {
        if !valid_event_metadata(&metadata) || !valid_worker_ref(&lease.worker_ref) {
            return Err(TaskApiError::InvalidRequest);
        }
        let occurred=i64::try_from(occurred_at).map_err(|_|TaskApiError::InvalidRequest)?;
        let mut client=self.client.lock().map_err(|_|TaskApiError::RepositoryUnavailable)?;
        let mut tx=client.transaction().map_err(|_|TaskApiError::RepositoryUnavailable)?;
        let sql=format!("SELECT {LEASE_COLUMNS} FROM iroka_tasks WHERE task_id=$1 FOR UPDATE");
        let row=tx.query_opt(&sql,&[&lease.task.task_id]).map_err(|_|TaskApiError::RepositoryUnavailable)?
            .ok_or(TaskApiError::NotFound)?;
        let current=lease_from_row(&row)?;
        if current.task.state!=TaskState::CancelRequested || current.worker_ref!=lease.worker_ref
            || current.lease_token!=lease.lease_token || current.lease_expires_at<=occurred_at
            || occurred_at<current.task.updated_at {
            return Err(TaskApiError::Conflict);
        }
        let next_version=current.task.task_version.checked_add(1).ok_or(TaskApiError::Conflict)?;
        let changed=tx.execute(
            "UPDATE iroka_tasks SET state='cancelled',task_version=$2,updated_at=$3,
                lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL
             WHERE task_id=$1 AND task_version=$4",
            &[&current.task.task_id,&(next_version as i64),&occurred,
              &(current.task.task_version as i64)],
        ).map_err(|_|TaskApiError::RepositoryUnavailable)?;
        if changed!=1 { return Err(TaskApiError::Conflict); }
        let updated_sql=format!("SELECT {TASK_COLUMNS} FROM iroka_tasks WHERE task_id=$1");
        let updated=tx.query_one(&updated_sql,&[&current.task.task_id]).map_err(|_|TaskApiError::RepositoryUnavailable)?;
        let task=task_from_row(&updated)?;
        append_worker_event(&mut tx,&task,"task.cancelled",&lease.worker_ref,occurred_at,&metadata)?;
        tx.commit().map_err(|_|TaskApiError::RepositoryUnavailable)?;
        Ok(task)
    }
}
