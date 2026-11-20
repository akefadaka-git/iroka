//! Content-free task audit events and the PostgreSQL G11 adapter.
use crate::{TaskApiError, TaskRecord};
use iroka_g05_memory::{
    g11_audit_envelope_sha256, sha256_hex, G11Acknowledgment, G11AuditEnvelope,
    PostgresG11MemoryAdapter,
};
use serde::{Deserialize, Serialize};

const MAX_AUDIT_REF_BYTES: usize = 256;

fn valid_ref(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_AUDIT_REF_BYTES
        && !value.chars().any(char::is_control)
}

/// A task audit payload deliberately excludes prompts, document bodies, results,
/// credentials, and other user content. Its digest is carried by the G11 envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskAuditEvent {
    pub event_id: String,
    pub event_type: String,
    pub task_id: String,
    pub tenant_ref: String,
    pub principal_ref: String,
    pub worker_ref: String,
    pub capability_id: String,
    pub policy_version: String,
    pub correlation_id: String,
    pub task_version: u64,
    pub occurred_at: u64,
    pub outcome_code: String,
}

impl TaskAuditEvent {
    pub fn validate(&self) -> Result<(), TaskApiError> {
        let refs = [
            self.event_id.as_str(), self.task_id.as_str(), self.tenant_ref.as_str(),
            self.principal_ref.as_str(), self.worker_ref.as_str(), self.capability_id.as_str(),
            self.policy_version.as_str(), self.correlation_id.as_str(), self.outcome_code.as_str(),
        ];
        if refs.iter().any(|value| !valid_ref(value))
            || self.event_id.len() > 256
            || !matches!(self.event_type.as_str(),
                "task.effect.attempted" | "task.completed" | "task.failed" | "task.cancelled")
            || self.outcome_code.len() > 128
            || !self.outcome_code.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || self.task_version == 0
            || i64::try_from(self.occurred_at).is_err()
        {
            return Err(TaskApiError::InvalidRequest);
        }
        Ok(())
    }

    pub(crate) fn to_g11_envelope(&self) -> Result<G11AuditEnvelope, TaskApiError> {
        self.validate()?;
        let canonical = serde_json::to_vec(self).map_err(|_| TaskApiError::InvalidRequest)?;
        Ok(G11AuditEnvelope {
            event_id: self.event_id.clone(),
            event_type: self.event_type.clone(),
            subject_ref: self.principal_ref.clone(),
            capability_id: self.capability_id.clone(),
            resource_ref: format!("iroka:tenant:{}:task:{}", self.tenant_ref, self.task_id),
            policy_version: self.policy_version.clone(),
            correlation_ref: self.correlation_id.clone(),
            occurred_at: self.occurred_at,
            subject_payload_sha256: sha256_hex(&canonical),
        })
    }

    pub(crate) fn validate_for_task(
        &self,
        task: &TaskRecord,
        worker_ref: &str,
        event_type: &str,
        next_version: u64,
        occurred_at: u64,
        outcome_code: &str,
    ) -> Result<G11AuditEnvelope, TaskApiError> {
        let expected_id = format!("task:{}:v{}:{}", task.task_id, next_version, event_type);
        if self.task_id != task.task_id
            || self.tenant_ref != task.tenant_ref
            || self.principal_ref != task.principal_ref
            || self.worker_ref != worker_ref
            || self.capability_id != task.capability_id
            || self.policy_version != task.policy_version
            || self.correlation_id != task.correlation_id
            || self.event_type != event_type
            || self.event_id != expected_id
            || self.task_version != next_version
            || self.occurred_at != occurred_at
            || self.outcome_code != outcome_code
        {
            return Err(TaskApiError::AuthorityUnavailable);
        }
        self.to_g11_envelope().map_err(|_| TaskApiError::AuthorityUnavailable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskAuditReceipt {
    event_id: String,
    payload_sha256: String,
    accepted_at: u64,
}

impl TaskAuditReceipt {
    pub fn event_id(&self) -> &str { &self.event_id }
    pub fn payload_sha256(&self) -> &str { &self.payload_sha256 }
    pub fn accepted_at(&self) -> u64 { self.accepted_at }

    pub(crate) fn matches(&self, event: &TaskAuditEvent, envelope: &G11AuditEnvelope) -> bool {
        self.event_id == event.event_id
            && self.payload_sha256 == g11_audit_envelope_sha256(envelope)
            && self.accepted_at >= event.occurred_at
    }

    #[cfg(test)]
    pub(crate) fn for_test(event: &TaskAuditEvent) -> Self {
        let envelope = event.to_g11_envelope().expect("valid test audit event");
        Self {
            event_id: envelope.event_id.clone(),
            payload_sha256: g11_audit_envelope_sha256(&envelope),
            accepted_at: event.occurred_at,
        }
    }
}

pub trait TaskAuditAuthority: Send + Sync {
    fn append(&self, event: &TaskAuditEvent) -> Result<TaskAuditReceipt, TaskApiError>;
}

#[derive(Clone)]
pub struct PostgresTaskAuditAuthority {
    adapter: PostgresG11MemoryAdapter,
}

impl PostgresTaskAuditAuthority {
    pub fn connect(connection_string: &str) -> Result<Self, TaskApiError> {
        let adapter = PostgresG11MemoryAdapter::connect(connection_string)
            .map_err(|_| TaskApiError::AuthorityUnavailable)?;
        Ok(Self { adapter })
    }

    pub fn from_adapter(adapter: PostgresG11MemoryAdapter) -> Self {
        Self { adapter }
    }
}

impl TaskAuditAuthority for PostgresTaskAuditAuthority {
    fn append(&self, event: &TaskAuditEvent) -> Result<TaskAuditReceipt, TaskApiError> {
        let envelope = event.to_g11_envelope()?;
        let acknowledgment: G11Acknowledgment = self.adapter.append_envelope(&envelope)
            .map_err(|_| TaskApiError::AuthorityUnavailable)?;
        if acknowledgment.event_id() != event.event_id
            || acknowledgment.payload_sha256() != g11_audit_envelope_sha256(&envelope)
            || acknowledgment.accepted_at() < event.occurred_at
        {
            return Err(TaskApiError::AuthorityUnavailable);
        }
        Ok(TaskAuditReceipt {
            event_id: acknowledgment.event_id().to_owned(),
            payload_sha256: acknowledgment.payload_sha256().to_owned(),
            accepted_at: acknowledgment.accepted_at(),
        })
    }
}

/// Opaque permit proving that G11 durably accepted the exact task effect-attempt event.
#[derive(Debug, PartialEq, Eq)]
pub struct TaskEffectPermit {
    event_id: String,
    payload_sha256: String,
    accepted_at: u64,
}

impl TaskEffectPermit {
    pub fn event_id(&self) -> &str { &self.event_id }
    pub fn payload_sha256(&self) -> &str { &self.payload_sha256 }
    pub fn accepted_at(&self) -> u64 { self.accepted_at }
}

/// Pre-effect audit gate. A protected-effect implementation must obtain this
/// permit before invoking its external executor; unavailable G11 fails closed.
pub struct TaskEffectAuditGate<A> {
    authority: A,
}

impl<A: TaskAuditAuthority> TaskEffectAuditGate<A> {
    pub fn new(authority: A) -> Self { Self { authority } }

    pub fn record_before_effect(
        &self,
        task: &TaskRecord,
        worker_ref: &str,
        next_task_version: u64,
        occurred_at: u64,
        event: &TaskAuditEvent,
    ) -> Result<TaskEffectPermit, TaskApiError> {
        let envelope = event.validate_for_task(
            task, worker_ref, "task.effect.attempted", next_task_version,
            occurred_at, "attempted",
        )?;
        let receipt = self.authority.append(event)?;
        if !receipt.matches(event, &envelope) {
            return Err(TaskApiError::AuthorityUnavailable);
        }
        Ok(TaskEffectPermit {
            event_id: receipt.event_id,
            payload_sha256: receipt.payload_sha256,
            accepted_at: receipt.accepted_at,
        })
    }
}

#[cfg(test)]
mod effect_gate_tests {
    use super::*;

    struct AcceptingAudit;
    impl TaskAuditAuthority for AcceptingAudit {
        fn append(&self, event: &TaskAuditEvent) -> Result<TaskAuditReceipt, TaskApiError> {
            Ok(TaskAuditReceipt::for_test(event))
        }
    }

    struct UnavailableAudit;
    impl TaskAuditAuthority for UnavailableAudit {
        fn append(&self, _event: &TaskAuditEvent) -> Result<TaskAuditReceipt, TaskApiError> {
            Err(TaskApiError::AuthorityUnavailable)
        }
    }

    fn fixture() -> (TaskRecord, TaskAuditEvent) {
        let task = TaskRecord {
            task_id: "task:audit-gate".into(),
            tenant_ref: "tenant:audit-gate".into(),
            principal_ref: "principal:audit-gate".into(),
            capability_id: "iroka.task.execute".into(),
            capability_version: "v1".into(),
            policy_version: "policy:v1".into(),
            idempotency_key: "idem:audit-gate".into(),
            request_sha256: "a".repeat(64),
            correlation_id: "trace:audit-gate".into(),
            client_request_id: "client:audit-gate".into(),
            state: crate::TaskState::Running,
            task_version: 3,
            created_at: 10,
            updated_at: 20,
            expires_at: 1000,
            result_ref: None,
            error_code: None,
        };
        let event = TaskAuditEvent {
            event_id: "task:task:audit-gate:v4:task.effect.attempted".into(),
            event_type: "task.effect.attempted".into(),
            task_id: task.task_id.clone(),
            tenant_ref: task.tenant_ref.clone(),
            principal_ref: task.principal_ref.clone(),
            worker_ref: "worker:audit-gate".into(),
            capability_id: task.capability_id.clone(),
            policy_version: task.policy_version.clone(),
            correlation_id: task.correlation_id.clone(),
            task_version: 4,
            occurred_at: 30,
            outcome_code: "attempted".into(),
        };
        (task,event)
    }

    #[test]
    fn pre_effect_gate_returns_permit_only_after_matching_g11_receipt() {
        let (task,event)=fixture();
        let gate=TaskEffectAuditGate::new(AcceptingAudit);
        let permit=gate.record_before_effect(&task,"worker:audit-gate",4,30,&event).unwrap();
        assert_eq!(permit.event_id(),event.event_id);
        assert_eq!(permit.accepted_at(),30);
    }

    #[test]
    fn pre_effect_gate_rejects_non_effect_events() {
        let (task,mut event)=fixture();
        event.event_type="task.completed".into();
        let gate=TaskEffectAuditGate::new(AcceptingAudit);
        assert_eq!(
            gate.record_before_effect(&task,"worker:audit-gate",4,30,&event),
            Err(TaskApiError::AuthorityUnavailable)
        );
    }

    #[test]
    fn pre_effect_gate_fails_closed_when_g11_is_unavailable() {
        let (task,event)=fixture();
        let gate=TaskEffectAuditGate::new(UnavailableAudit);
        assert_eq!(
            gate.record_before_effect(&task,"worker:audit-gate",4,30,&event),
            Err(TaskApiError::AuthorityUnavailable)
        );
    }
}
