//! G11 assurance: structured audit events and fail-closed sink contract.

use crate::{Decision, DecisionCode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    event_id: String,
    correlation_id: String,
    subject: String,
    capability: String,
    resource: String,
    policy_version: String,
    decision: DecisionCode,
    occurred_at: u64,
}

impl AuditEvent {
    #[allow(clippy::too_many_arguments)] // Explicitly binds every audit field at the trust boundary.
    pub fn new(
        event_id: impl Into<String>,
        correlation_id: impl Into<String>,
        subject: impl Into<String>,
        capability: impl Into<String>,
        resource: impl Into<String>,
        policy_version: impl Into<String>,
        decision: DecisionCode,
        occurred_at: u64,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            correlation_id: correlation_id.into(),
            subject: subject.into(),
            capability: capability.into(),
            resource: resource.into(),
            policy_version: policy_version.into(),
            decision,
            occurred_at,
        }
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }
    pub fn correlation_id(&self) -> &str {
        &self.correlation_id
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn capability(&self) -> &str {
        &self.capability
    }
    pub fn resource(&self) -> &str {
        &self.resource
    }
    pub fn policy_version(&self) -> &str {
        &self.policy_version
    }
    pub fn decision(&self) -> DecisionCode {
        self.decision
    }
    pub fn occurred_at(&self) -> u64 {
        self.occurred_at
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditError {
    Unavailable,
    IntegrityFailure,
    Rejected,
}

/// Implementations must provide durable append semantics, integrity protection,
/// access control and tamper evidence. Updating/deleting prior events is forbidden.
pub trait AuditSink {
    fn append(&self, event: &AuditEvent) -> Result<(), AuditError>;
}

/// Record a decision. An audit failure converts an otherwise positive decision
/// into ESCALATE; callers must not execute the protected operation.
pub fn record_decision<S: AuditSink>(sink: &S, event: &AuditEvent, decision: Decision) -> Decision {
    match sink.append(event) {
        Ok(()) => decision,
        Err(_) => Decision::new(
            DecisionCode::Escalate,
            crate::DecisionReason::AuditUnavailable,
            event.policy_version(),
        ),
    }
}
