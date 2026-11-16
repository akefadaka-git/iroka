//! G09 operation-specific authorization, admission, execution and receipt boundary.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    evaluate, AuditEvent, AuditSink, AuthorizationRequest, DecisionCode, OwnerApprovalError,
    OwnerApprovalVerifier, Policy, RiskLevel, SignedOwnerEffectGrant, VerifiedGenesis,
    VerifiedPrincipal,
};

const EFFECT_DOMAIN: &[u8] = b"IROKA:G09:PROTECTED-EFFECT:V1\0";
const EXECUTION_RESULT_DOMAIN: &[u8] = b"IROKA:G09:EXECUTION-RESULT:V1\0";
const EXECUTION_RECEIPT_DOMAIN: &[u8] = b"IROKA:G09:EXECUTION-RECEIPT:V1\0";

#[derive(Debug, Clone, PartialEq)]
pub struct ProtectedEffectRequest {
    executor_subject: String,
    capability: String,
    resource: String,
    effect_type: String,
    risk: RiskLevel,
    operation: serde_json::Value,
}

impl ProtectedEffectRequest {
    pub fn new(
        executor_subject: impl Into<String>,
        capability: impl Into<String>,
        resource: impl Into<String>,
        effect_type: impl Into<String>,
        risk: RiskLevel,
        operation: serde_json::Value,
    ) -> Self {
        Self {
            executor_subject: executor_subject.into(),
            capability: capability.into(),
            resource: resource.into(),
            effect_type: effect_type.into(),
            risk,
            operation,
        }
    }

    pub fn executor_subject(&self) -> &str {
        &self.executor_subject
    }

    pub fn capability(&self) -> &str {
        &self.capability
    }

    pub fn resource(&self) -> &str {
        &self.resource
    }

    pub fn effect_type(&self) -> &str {
        &self.effect_type
    }

    pub fn risk(&self) -> RiskLevel {
        self.risk
    }

    pub fn operation(&self) -> &serde_json::Value {
        &self.operation
    }

    pub fn risk_class(&self) -> &'static str {
        match self.risk {
            RiskLevel::Low => "low",
            RiskLevel::Moderate => "moderate",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }

    pub fn operation_digest(
        &self,
        subject: &str,
        policy_version: &str,
        genome_digest: &str,
    ) -> Result<[u8; 32], ProtectedEffectError> {
        self.validate()?;
        if subject.trim().is_empty()
            || policy_version.trim().is_empty()
            || !is_sha256_hex(genome_digest)
        {
            return Err(ProtectedEffectError::Malformed);
        }
        let envelope = serde_json::json!({
            "protocol": "iroka.g09.protected-effect",
            "version": 1,
            "subject": subject,
            "executor_subject": self.executor_subject,
            "capability": self.capability,
            "resource": self.resource,
            "effect_type": self.effect_type,
            "risk_class": self.risk_class(),
            "policy_version": policy_version,
            "genome_digest": genome_digest.to_ascii_lowercase(),
            "operation": self.operation,
        });
        let canonical =
            crate::canonical_json(&envelope).map_err(|_| ProtectedEffectError::Malformed)?;
        Ok(Sha256::digest(canonical).into())
    }

    fn validate(&self) -> Result<(), ProtectedEffectError> {
        if self.executor_subject.trim().is_empty()
            || self.capability.trim().is_empty()
            || self.resource.trim().is_empty()
            || self.effect_type.trim().is_empty()
            || !self.operation.is_object()
        {
            return Err(ProtectedEffectError::Malformed);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnerEffectGrantPayload {
    pub nonce: String,
    pub owner_subject: String,
    pub key_id: String,
    pub request_subject: String,
    pub executor_subject: String,
    pub capability: String,
    pub resource: String,
    pub effect_type: String,
    pub risk_class: String,
    pub policy_version: String,
    pub genome_digest: [u8; 32],
    pub operation_digest: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
}

impl OwnerEffectGrantPayload {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ProtectedEffectError> {
        let value = serde_json::to_value(self).map_err(|_| ProtectedEffectError::Malformed)?;
        let canonical =
            crate::canonical_json(&value).map_err(|_| ProtectedEffectError::Malformed)?;
        let mut bytes = b"IROKA:G09:PROTECTED-EFFECT-GRANT:V1\0".to_vec();
        bytes.extend_from_slice(&canonical);
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedOwnerEffectGrant {
    pub payload: OwnerEffectGrantPayload,
    pub signature: Vec<u8>,
}

impl SignedOwnerEffectGrant {
    pub fn from_signature(payload: OwnerEffectGrantPayload, signature: Vec<u8>) -> Self {
        Self { payload, signature }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEffectGrant {
    nonce: String,
    owner_subject: String,
    request_subject: String,
    executor_subject: String,
    capability: String,
    resource: String,
    effect_type: String,
    risk_class: String,
    policy_version: String,
    genome_digest: [u8; 32],
    operation_digest: [u8; 32],
    expires_at: u64,
}

impl VerifiedEffectGrant {
    pub(crate) fn from_payload(payload: &OwnerEffectGrantPayload) -> Self {
        Self {
            nonce: payload.nonce.clone(),
            owner_subject: payload.owner_subject.clone(),
            request_subject: payload.request_subject.clone(),
            executor_subject: payload.executor_subject.clone(),
            capability: payload.capability.clone(),
            resource: payload.resource.clone(),
            effect_type: payload.effect_type.clone(),
            risk_class: payload.risk_class.clone(),
            policy_version: payload.policy_version.clone(),
            genome_digest: payload.genome_digest,
            operation_digest: payload.operation_digest,
            expires_at: payload.expires_at,
        }
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn operation_digest(&self) -> [u8; 32] {
        self.operation_digest
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcome {
    Succeeded,
    Failed,
    Partial,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResultPayload {
    pub protocol: String,
    pub version: u32,
    pub nonce: String,
    pub operation_digest: [u8; 32],
    pub executor_subject: String,
    pub executor_key_id: String,
    pub outcome: ExecutionOutcome,
    pub result_digest: Option<[u8; 32]>,
    pub completed_at: u64,
}

impl ExecutionResultPayload {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ProtectedEffectError> {
        let value = serde_json::to_value(self).map_err(|_| ProtectedEffectError::Malformed)?;
        let canonical =
            crate::canonical_json(&value).map_err(|_| ProtectedEffectError::Malformed)?;
        let mut bytes = EXECUTION_RESULT_DOMAIN.to_vec();
        bytes.extend_from_slice(&canonical);
        Ok(bytes)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedExecutionResult {
    pub payload: ExecutionResultPayload,
    pub signature: Vec<u8>,
}

impl SignedExecutionResult {
    pub fn from_signature(payload: ExecutionResultPayload, signature: Vec<u8>) -> Self {
        Self { payload, signature }
    }
}

#[derive(Debug, Clone)]
pub struct TrustedExecutorKey {
    pub executor_subject: String,
    pub key_id: String,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectExecutionError {
    RejectedBeforeEffect,
    OutcomeUnknown,
    Unavailable,
}

pub trait ProtectedEffectExecutor: Send + Sync {
    /// The executor must use nonce as an idempotency key and reject a repeated
    /// nonce bound to a different operation digest.
    fn execute(
        &self,
        effect: &ProtectedEffectRequest,
        nonce: &str,
        operation_digest: [u8; 32],
    ) -> Result<SignedExecutionResult, EffectExecutionError>;

    /// Resolve an ambiguous execute outcome by nonce. A durable executor should
    /// return the same signed result after a process or network interruption.
    fn lookup(
        &self,
        nonce: &str,
    ) -> Result<Option<SignedExecutionResult>, EffectExecutionError>;
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Succeeded,
    Failed,
    Partial,
    Indeterminate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceipt {
    nonce: String,
    operation_digest: [u8; 32],
    subject: String,
    executor_subject: String,
    capability: String,
    resource: String,
    effect_type: String,
    policy_version: String,
    genome_digest: [u8; 32],
    status: ExecutionStatus,
    result_digest: Option<[u8; 32]>,
    executor_key_id: Option<String>,
    executor_signature: Option<Vec<u8>>,
    failure_code: Option<String>,
    admitted_at: u64,
    completed_at: u64,
    receipt_digest: [u8; 32],
}

impl ExecutionReceipt {
    fn new(
        grant: &VerifiedEffectGrant,
        status: ExecutionStatus,
        result: Option<&SignedExecutionResult>,
        failure_code: Option<String>,
        admitted_at: u64,
        completed_at: u64,
    ) -> Result<Self, ProtectedEffectError> {
        let mut receipt = Self {
            nonce: grant.nonce.clone(),
            operation_digest: grant.operation_digest,
            subject: grant.request_subject.clone(),
            executor_subject: grant.executor_subject.clone(),
            capability: grant.capability.clone(),
            resource: grant.resource.clone(),
            effect_type: grant.effect_type.clone(),
            policy_version: grant.policy_version.clone(),
            genome_digest: grant.genome_digest,
            status,
            result_digest: result.and_then(|value| value.payload.result_digest),
            executor_key_id: result.map(|value| value.payload.executor_key_id.clone()),
            executor_signature: result.map(|value| value.signature.clone()),
            failure_code,
            admitted_at,
            completed_at,
            receipt_digest: [0; 32],
        };
        receipt.receipt_digest = receipt.calculate_digest()?;
        Ok(receipt)
    }

    fn calculate_digest(&self) -> Result<[u8; 32], ProtectedEffectError> {
        let mut value = serde_json::to_value(self).map_err(|_| ProtectedEffectError::Malformed)?;
        if let Some(object) = value.as_object_mut() {
            object.remove("receipt_digest");
        }
        let canonical =
            crate::canonical_json(&value).map_err(|_| ProtectedEffectError::Malformed)?;
        let mut bytes = EXECUTION_RECEIPT_DOMAIN.to_vec();
        bytes.extend_from_slice(&canonical);
        Ok(Sha256::digest(bytes).into())
    }

    pub fn verify_integrity(&self) -> Result<(), ProtectedEffectError> {
        if self.nonce.trim().is_empty()
            || self.subject.trim().is_empty()
            || self.executor_subject.trim().is_empty()
            || self.capability.trim().is_empty()
            || self.resource.trim().is_empty()
            || self.effect_type.trim().is_empty()
            || self.policy_version.trim().is_empty()
            || self.admitted_at > self.completed_at
            || self.calculate_digest()? != self.receipt_digest
        {
            return Err(ProtectedEffectError::ReceiptIntegrityFailure);
        }
        Ok(())
    }

    pub fn verify_executor_attestation(
        &self,
        trusted_keys: &[TrustedExecutorKey],
    ) -> Result<(), ProtectedEffectError> {
        self.verify_integrity()?;
        let (Some(key_id), Some(signature)) =
            (self.executor_key_id.as_deref(), self.executor_signature.as_deref())
        else {
            return if self.status == ExecutionStatus::Failed
                || self.status == ExecutionStatus::Indeterminate
            {
                Ok(())
            } else {
                Err(ProtectedEffectError::InvalidExecutorAttestation)
            };
        };
        let key = trusted_keys
            .iter()
            .find(|item| item.key_id == key_id)
            .ok_or(ProtectedEffectError::UnknownExecutorKey)?;
        if key.executor_subject != self.executor_subject
            || self.completed_at < key.not_before
            || self.completed_at >= key.not_after
        {
            return Err(ProtectedEffectError::UnknownExecutorKey);
        }
        let public_key = VerifyingKey::from_bytes(&key.public_key)
            .map_err(|_| ProtectedEffectError::InvalidExecutorAttestation)?;
        let payload = ExecutionResultPayload {
            protocol: "iroka.g09.execution-result".into(),
            version: 1,
            nonce: self.nonce.clone(),
            operation_digest: self.operation_digest,
            executor_subject: self.executor_subject.clone(),
            executor_key_id: key_id.into(),
            outcome: match self.status {
                ExecutionStatus::Succeeded => ExecutionOutcome::Succeeded,
                ExecutionStatus::Failed => ExecutionOutcome::Failed,
                ExecutionStatus::Partial => ExecutionOutcome::Partial,
                ExecutionStatus::Indeterminate => {
                    return Err(ProtectedEffectError::InvalidExecutorAttestation)
                }
            },
            result_digest: self.result_digest,
            completed_at: self.completed_at,
        };
        let bytes = payload.signing_bytes()?;
        let signature = Signature::from_slice(signature)
            .map_err(|_| ProtectedEffectError::InvalidExecutorAttestation)?;
        public_key
            .verify(&bytes, &signature)
            .map_err(|_| ProtectedEffectError::InvalidExecutorAttestation)
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn status(&self) -> ExecutionStatus {
        self.status
    }

    pub fn receipt_digest(&self) -> [u8; 32] {
        self.receipt_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedEffectError {
    Malformed,
    PolicyDenied,
    PolicyEscalated,
    CapabilityNotApprovalGated,
    OwnerApproval(OwnerApprovalError),
    AuditUnavailable,
    ExecutorUnavailable,
    InvalidExecutorAttestation,
    UnknownExecutorKey,
    ReceiptIntegrityFailure,
    StoreUnavailable,
}

impl From<OwnerApprovalError> for ProtectedEffectError {
    fn from(error: OwnerApprovalError) -> Self {
        Self::OwnerApproval(error)
    }
}

pub struct ProtectedExecutionContext<'a> {
    pub effect: &'a ProtectedEffectRequest,
    pub principal: &'a VerifiedPrincipal,
    pub genesis: &'a VerifiedGenesis,
    pub grant: &'a SignedOwnerEffectGrant,
    pub owner_verifier: &'a OwnerApprovalVerifier,
    pub executor: &'a dyn ProtectedEffectExecutor,
    pub executor_keys: &'a [TrustedExecutorKey],
    pub audit_sink: &'a dyn AuditSink,
    pub policy: &'a Policy,
    pub now: u64,
    pub emergency_stop_active: bool,
    pub admission_event_id: &'a str,
    pub result_event_id: &'a str,
    pub correlation_id: &'a str,
}

pub fn execute_protected_effect(
    context: ProtectedExecutionContext<'_>,
) -> Result<ExecutionReceipt, ProtectedEffectError> {
    context.effect.validate()?;
    if context.principal.subject().trim().is_empty()
        || context.policy.version().trim().is_empty()
        || context.genesis.epoch() != 0
        || crate::igacms::validate_embedded_baseline()
            .map(|fingerprint| fingerprint.digest_hex != context.genesis.digest())
            .unwrap_or(true)
    {
        return Err(ProtectedEffectError::Malformed);
    }

    let request = AuthorizationRequest::new(
        context.principal.subject(),
        context.effect.capability(),
        context.effect.resource(),
        context.effect.risk(),
    );
    let decision = evaluate(
        &request,
        context.policy,
        context.emergency_stop_active,
    );
    match decision.code() {
        DecisionCode::RequireApproval => {}
        DecisionCode::Deny => return Err(ProtectedEffectError::PolicyDenied),
        DecisionCode::Escalate => return Err(ProtectedEffectError::PolicyEscalated),
        DecisionCode::Allow => return Err(ProtectedEffectError::CapabilityNotApprovalGated),
    }

    let grant = context.owner_verifier.verify_and_consume_effect_grant(
        context.grant,
        context.effect,
        context.principal,
        context.genesis,
        context.policy.version(),
        context.now,
    )?;
    let admission_event = AuditEvent::new(
        context.admission_event_id,
        context.correlation_id,
        context.principal.subject(),
        context.effect.capability(),
        context.effect.resource(),
        context.policy.version(),
        DecisionCode::Allow,
        context.now,
    );
    context
        .audit_sink
        .append(&admission_event)
        .map_err(|_| ProtectedEffectError::AuditUnavailable)?;

    let (status, signed_result, failure_code) = match context.executor.execute(
        context.effect,
        grant.nonce(),
        grant.operation_digest(),
    ) {
        Ok(result) => match verify_execution_result(
            &result,
            &grant,
            context.executor_keys,
            context.now,
        ) {
            Ok(()) => (status_from_outcome(result.payload.outcome), Some(result), None),
            Err(_) => (
                ExecutionStatus::Indeterminate,
                None,
                Some("executor_attestation_invalid".into()),
            ),
        },
        Err(EffectExecutionError::RejectedBeforeEffect) => (
            ExecutionStatus::Failed,
            None,
            Some("rejected_before_effect".into()),
        ),
        Err(EffectExecutionError::OutcomeUnknown | EffectExecutionError::Unavailable) => {
            match context.executor.lookup(grant.nonce()) {
                Ok(Some(result)) => match verify_execution_result(
                    &result,
                    &grant,
                    context.executor_keys,
                    context.now,
                ) {
                    Ok(()) => (status_from_outcome(result.payload.outcome), Some(result), None),
                    Err(_) => (
                        ExecutionStatus::Indeterminate,
                        None,
                        Some("executor_reconciliation_attestation_invalid".into()),
                    ),
                },
                Ok(None) => (
                    ExecutionStatus::Indeterminate,
                    None,
                    Some("execution_outcome_unknown".into()),
                ),
                Err(_) => (
                    ExecutionStatus::Indeterminate,
                    None,
                    Some("execution_reconciliation_unavailable".into()),
                ),
            }
        }
    };

    let completed_at = signed_result
        .as_ref()
        .map_or(context.now, |result| result.payload.completed_at);
    let receipt = ExecutionReceipt::new(
        &grant,
        status,
        signed_result.as_ref(),
        failure_code,
        context.now,
        completed_at,
    )?;
    context
        .owner_verifier
        .record_execution_receipt(&receipt, context.now)
        .map_err(|_| ProtectedEffectError::StoreUnavailable)?;

    let result_decision = if status == ExecutionStatus::Succeeded {
        DecisionCode::Allow
    } else {
        DecisionCode::Escalate
    };
    let result_event = AuditEvent::new(
        context.result_event_id,
        context.correlation_id,
        context.principal.subject(),
        context.effect.capability(),
        context.effect.resource(),
        context.policy.version(),
        result_decision,
        completed_at,
    );
    context
        .audit_sink
        .append(&result_event)
        .map_err(|_| ProtectedEffectError::AuditUnavailable)?;
    Ok(receipt)
}

fn status_from_outcome(outcome: ExecutionOutcome) -> ExecutionStatus {
    match outcome {
        ExecutionOutcome::Succeeded => ExecutionStatus::Succeeded,
        ExecutionOutcome::Failed => ExecutionStatus::Failed,
        ExecutionOutcome::Partial => ExecutionStatus::Partial,
    }
}

fn verify_execution_result(
    result: &SignedExecutionResult,
    grant: &VerifiedEffectGrant,
    trusted_keys: &[TrustedExecutorKey],
    now: u64,
) -> Result<(), ProtectedEffectError> {
    let p = &result.payload;
    if p.protocol != "iroka.g09.execution-result"
        || p.version != 1
        || p.nonce != grant.nonce
        || p.operation_digest != grant.operation_digest
        || p.executor_subject != grant.executor_subject
        || p.executor_key_id.trim().is_empty()
        || p.completed_at.saturating_add(30) < now
        || p.completed_at > now.saturating_add(30)
        || matches!(p.outcome, ExecutionOutcome::Succeeded | ExecutionOutcome::Partial)
            && p.result_digest.is_none()
    {
        return Err(ProtectedEffectError::InvalidExecutorAttestation);
    }
    let key = trusted_keys
        .iter()
        .find(|item| item.key_id == p.executor_key_id)
        .ok_or(ProtectedEffectError::UnknownExecutorKey)?;
    if key.executor_subject != p.executor_subject
        || p.completed_at < key.not_before
        || p.completed_at >= key.not_after
    {
        return Err(ProtectedEffectError::UnknownExecutorKey);
    }
    let public_key = VerifyingKey::from_bytes(&key.public_key)
        .map_err(|_| ProtectedEffectError::InvalidExecutorAttestation)?;
    let bytes = p.signing_bytes()?;
    let signature = Signature::from_slice(&result.signature)
        .map_err(|_| ProtectedEffectError::InvalidExecutorAttestation)?;
    public_key
        .verify(&bytes, &signature)
        .map_err(|_| ProtectedEffectError::InvalidExecutorAttestation)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
