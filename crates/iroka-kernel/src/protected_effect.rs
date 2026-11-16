//! G09 operation-specific authorization, admission, execution and receipt boundary.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    evaluate, AuditEvent, AuditSink, AuthorizationRequest, DecisionCode, OwnerApprovalError,
    OwnerApprovalVerifier, Policy, RiskLevel, VerifiedGenesis, VerifiedPrincipal,
};

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
        principal: &VerifiedPrincipal,
        policy_version: &str,
        genome_digest: &str,
    ) -> Result<[u8; 32], ProtectedEffectError> {
        self.validate()?;
        if principal.subject().trim().is_empty()
            || principal.issuer().trim().is_empty()
            || principal.credential_id().trim().is_empty()
            || policy_version.trim().is_empty()
            || !is_sha256_hex(genome_digest)
        {
            return Err(ProtectedEffectError::Malformed);
        }
        let envelope = serde_json::json!({
            "protocol": "iroka.g09.protected-effect",
            "version": 1,
            "subject": principal.subject(),
            "issuer": principal.issuer(),
            "credential_id": principal.credential_id(),
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
        if canonical.len() > 1_048_576 {
            return Err(ProtectedEffectError::Malformed);
        }
        Ok(Sha256::digest(canonical).into())
    }

    fn validate(&self) -> Result<(), ProtectedEffectError> {
        if self.executor_subject.trim().is_empty()
            || self.executor_subject.len() > 256
            || self.capability.trim().is_empty()
            || self.capability.len() > 256
            || self.resource.trim().is_empty()
            || self.resource.len() > 256
            || self.effect_type.trim().is_empty()
            || self.effect_type.len() > 256
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
    pub revoked_at: Option<u64>,
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
    fn lookup(&self, nonce: &str) -> Result<Option<SignedExecutionResult>, EffectExecutionError>;
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
    owner_subject: String,
    subject: String,
    executor_subject: String,
    capability: String,
    resource: String,
    effect_type: String,
    risk_class: String,
    policy_version: String,
    genome_digest: [u8; 32],
    grant_expires_at: u64,
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
            owner_subject: grant.owner_subject.clone(),
            subject: grant.request_subject.clone(),
            executor_subject: grant.executor_subject.clone(),
            capability: grant.capability.clone(),
            resource: grant.resource.clone(),
            effect_type: grant.effect_type.clone(),
            risk_class: grant.risk_class.clone(),
            policy_version: grant.policy_version.clone(),
            genome_digest: grant.genome_digest,
            grant_expires_at: grant.expires_at,
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
            || self.owner_subject.trim().is_empty()
            || self.subject.trim().is_empty()
            || self.executor_subject.trim().is_empty()
            || self.capability.trim().is_empty()
            || self.resource.trim().is_empty()
            || self.effect_type.trim().is_empty()
            || self.policy_version.trim().is_empty()
            || self.admitted_at > self.completed_at
            || self.admitted_at >= self.grant_expires_at
            || self.risk_class.trim().is_empty()
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
        validate_executor_keys(trusted_keys)?;
        let (Some(key_id), Some(signature)) = (
            self.executor_key_id.as_deref(),
            self.executor_signature.as_deref(),
        ) else {
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
            || key.revoked_at.is_some_and(|revoked_at| self.completed_at >= revoked_at)
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

/// Opaque receipt evidence that has passed the kernel's result/receipt checks.
/// Its constructor is crate-private so untrusted deserialized receipts cannot be
/// inserted into the security store as verified execution evidence.
#[derive(Debug, Clone)]
pub struct VerifiedExecutionReceipt {
    receipt: ExecutionReceipt,
}

impl VerifiedExecutionReceipt {
    pub(crate) fn new(receipt: ExecutionReceipt) -> Result<Self, ProtectedEffectError> {
        receipt.verify_integrity()?;
        Ok(Self { receipt })
    }

    pub fn receipt(&self) -> &ExecutionReceipt {
        &self.receipt
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
    InvalidExecutorAttestation,
    InvalidExecutorKeySet,
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

fn validate_executor_keys(keys: &[TrustedExecutorKey]) -> Result<(), ProtectedEffectError> {
    let mut key_ids = std::collections::HashSet::new();
    let mut public_keys = std::collections::HashSet::new();
    for key in keys {
        if key.executor_subject.trim().is_empty()
            || key.executor_subject.len() > 256
            || key.key_id.trim().is_empty()
            || key.key_id.len() > 256
            || key.not_before >= key.not_after
            || key.revoked_at.is_some_and(|revoked_at| revoked_at < key.not_before)
            || VerifyingKey::from_bytes(&key.public_key).is_err()
            || !key_ids.insert(key.key_id.as_str())
            || !public_keys.insert(key.public_key)
        {
            return Err(ProtectedEffectError::InvalidExecutorKeySet);
        }
    }
    Ok(())
}

pub fn execute_protected_effect(
    context: ProtectedExecutionContext<'_>,
) -> Result<ExecutionReceipt, ProtectedEffectError> {
    context.effect.validate()?;
    validate_executor_keys(context.executor_keys)?;
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
    let decision = evaluate(&request, context.policy, context.emergency_stop_active);
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

    let (status, signed_result, failure_code) =
        match context
            .executor
            .execute(context.effect, grant.nonce(), grant.operation_digest())
        {
            Ok(result) => {
                match verify_execution_result(&result, &grant, context.executor_keys, context.now) {
                    Ok(()) => (
                        status_from_outcome(result.payload.outcome),
                        Some(result),
                        None,
                    ),
                    Err(_) => (
                        ExecutionStatus::Indeterminate,
                        None,
                        Some("executor_attestation_invalid".into()),
                    ),
                }
            }
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
                        Ok(()) => (
                            status_from_outcome(result.payload.outcome),
                            Some(result),
                            None,
                        ),
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
    let verified_receipt = VerifiedExecutionReceipt::new(receipt.clone())?;
    context
        .owner_verifier
        .record_execution_receipt(&verified_receipt, context.now)
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
        || p.completed_at < now
        || p.completed_at > now.saturating_add(30)
        || matches!(
            p.outcome,
            ExecutionOutcome::Succeeded | ExecutionOutcome::Partial
        ) && p.result_digest.is_none()
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
        || key.revoked_at.is_some_and(|revoked_at| p.completed_at >= revoked_at)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        sign_genesis, validate_embedded_baseline, verify_genesis_with_trust_roots, Attestation,
        Genesis, SqliteAuditSink, SqliteSecurityStore, TrustRoot, TrustRootSet, TrustedOwnerKey,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::HashMap;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };

    struct TestExecutor {
        subject: String,
        key_id: String,
        key: SigningKey,
        calls: AtomicUsize,
        results: Mutex<HashMap<String, SignedExecutionResult>>,
    }

    impl TestExecutor {
        fn new(subject: &str, key_id: &str, seed: u8) -> Self {
            Self {
                subject: subject.into(),
                key_id: key_id.into(),
                key: SigningKey::from_bytes(&[seed; 32]),
                calls: AtomicUsize::new(0),
                results: Mutex::new(HashMap::new()),
            }
        }

        fn trusted_key(&self) -> TrustedExecutorKey {
            TrustedExecutorKey {
                executor_subject: self.subject.clone(),
                key_id: self.key_id.clone(),
                public_key: self.key.verifying_key().to_bytes(),
                not_before: 900,
                not_after: 5_000,
                revoked_at: None,
            }
        }

        fn signed_result(
            &self,
            nonce: &str,
            operation_digest: [u8; 32],
            completed_at: u64,
        ) -> SignedExecutionResult {
            let payload = ExecutionResultPayload {
                protocol: "iroka.g09.execution-result".into(),
                version: 1,
                nonce: nonce.into(),
                operation_digest,
                executor_subject: self.subject.clone(),
                executor_key_id: self.key_id.clone(),
                outcome: ExecutionOutcome::Succeeded,
                result_digest: Some(Sha256::digest(b"committed-effect-result").into()),
                completed_at,
            };
            let signature = self
                .key
                .sign(&payload.signing_bytes().unwrap())
                .to_bytes()
                .to_vec();
            SignedExecutionResult::from_signature(payload, signature)
        }
    }

    impl ProtectedEffectExecutor for TestExecutor {
        fn execute(
            &self,
            _effect: &ProtectedEffectRequest,
            nonce: &str,
            operation_digest: [u8; 32],
        ) -> Result<SignedExecutionResult, EffectExecutionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(existing) = self.results.lock().unwrap().get(nonce).cloned() {
                return Ok(existing);
            }
            let result = self.signed_result(nonce, operation_digest, 1_201);
            self.results
                .lock()
                .unwrap()
                .insert(nonce.into(), result.clone());
            Ok(result)
        }

        fn lookup(
            &self,
            nonce: &str,
        ) -> Result<Option<SignedExecutionResult>, EffectExecutionError> {
            Ok(self.results.lock().unwrap().get(nonce).cloned())
        }
    }

    struct UnknownExecutor;
    impl ProtectedEffectExecutor for UnknownExecutor {
        fn execute(
            &self,
            _effect: &ProtectedEffectRequest,
            _nonce: &str,
            _operation_digest: [u8; 32],
        ) -> Result<SignedExecutionResult, EffectExecutionError> {
            Err(EffectExecutionError::OutcomeUnknown)
        }

        fn lookup(
            &self,
            _nonce: &str,
        ) -> Result<Option<SignedExecutionResult>, EffectExecutionError> {
            Ok(None)
        }
    }

    struct FailedAudit;
    impl AuditSink for FailedAudit {
        fn append(&self, _event: &AuditEvent) -> Result<(), crate::AuditError> {
            Err(crate::AuditError::Unavailable)
        }
    }

    fn verified_genesis() -> VerifiedGenesis {
        let fingerprint = validate_embedded_baseline().unwrap();
        let signer = SigningKey::from_bytes(&[72u8; 32]);
        let root = TrustRoot {
            key_id: "genesis-root".into(),
            public_key: signer.verifying_key().to_bytes(),
            not_before: 900,
            not_after: 5_000,
            provenance_ref: "root-provenance:test".into(),
        };
        let mut genesis = Genesis {
            dna_id: "iroka.dna".into(),
            dna_version: "1.0.0".into(),
            genome_id: "IROKA_ZERO_GENOME".into(),
            genome_version: "1.0.0".into(),
            digest: fingerprint.digest_hex.clone(),
            canonicalization: "RFC8785-JCS".into(),
            hash_algorithm: "SHA-256".into(),
            epoch: 0,
            parent: None,
            owner_approval_ref: "owner-approval:test".into(),
            trust_root_key_ids: vec!["genesis-root".into()],
            trust_root_provenance_refs: vec!["root-provenance:test".into()],
            attestation: Attestation {
                envelope_type: "iroka.igacms.attestation".into(),
                version: "1.0.0".into(),
                digest: String::new(),
                epoch: 0,
                key_id: "genesis-root".into(),
                signature: Vec::new(),
            },
            audit_refs: vec!["audit:test".into()],
        };
        genesis.attestation = sign_genesis(&genesis, "genesis-root", &signer).unwrap();
        let roots = TrustRootSet::new(vec![root]).unwrap();
        verify_genesis_with_trust_roots(&genesis, &fingerprint, &roots, 1_200).unwrap()
    }

    fn effect() -> ProtectedEffectRequest {
        ProtectedEffectRequest::new(
            "executor:finance",
            "finance.transfer",
            "account:source-001",
            "bank.transfer",
            RiskLevel::Critical,
            serde_json::json!({
                "amount_minor": 25000,
                "currency": "ETB",
                "destination": "account:beneficiary-002",
                "reference": "transfer:test-001"
            }),
        )
    }

    fn policy() -> Policy {
        Policy::new(
            "policy-v1",
            vec!["finance.transfer".into()],
            vec!["finance.transfer".into()],
            RiskLevel::Critical,
        )
    }

    fn principal() -> VerifiedPrincipal {
        VerifiedPrincipal::from_verified_credential(
            "principal:finance-operator".into(),
            "issuer:iroka-test".into(),
            "credential:finance-operator".into(),
        )
    }

    fn owner_verifier() -> (SigningKey, OwnerApprovalVerifier) {
        let signer = SigningKey::from_bytes(&[91u8; 32]);
        let store = Arc::new(SqliteSecurityStore::open_in_memory().unwrap());
        let verifier = OwnerApprovalVerifier::new(
            vec![TrustedOwnerKey {
                owner_subject: "owner:akefa".into(),
                key_id: "owner-effect-key".into(),
                public_key: signer.verifying_key().to_bytes(),
                not_before: 900,
                not_after: 5_000,
            }],
            store,
        )
        .unwrap();
        (signer, verifier)
    }

    fn decode_sha256_hex(value: &str) -> [u8; 32] {
        let mut digest = [0_u8; 32];
        for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            let text = std::str::from_utf8(chunk).unwrap();
            digest[index] = u8::from_str_radix(text, 16).unwrap();
        }
        digest
    }

    fn signed_grant(
        signer: &SigningKey,
        effect: &ProtectedEffectRequest,
        principal: &VerifiedPrincipal,
        genesis: &VerifiedGenesis,
        nonce: &str,
    ) -> SignedOwnerEffectGrant {
        let payload = OwnerEffectGrantPayload {
            nonce: nonce.into(),
            owner_subject: "owner:akefa".into(),
            key_id: "owner-effect-key".into(),
            request_subject: principal.subject().into(),
            executor_subject: effect.executor_subject().into(),
            capability: effect.capability().into(),
            resource: effect.resource().into(),
            effect_type: effect.effect_type().into(),
            risk_class: effect.risk_class().into(),
            policy_version: "policy-v1".into(),
            genome_digest: decode_sha256_hex(genesis.digest()),
            operation_digest: effect
                .operation_digest(principal, "policy-v1", genesis.digest())
                .unwrap(),
            issued_at: 1_100,
            expires_at: 1_400,
        };
        let signature = signer
            .sign(&payload.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        SignedOwnerEffectGrant::from_signature(payload, signature)
    }

    #[test]
    fn protected_effect_requires_owner_grant_and_persists_verifiable_receipt() {
        let genesis = verified_genesis();
        let principal = principal();
        let effect = effect();
        let policy = policy();
        let (owner_signer, owner) = owner_verifier();
        let grant = signed_grant(
            &owner_signer,
            &effect,
            &principal,
            &genesis,
            "nonce:effect-success",
        );
        let executor = TestExecutor::new("executor:finance", "executor-key-01", 92);
        let trusted = vec![executor.trusted_key()];
        let audit = SqliteAuditSink::open_in_memory().unwrap();

        let receipt = execute_protected_effect(ProtectedExecutionContext {
            effect: &effect,
            principal: &principal,
            genesis: &genesis,
            grant: &grant,
            owner_verifier: &owner,
            executor: &executor,
            executor_keys: &trusted,
            audit_sink: &audit,
            policy: &policy,
            now: 1_200,
            emergency_stop_active: false,
            admission_event_id: "event:effect-admission",
            result_event_id: "event:effect-result",
            correlation_id: "trace:effect-001",
        })
        .unwrap();

        assert_eq!(receipt.status(), ExecutionStatus::Succeeded);
        receipt.verify_integrity().unwrap();
        receipt.verify_executor_attestation(&trusted).unwrap();
        assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
        assert_eq!(audit.verified_head().unwrap().0, 2);

        let stored = owner
            .latest_execution_receipt_bytes("nonce:effect-success")
            .unwrap()
            .unwrap();
        let recovered: ExecutionReceipt = serde_json::from_slice(&stored).unwrap();
        recovered.verify_integrity().unwrap();
        recovered.verify_executor_attestation(&trusted).unwrap();

        let replay = execute_protected_effect(ProtectedExecutionContext {
            effect: &effect,
            principal: &principal,
            genesis: &genesis,
            grant: &grant,
            owner_verifier: &owner,
            executor: &executor,
            executor_keys: &trusted,
            audit_sink: &audit,
            policy: &policy,
            now: 1_201,
            emergency_stop_active: false,
            admission_event_id: "event:effect-replay",
            result_event_id: "event:effect-replay-result",
            correlation_id: "trace:effect-001",
        });
        assert_eq!(
            replay,
            Err(ProtectedEffectError::OwnerApproval(
                OwnerApprovalError::Replay
            ))
        );
        assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn effect_grant_is_bound_to_exact_operation_and_executor() {
        let genesis = verified_genesis();
        let principal = principal();
        let effect = effect();
        let (owner_signer, owner) = owner_verifier();
        let grant = signed_grant(
            &owner_signer,
            &effect,
            &principal,
            &genesis,
            "nonce:effect-scope",
        );
        let altered = ProtectedEffectRequest::new(
            effect.executor_subject(),
            effect.capability(),
            effect.resource(),
            effect.effect_type(),
            effect.risk(),
            serde_json::json!({
                "amount_minor": 25001,
                "currency": "ETB",
                "destination": "account:beneficiary-002",
                "reference": "transfer:test-001"
            }),
        );
        assert_eq!(
            owner.verify_and_consume_effect_grant(
                &grant,
                &altered,
                &principal,
                &genesis,
                "policy-v1",
                1_200,
            ),
            Err(OwnerApprovalError::ScopeMismatch)
        );

        let verified = owner
            .verify_and_consume_effect_grant(
                &grant,
                &effect,
                &principal,
                &genesis,
                "policy-v1",
                1_200,
            )
            .unwrap();
        assert_eq!(verified.nonce(), "nonce:effect-scope");
    }

    #[test]
    fn emergency_stop_blocks_execution_before_grant_consumption() {
        let genesis = verified_genesis();
        let principal = principal();
        let effect = effect();
        let policy = policy();
        let (owner_signer, owner) = owner_verifier();
        let grant = signed_grant(
            &owner_signer,
            &effect,
            &principal,
            &genesis,
            "nonce:emergency-stop",
        );
        let executor = TestExecutor::new("executor:finance", "executor-key-01", 93);
        let audit = SqliteAuditSink::open_in_memory().unwrap();

        assert_eq!(
            execute_protected_effect(ProtectedExecutionContext {
                effect: &effect,
                principal: &principal,
                genesis: &genesis,
                grant: &grant,
                owner_verifier: &owner,
                executor: &executor,
                executor_keys: &[executor.trusted_key()],
                audit_sink: &audit,
                policy: &policy,
                now: 1_200,
                emergency_stop_active: true,
                admission_event_id: "event:emergency",
                result_event_id: "event:emergency-result",
                correlation_id: "trace:emergency",
            }),
            Err(ProtectedEffectError::PolicyEscalated)
        );
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        owner
            .verify_and_consume_effect_grant(
                &grant,
                &effect,
                &principal,
                &genesis,
                "policy-v1",
                1_200,
            )
            .unwrap();
    }

    #[test]
    fn audit_admission_failure_consumes_grant_but_never_executes_effect() {
        let genesis = verified_genesis();
        let principal = principal();
        let effect = effect();
        let policy = policy();
        let (owner_signer, owner) = owner_verifier();
        let grant = signed_grant(
            &owner_signer,
            &effect,
            &principal,
            &genesis,
            "nonce:audit-failure",
        );
        let executor = TestExecutor::new("executor:finance", "executor-key-01", 94);

        assert_eq!(
            execute_protected_effect(ProtectedExecutionContext {
                effect: &effect,
                principal: &principal,
                genesis: &genesis,
                grant: &grant,
                owner_verifier: &owner,
                executor: &executor,
                executor_keys: &[executor.trusted_key()],
                audit_sink: &FailedAudit,
                policy: &policy,
                now: 1_200,
                emergency_stop_active: false,
                admission_event_id: "event:audit-failure",
                result_event_id: "event:audit-failure-result",
                correlation_id: "trace:audit-failure",
            }),
            Err(ProtectedEffectError::AuditUnavailable)
        );
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            owner.verify_and_consume_effect_grant(
                &grant,
                &effect,
                &principal,
                &genesis,
                "policy-v1",
                1_201,
            ),
            Err(OwnerApprovalError::Replay)
        );
    }

    #[test]
    fn revoked_executor_key_cannot_produce_a_success_receipt() {
        let genesis = verified_genesis();
        let principal = principal();
        let effect = effect();
        let policy = policy();
        let (owner_signer, owner) = owner_verifier();
        let grant = signed_grant(
            &owner_signer,
            &effect,
            &principal,
            &genesis,
            "nonce:revoked-executor",
        );
        let executor = TestExecutor::new("executor:finance", "executor-key-revoked", 95);
        let mut trusted_key = executor.trusted_key();
        trusted_key.revoked_at = Some(1_201);
        let audit = SqliteAuditSink::open_in_memory().unwrap();

        let receipt = execute_protected_effect(ProtectedExecutionContext {
            effect: &effect,
            principal: &principal,
            genesis: &genesis,
            grant: &grant,
            owner_verifier: &owner,
            executor: &executor,
            executor_keys: &[trusted_key.clone()],
            audit_sink: &audit,
            policy: &policy,
            now: 1_200,
            emergency_stop_active: false,
            admission_event_id: "event:revoked-executor-admission",
            result_event_id: "event:revoked-executor-result",
            correlation_id: "trace:revoked-executor",
        })
        .unwrap();
        assert_eq!(receipt.status(), ExecutionStatus::Indeterminate);
        receipt.verify_integrity().unwrap();
        assert_eq!(receipt.verify_executor_attestation(&[trusted_key]), Ok(()));
    }

    #[test]
    fn duplicate_executor_trust_keys_fail_before_consuming_owner_grant() {
        let genesis = verified_genesis();
        let principal = principal();
        let effect = effect();
        let policy = policy();
        let (owner_signer, owner) = owner_verifier();
        let grant = signed_grant(
            &owner_signer,
            &effect,
            &principal,
            &genesis,
            "nonce:duplicate-executor-key",
        );
        let executor = TestExecutor::new("executor:finance", "executor-key-duplicate", 96);
        let key = executor.trusted_key();
        let audit = SqliteAuditSink::open_in_memory().unwrap();

        assert_eq!(
            execute_protected_effect(ProtectedExecutionContext {
                effect: &effect,
                principal: &principal,
                genesis: &genesis,
                grant: &grant,
                owner_verifier: &owner,
                executor: &executor,
                executor_keys: &[key.clone(), key],
                audit_sink: &audit,
                policy: &policy,
                now: 1_200,
                emergency_stop_active: false,
                admission_event_id: "event:duplicate-key-admission",
                result_event_id: "event:duplicate-key-result",
                correlation_id: "trace:duplicate-key",
            }),
            Err(ProtectedEffectError::InvalidExecutorKeySet)
        );
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        owner
            .verify_and_consume_effect_grant(
                &grant,
                &effect,
                &principal,
                &genesis,
                "policy-v1",
                1_200,
            )
            .unwrap();
    }

    #[test]
    fn unknown_executor_outcome_is_recorded_as_indeterminate_not_success() {
        let genesis = verified_genesis();
        let principal = principal();
        let effect = effect();
        let policy = policy();
        let (owner_signer, owner) = owner_verifier();
        let grant = signed_grant(
            &owner_signer,
            &effect,
            &principal,
            &genesis,
            "nonce:unknown-outcome",
        );
        let audit = SqliteAuditSink::open_in_memory().unwrap();
        let receipt = execute_protected_effect(ProtectedExecutionContext {
            effect: &effect,
            principal: &principal,
            genesis: &genesis,
            grant: &grant,
            owner_verifier: &owner,
            executor: &UnknownExecutor,
            executor_keys: &[],
            audit_sink: &audit,
            policy: &policy,
            now: 1_200,
            emergency_stop_active: false,
            admission_event_id: "event:unknown-admission",
            result_event_id: "event:unknown-result",
            correlation_id: "trace:unknown",
        })
        .unwrap();
        assert_eq!(receipt.status(), ExecutionStatus::Indeterminate);
        receipt.verify_integrity().unwrap();
        receipt.verify_executor_attestation(&[]).unwrap();
    }
}
