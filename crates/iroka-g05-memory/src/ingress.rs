//! Production-facing G05 ingress boundary.
//! G01 credentials, G02 tenant/organization authority, and G09 execution policy
//! are revalidated at ingress and again immediately before every external effect.
//! No caller-supplied principal, authorization boolean, or timestamp is accepted.
use crate::{
    AuditEvent, AuthorizationRequest, G02AuthorizationAuthority, G02PolicySnapshot, G05Error,
    G11MemoryAuditAuthority, Operation,
};
use iroka_kernel::{
    evaluate, CredentialError, DecisionCode, Ed25519CredentialVerifier, Policy, RevocationChecker,
    RiskLevel, TenantContext, VerifiedPrincipal,
};
use std::sync::atomic::{AtomicBool, Ordering};

pub trait TrustedClock: Send + Sync {
    fn now_unix_seconds(&self) -> Result<u64, G05Error>;
}

/// G09 policy source must return a fresh authoritative policy snapshot and
/// emergency-stop state on every invocation. A stale/unavailable source denies.
pub trait G09PolicyResolver: Send + Sync {
    fn current_policy(&self, now: u64) -> Result<(Policy, bool), G05Error>;

    /// Recheck tenant/resource scope against current G09 authority state.
    /// This is mandatory because the kernel capability policy alone does not
    /// establish ownership of a particular tenant memory resource.
    fn authorize_resource_scope(
        &self,
        principal: &VerifiedPrincipal,
        request: &AuthorizationRequest,
        now: u64,
    ) -> Result<(), G05Error>;

    /// Hold a consistent G02 authority guard for the complete protected effect.
    /// Implementations serialize membership, policy, revocation and emergency-stop
    /// changes against this closure. The default denies rather than providing an
    /// unsafe check-then-act fallback.
    fn with_execution_authority<T>(
        &self,
        principal: &VerifiedPrincipal,
        tenant: &TenantContext,
        request: &AuthorizationRequest,
        now: u64,
        effect: impl FnOnce(&G02PolicySnapshot) -> Result<T, G05Error>,
    ) -> Result<T, G05Error> {
        let _ = (principal, tenant, request, now, effect);
        Err(G05Error::AuthorityUnavailable)
    }
}

pub trait G09ExecutionRevalidator: Send + Sync {
    fn revalidate(
        &self,
        principal: &VerifiedPrincipal,
        request: &AuthorizationRequest,
        now: u64,
    ) -> Result<(), G05Error>;

    /// Execute under a fresh, version-matched G01/G02 authority guard.
    /// A previous revalidation or Kernel ALLOW is never accepted as a grant.
    fn with_current_authority<T>(
        &self,
        principal: &VerifiedPrincipal,
        tenant: &TenantContext,
        request: &AuthorizationRequest,
        now: u64,
        effect: impl FnOnce(&G02PolicySnapshot) -> Result<T, G05Error>,
    ) -> Result<T, G05Error> {
        let _ = (principal, tenant, request, now, effect);
        Err(G05Error::AuthorityUnavailable)
    }
}

/// Kernel-backed G09 execution gate. The resolver is the trusted G09 policy
/// source; the gate maps the G05 operation into the kernel policy vocabulary.
pub struct KernelG09ExecutionRevalidator<P> {
    policies: P,
}

impl<P> KernelG09ExecutionRevalidator<P> {
    pub fn new(policies: P) -> Self {
        Self { policies }
    }
}

impl<P: G09PolicyResolver> G09ExecutionRevalidator for KernelG09ExecutionRevalidator<P> {
    fn with_current_authority<T>(
        &self,
        principal: &VerifiedPrincipal,
        tenant: &TenantContext,
        request: &AuthorizationRequest,
        now: u64,
        effect: impl FnOnce(&G02PolicySnapshot) -> Result<T, G05Error>,
    ) -> Result<T, G05Error> {
        self.policies
            .with_execution_authority(principal, tenant, request, now, effect)
    }

    fn revalidate(
        &self,
        principal: &VerifiedPrincipal,
        request: &AuthorizationRequest,
        now: u64,
    ) -> Result<(), G05Error> {
        if request.principal_ref != principal.subject() {
            return Err(G05Error::AuthorizationDenied);
        }
        self.policies
            .authorize_resource_scope(principal, request, now)?;
        let (policy, emergency_stop) = self.policies.current_policy(now)?;
        let capability = capability_for(request.operation);
        let resource = format!(
            "g05:tenant:{}:memory:{}",
            request.tenant_ref,
            request.memory_id.as_deref().unwrap_or("*")
        );
        let kernel_request = iroka_kernel::AuthorizationRequest::new(
            principal.subject(),
            capability,
            resource,
            risk_for(request.operation),
        );
        match evaluate(&kernel_request, &policy, emergency_stop).code() {
            DecisionCode::Allow => Ok(()),
            _ => Err(G05Error::AuthorizationDenied),
        }
    }
}

pub(crate) fn capability_for(operation: Operation) -> &'static str {
    match operation {
        Operation::Propose => "g05.memory.propose",
        Operation::CreateWorking => "g05.memory.working.create",
        Operation::CreateEpisodic => "g05.memory.episodic.create",
        Operation::ActivateDurable => "g05.memory.durable.activate",
        Operation::Retrieve => "g05.memory.retrieve",
        Operation::InspectMetadata => "g05.memory.metadata.inspect",
        Operation::Correct => "g05.memory.correct",
        Operation::Restrict => "g05.memory.restrict",
        Operation::RequestDeletion => "g05.memory.delete.request",
        Operation::VerifyDeletion => "g05.memory.delete.verify",
        Operation::Share => "g05.memory.share",
        Operation::GrantEpisodicConsent => "g05.memory.episodic.consent.grant",
        Operation::WithdrawEpisodicConsent => "g05.memory.episodic.consent.withdraw",
    }
}

pub(crate) fn risk_for(operation: Operation) -> RiskLevel {
    match operation {
        Operation::ActivateDurable
        | Operation::RequestDeletion
        | Operation::VerifyDeletion
        | Operation::Share => RiskLevel::Critical,
        Operation::Correct
        | Operation::Restrict
        | Operation::GrantEpisodicConsent
        | Operation::WithdrawEpisodicConsent => RiskLevel::High,
        Operation::Propose
        | Operation::CreateWorking
        | Operation::CreateEpisodic
        | Operation::Retrieve
        | Operation::InspectMetadata => RiskLevel::Moderate,
    }
}

/// An ingress context can only be constructed by successful G01/G02/G09 checks.
pub struct AuthenticatedG05Request {
    principal: VerifiedPrincipal,
    request: AuthorizationRequest,
    authenticated_at: u64,
    execution_id: String,
    execution_consumed: AtomicBool,
}

impl AuthenticatedG05Request {
    pub fn principal(&self) -> &VerifiedPrincipal {
        &self.principal
    }

    pub fn request(&self) -> &AuthorizationRequest {
        &self.request
    }

    pub fn authenticated_at(&self) -> u64 {
        self.authenticated_at
    }
}

pub struct G05IngressService<R, G, C, E> {
    credentials: Ed25519CredentialVerifier<R>,
    g02: G,
    clock: C,
    g09: E,
    expected_audience: String,
}

impl<R, G, C, E> G05IngressService<R, G, C, E>
where
    R: RevocationChecker,
    G: G02AuthorizationAuthority,
    C: TrustedClock,
    E: G09ExecutionRevalidator,
{
    pub fn new(
        credentials: Ed25519CredentialVerifier<R>,
        g02: G,
        clock: C,
        g09: E,
        expected_audience: impl Into<String>,
    ) -> Result<Self, G05Error> {
        let expected_audience = expected_audience.into();
        if expected_audience.trim().is_empty() || expected_audience.len() > 512 {
            return Err(G05Error::MalformedRecord);
        }
        Ok(Self {
            credentials,
            g02,
            clock,
            g09,
            expected_audience,
        })
    }

    /// Read the trusted service clock. Callers cannot supply or override time.
    pub fn current_time(&self) -> Result<u64, G05Error> {
        self.clock.now_unix_seconds()
    }

    /// Authenticate and authorize the request from server-verified evidence.
    /// The request carries scope and operation only; its principal_ref must
    /// exactly match the G01-authenticated subject.
    pub fn authorize(
        &self,
        compact_credential: &str,
        request: AuthorizationRequest,
    ) -> Result<AuthenticatedG05Request, G05Error> {
        let now = self.clock.now_unix_seconds()?;
        let principal = self.authenticate(compact_credential, now)?;
        if request.principal_ref != principal.subject() {
            return Err(G05Error::AuthorizationDenied);
        }
        self.g02.authorize_g05(&request)?;
        self.g09.revalidate(&principal, &request, now)?;
        let sequence = NEXT_G09_EXECUTION_ID.fetch_add(1, Ordering::Relaxed);
        let nonce_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let execution_id = crate::sha256_hex(
            format!(
                "IROKA:G09:EXECUTION:V1:{}:{}:{}:{}:{}:{}:{}",
                request.correlation_ref,
                principal.subject(),
                principal.credential_id(),
                now,
                std::process::id(),
                nonce_time,
                sequence
            )
            .as_bytes(),
        );
        Ok(AuthenticatedG05Request {
            principal,
            request,
            authenticated_at: now,
            execution_id,
            execution_consumed: AtomicBool::new(false),
        })
    }

    /// Legacy check-then-act API is intentionally disabled. Callers must use
    /// execute_external_with_context and supply an opaque G01 TenantContext plus G11.
    #[deprecated(note = "use execute_external_with_context; this API fails closed")]
    pub fn execute_external<T>(
        &self,
        _context: &AuthenticatedG05Request,
        _compact_credential: &str,
        _effect: impl FnOnce() -> Result<T, G05Error>,
    ) -> Result<T, G05Error> {
        Err(G05Error::AuthorityUnavailable)
    }

    /// Execute one protected effect under the current G01/G02 authority snapshot.
    /// The one-shot context cannot be replayed; G11 must durably accept the
    /// intent receipt before the effect and the outcome receipt afterward.
    pub fn execute_external_with_context<T, A>(
        &self,
        context: &AuthenticatedG05Request,
        tenant: &TenantContext,
        compact_credential: &str,
        g11: &A,
        effect: impl FnOnce() -> Result<T, G05Error>,
    ) -> Result<T, G05Error>
    where
        A: G11MemoryAuditAuthority,
    {
        if context
            .execution_consumed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(G05Error::ExecutionReplay);
        }
        let now = self.clock.now_unix_seconds()?;
        let current = self.authenticate(compact_credential, now)?;
        if current.subject() != context.principal.subject()
            || current.issuer() != context.principal.issuer()
            || current.credential_id() != context.principal.credential_id()
            || context.request.principal_ref != current.subject()
            || tenant.subject() != current.subject()
            || tenant.tenant_id() != context.request.tenant_ref
            || tenant.resolved_at() > now
            || now.saturating_sub(tenant.resolved_at()) > 600
            || tenant.membership_version() == 0
        {
            return Err(G05Error::AuthorizationDenied);
        }
        self.g02.authorize_g05(&context.request)?;
        self.g09
            .with_current_authority(&current, tenant, &context.request, now, |snapshot| {
                let intent = g09_execution_audit_event(
                    &context.execution_id,
                    "authorized",
                    &current,
                    tenant,
                    &context.request,
                    snapshot,
                    now,
                );
                g11.append_memory_event(&intent)
                    .map_err(|_| G05Error::AuditUnavailable)?;
                let outcome = effect();
                let outcome_name = if outcome.is_ok() {
                    "completed"
                } else {
                    "failed"
                };
                let finished_at = self.clock.now_unix_seconds()?;
                let receipt = g09_execution_audit_event(
                    &context.execution_id,
                    outcome_name,
                    &current,
                    tenant,
                    &context.request,
                    snapshot,
                    finished_at,
                );
                g11.append_memory_event(&receipt)
                    .map_err(|_| G05Error::AuditUnavailable)?;
                outcome
            })
    }

    fn authenticate(
        &self,
        compact_credential: &str,
        now: u64,
    ) -> Result<VerifiedPrincipal, G05Error> {
        self.credentials
            .authenticate(compact_credential, &self.expected_audience, now)
            .map_err(|error| match error {
                CredentialError::RevocationUnavailable => G05Error::AuthorityUnavailable,
                _ => G05Error::AuthorizationDenied,
            })
    }
}

static NEXT_G09_EXECUTION_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn g09_execution_audit_event(
    execution_id: &str,
    outcome: &str,
    principal: &VerifiedPrincipal,
    tenant: &TenantContext,
    request: &AuthorizationRequest,
    snapshot: &G02PolicySnapshot,
    occurred_at: u64,
) -> AuditEvent {
    let resource = request.memory_id.as_deref().unwrap_or("tenant-scope");
    let binding = format!(
        "execution_id={}\\nsubject={}\\ntenant={}\\ncapability={}\\nresource={}\\nrecipients={}\\nmembership_version={}\\npolicy_version={}\\npolicy_digest={}\\ncorrelation={}",
        execution_id,
        principal.subject(),
        tenant.tenant_id(),
        capability_for(request.operation),
        resource,
        request.recipient_refs.join("\\0"),
        tenant.membership_version(),
        snapshot.policy_version,
        snapshot.payload_sha256,
        request.correlation_ref
    );
    let idempotency_key = crate::sha256_hex(
        format!(
            "IROKA:G09:IDEMPOTENCY:V1:{}:{}:{}",
            tenant.tenant_id(),
            principal.subject(),
            request.correlation_ref
        )
        .as_bytes(),
    );
    let phase = if outcome == "authorized" {
        "intent"
    } else {
        "outcome"
    };
    AuditEvent {
        event_id: format!("g09:execution:{idempotency_key}:{phase}"),
        event_type: format!(
            "g09.execution.{outcome}.{}.{}.{}",
            capability_for(request.operation),
            snapshot.policy_version,
            snapshot.payload_sha256
        ),
        memory_id: resource.to_owned(),
        tenant_ref: tenant.tenant_id().to_owned(),
        actor_ref: principal.subject().to_owned(),
        purpose: request.purpose,
        record_version: tenant.membership_version(),
        outcome: outcome.to_owned(),
        correlation_ref: request.correlation_ref.clone(),
        occurred_at,
        content_sha256: crate::sha256_hex(binding.as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_mapping_assigns_critical_risk_to_irreversible_effects() {
        assert_eq!(
            capability_for(Operation::ActivateDurable),
            "g05.memory.durable.activate"
        );
        assert_eq!(risk_for(Operation::ActivateDurable), RiskLevel::Critical);
        assert_eq!(risk_for(Operation::RequestDeletion), RiskLevel::Critical);
        assert_eq!(risk_for(Operation::Retrieve), RiskLevel::Moderate);
    }
}
