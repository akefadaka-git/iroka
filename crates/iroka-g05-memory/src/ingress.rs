//! Production-facing G05 ingress boundary.
//! G01 credentials, G02 tenant/organization authority, and G09 execution policy
//! are revalidated at ingress and again immediately before every external effect.
//! No caller-supplied principal, authorization boolean, or timestamp is accepted.
use crate::{AuthorizationRequest, G02AuthorizationAuthority, G05Error, Operation};
use iroka_kernel::{
    evaluate, CredentialError, DecisionCode, Ed25519CredentialVerifier, Policy, RiskLevel,
    RevocationChecker, VerifiedPrincipal,
};

pub trait TrustedClock: Send + Sync {
    fn now_unix_seconds(&self) -> Result<u64, G05Error>;
}

/// G09 policy source must return a fresh authoritative policy snapshot and
/// emergency-stop state on every invocation. A stale/unavailable source denies.
pub trait G09PolicyResolver: Send + Sync {
    fn current_policy(&self, now: u64) -> Result<(Policy, bool), G05Error>;
}

pub trait G09ExecutionRevalidator: Send + Sync {
    fn revalidate(
        &self,
        principal: &VerifiedPrincipal,
        request: &AuthorizationRequest,
        now: u64,
    ) -> Result<(), G05Error>;
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
    fn revalidate(
        &self,
        principal: &VerifiedPrincipal,
        request: &AuthorizationRequest,
        now: u64,
    ) -> Result<(), G05Error> {
        if request.principal_ref != principal.subject() {
            return Err(G05Error::AuthorizationDenied);
        }
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

fn capability_for(operation: Operation) -> &'static str {
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

fn risk_for(operation: Operation) -> RiskLevel {
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
        Ok(AuthenticatedG05Request {
            principal,
            request,
            authenticated_at: now,
        })
    }

    /// Execute an external effect only after fresh G01 revocation, G02 authority,
    /// and G09 policy checks. The caller cannot provide or override the clock.
    pub fn execute_external<T>(
        &self,
        context: &AuthenticatedG05Request,
        compact_credential: &str,
        effect: impl FnOnce() -> Result<T, G05Error>,
    ) -> Result<T, G05Error> {
        let now = self.clock.now_unix_seconds()?;
        let current = self.authenticate(compact_credential, now)?;
        if current.subject() != context.principal.subject()
            || current.issuer() != context.principal.issuer()
            || current.credential_id() != context.principal.credential_id()
            || context.request.principal_ref != current.subject()
        {
            return Err(G05Error::AuthorizationDenied);
        }
        self.g02.authorize_g05(&context.request)?;
        self.g09.revalidate(&current, &context.request, now)?;
        effect()
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

#[cfg(test)]
mod tests {
    use super::*;

    struct TestClock;
    impl TrustedClock for TestClock {
        fn now_unix_seconds(&self) -> Result<u64, G05Error> {
            Ok(100)
        }
    }

    struct TestPolicy {
        emergency_stop: bool,
    }
    impl G09PolicyResolver for TestPolicy {
        fn current_policy(&self, _now: u64) -> Result<(Policy, bool), G05Error> {
            Ok((
                Policy::new(
                    "g09-test-v1",
                    vec!["g05.memory.retrieve".into()],
                    vec![],
                    RiskLevel::Critical,
                ),
                self.emergency_stop,
            ))
        }
    }

    #[test]
    fn g09_revalidation_fails_closed_when_emergency_stop_is_active() {
        let gate = KernelG09ExecutionRevalidator::new(TestPolicy {
            emergency_stop: true,
        });
        let principal = VerifiedPrincipal::from_verified_credential(
            "subject:ingress".into(),
            "issuer:ingress".into(),
            "credential:ingress".into(),
        );
        let request = AuthorizationRequest {
            operation: Operation::Retrieve,
            principal_ref: "subject:ingress".into(),
            tenant_ref: "tenant:ingress".into(),
            subject_ref: "subject:memory".into(),
            purpose: crate::Purpose::TaskContinuity,
            classification: crate::Classification::Internal,
            memory_id: Some("memory:ingress".into()),
            recipient_refs: vec![],
            correlation_ref: "trace:ingress".into(),
        };
        assert_eq!(
            gate.revalidate(&principal, &request, 100),
            Err(G05Error::AuthorizationDenied)
        );
    }

    #[test]
    fn g09_revalidation_requires_authenticated_principal_binding() {
        let gate = KernelG09ExecutionRevalidator::new(TestPolicy {
            emergency_stop: false,
        });
        let principal = VerifiedPrincipal::from_verified_credential(
            "subject:actual".into(),
            "issuer:ingress".into(),
            "credential:ingress".into(),
        );
        let request = AuthorizationRequest {
            operation: Operation::Retrieve,
            principal_ref: "subject:forged".into(),
            tenant_ref: "tenant:ingress".into(),
            subject_ref: "subject:memory".into(),
            purpose: crate::Purpose::TaskContinuity,
            classification: crate::Classification::Internal,
            memory_id: Some("memory:ingress".into()),
            recipient_refs: vec![],
            correlation_ref: "trace:ingress".into(),
        };
        assert_eq!(
            gate.revalidate(&principal, &request, 100),
            Err(G05Error::AuthorizationDenied)
        );
    }

    #[test]
    fn trusted_clock_contract_does_not_accept_request_timestamps() {
        assert_eq!(TestClock.now_unix_seconds().unwrap(), 100);
    }
}
