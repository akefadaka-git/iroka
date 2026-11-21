//! Production task authorization adapter over canonical G02 and G09 ports.
//! No caller role, membership, capability permission, or policy version is trusted.
use std::collections::HashSet;

use iroka_g05_memory::{
    AuthorizationRequest, Classification, G02AuthorizationAuthority, G09ExecutionRevalidator,
    Operation, Purpose,
};
use iroka_kernel::{RiskLevel, VerifiedPrincipal};

use crate::{
    TaskApiError, TaskAuthorizer, TaskAuthorization, TaskRecord, TaskSubmission,
};

const TASK_READ_CAPABILITY: &str = "iroka.task.read";
const TASK_CANCEL_CAPABILITY: &str = "iroka.task.cancel";
const MAX_CAPABILITY_GRANTS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCapabilityGrant {
    pub capability_id: String,
    pub capability_version: String,
    pub risk: RiskLevel,
}

/// Composes the authoritative G02 tenant-membership check with a G09
/// snapshot-bound capability decision. Grants are deployment-owned configuration,
/// not values supplied by Android clients.
pub struct G02G09TaskAuthorizer<G, E> {
    g02: G,
    g09: E,
    grants: Vec<TaskCapabilityGrant>,
}

impl<G, E> G02G09TaskAuthorizer<G, E> {
    pub fn new(
        g02: G,
        g09: E,
        grants: Vec<TaskCapabilityGrant>,
    ) -> Result<Self, TaskApiError> {
        if grants.is_empty() || grants.len() > MAX_CAPABILITY_GRANTS {
            return Err(TaskApiError::InvalidRequest);
        }
        let mut seen = HashSet::new();
        for grant in &grants {
            if grant.capability_id.trim().is_empty()
                || grant.capability_id.len() > 256
                || !grant.capability_id.starts_with("iroka.")
                || grant.capability_id.chars().any(char::is_control)
                || grant.capability_version.trim().is_empty()
                || grant.capability_version.len() > 128
                || grant.capability_version.chars().any(char::is_control)
                || !seen.insert((grant.capability_id.clone(), grant.capability_version.clone()))
            {
                return Err(TaskApiError::InvalidRequest);
            }
        }
        Ok(Self { g02, g09, grants })
    }
}

struct TaskCapabilityRequest<'a> {
    tenant_ref: &'a str,
    task_ref: Option<&'a str>,
    correlation_ref: &'a str,
    capability_id: &'a str,
    risk: RiskLevel,
    now: u64,
}

impl<G, E> G02G09TaskAuthorizer<G, E>
where
    G: G02AuthorizationAuthority,
    E: G09ExecutionRevalidator,
{
    fn authorize_capability(
        &self,
        principal: &VerifiedPrincipal,
        input: TaskCapabilityRequest<'_>,
    ) -> Result<String, TaskApiError> {
        let request = AuthorizationRequest {
            operation: Operation::InspectMetadata,
            principal_ref: principal.subject().to_owned(),
            tenant_ref: input.tenant_ref.to_owned(),
            subject_ref: principal.subject().to_owned(),
            purpose: Purpose::TaskContinuity,
            classification: Classification::Internal,
            memory_id: input.task_ref.map(str::to_owned),
            recipient_refs: Vec::new(),
            correlation_ref: input.correlation_ref.to_owned(),
        };
        // G02 resolves the selector against its exact Owner-authorized
        // membership key. No client-provided alias or tenant string is stored
        // unless it is the canonical reference returned by this authority.
        let canonical_tenant_ref = self.g02
            .resolve_task_tenant(principal, input.tenant_ref)
            .map_err(map_authority_error)?;
        if canonical_tenant_ref != input.tenant_ref {
            return Err(TaskApiError::Forbidden);
        }
        self.g09
            .authorize_task_capability(principal, &request, input.capability_id, input.risk, input.now)
            .map_err(map_authority_error)
    }

    fn require_task_owner(
        &self,
        principal: &VerifiedPrincipal,
        task: &TaskRecord,
    ) -> Result<(), TaskApiError> {
        if task.principal_ref != principal.subject() {
            return Err(TaskApiError::Forbidden);
        }
        Ok(())
    }
}

impl<G, E> TaskAuthorizer for G02G09TaskAuthorizer<G, E>
where
    G: G02AuthorizationAuthority,
    E: G09ExecutionRevalidator,
{
    fn authorize_submit(
        &self,
        principal: &VerifiedPrincipal,
        request: &TaskSubmission,
        now: u64,
    ) -> Result<TaskAuthorization, TaskApiError> {
        let grant = self.grants.iter().find(|grant| {
            grant.capability_id == request.capability_id
                && grant.capability_version == request.capability_version
        }).ok_or(TaskApiError::Forbidden)?;
        let policy_version = self.authorize_capability(
            principal,
            TaskCapabilityRequest {
                tenant_ref: &request.tenant_selector,
                task_ref: None,
                correlation_ref: &request.correlation_id,
                capability_id: &grant.capability_id,
                risk: grant.risk,
                now,
            },
        )?;
        Ok(TaskAuthorization {
            tenant_ref: request.tenant_selector.clone(),
            policy_version,
        })
    }

    fn authorize_read(
        &self,
        principal: &VerifiedPrincipal,
        task: &TaskRecord,
        now: u64,
    ) -> Result<(), TaskApiError> {
        self.require_task_owner(principal, task)?;
        self.authorize_capability(
            principal,
            TaskCapabilityRequest {
                tenant_ref: &task.tenant_ref,
                task_ref: Some(&task.task_id),
                correlation_ref: &task.correlation_id,
                capability_id: TASK_READ_CAPABILITY,
                risk: RiskLevel::Moderate,
                now,
            },
        )?;
        Ok(())
    }

    fn authorize_cancel(
        &self,
        principal: &VerifiedPrincipal,
        task: &TaskRecord,
        now: u64,
    ) -> Result<(), TaskApiError> {
        self.require_task_owner(principal, task)?;
        self.authorize_capability(
            principal,
            TaskCapabilityRequest {
                tenant_ref: &task.tenant_ref,
                task_ref: Some(&task.task_id),
                correlation_ref: &task.correlation_id,
                capability_id: TASK_CANCEL_CAPABILITY,
                risk: RiskLevel::High,
                now,
            },
        )?;
        Ok(())
    }
}

fn map_authority_error(error: iroka_g05_memory::G05Error) -> TaskApiError {
    match error {
        iroka_g05_memory::G05Error::AuthorityUnavailable
        | iroka_g05_memory::G05Error::RepositoryUnavailable => TaskApiError::AuthorityUnavailable,
        iroka_g05_memory::G05Error::AuthenticationRequired
        | iroka_g05_memory::G05Error::AuthenticationInvalid => TaskApiError::Unauthorized,
        _ => TaskApiError::Forbidden,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Unused;
    impl G02AuthorizationAuthority for Unused {
        fn authorize_g05(&self, _: &AuthorizationRequest) -> Result<(), iroka_g05_memory::G05Error> {
            Err(iroka_g05_memory::G05Error::AuthorityUnavailable)
        }
        fn resolve_g05_activation(
            &self,
            _: &iroka_kernel::VerifiedReviewerProof,
            _: &iroka_g05_memory::DurableApprovalReceipt,
            _: &iroka_g05_memory::MemoryRecord,
            _: &VerifiedPrincipal,
            _: u64,
        ) -> Result<iroka_kernel::G05ActivationDecision, iroka_g05_memory::G05Error> {
            Err(iroka_g05_memory::G05Error::ReviewerNotAuthorized)
        }
    }

    #[test]
    fn deployment_grants_reject_duplicates_and_untrusted_names() {
        let grant = TaskCapabilityGrant {
            capability_id: "iroka.answer".into(),
            capability_version: "1.0.0".into(),
            risk: RiskLevel::Moderate,
        };
        assert!(G02G09TaskAuthorizer::new(Unused, Unused, vec![grant.clone()]).is_ok());
        assert!(G02G09TaskAuthorizer::new(Unused, Unused, vec![grant.clone(), grant]).is_err());
        assert!(G02G09TaskAuthorizer::new(Unused, Unused, vec![
            TaskCapabilityGrant {
                capability_id: "caller.supplied.permission".into(),
                capability_version: "1".into(),
                risk: RiskLevel::Low,
            }
        ]).is_err());
        assert!(G02G09TaskAuthorizer::new(Unused, Unused, Vec::new()).is_err());
    }
}
