//! Narrow adapter to the adopted production IROKA Kernel authorization API.

use std::sync::Arc;

use crate::{ConversationError, KernelAuthorization, Operation, VerifiedPolicy};
use iroka_kernel::{
    authorize_authenticated_with_owner_approval, AuditSink, AuthorizationRequest, DecisionCode,
    OwnerApprovalVerifier, RiskLevel, VerifiedGenesis, VerifiedPrincipal,
};

pub struct KernelConversationAuthorizer<S: AuditSink + Send + Sync + 'static> {
    policy: Arc<VerifiedPolicy>,
    genesis: Arc<VerifiedGenesis>,
    owner_approvals: Arc<OwnerApprovalVerifier>,
    audit: Arc<S>,
}

impl<S: AuditSink + Send + Sync + 'static> KernelConversationAuthorizer<S> {
    /// All trust dependencies are supplied by the trusted composition root.
    /// The policy can only be obtained from successful signed-policy verification.
    pub fn new(
        policy: Arc<VerifiedPolicy>,
        genesis: Arc<VerifiedGenesis>,
        owner_approvals: Arc<OwnerApprovalVerifier>,
        audit: Arc<S>,
    ) -> Self {
        Self {
            policy,
            genesis,
            owner_approvals,
            audit,
        }
    }
}

impl<S: AuditSink + Send + Sync + 'static> KernelAuthorization for KernelConversationAuthorizer<S> {
    fn authorize(
        &self,
        principal: &VerifiedPrincipal,
        operation: Operation,
        resource: &str,
        correlation_id: &str,
        now: u64,
    ) -> Result<(), ConversationError> {
        let capability = match operation {
            Operation::Create => "conversation.create",
            Operation::List => "conversation.list",
            Operation::Read => "conversation.read",
            Operation::SubmitTurn => "turn.create",
            Operation::CancelTurn => "generation.cancel",
            Operation::Delete => "conversation.delete",
        };
        if resource.trim().is_empty() || correlation_id.trim().is_empty() {
            return Err(ConversationError::AuthorizationDenied);
        }
        let request =
            AuthorizationRequest::new(principal.subject(), capability, resource, RiskLevel::Low);
        let event_id = format!("ciw:{correlation_id}:{capability}:{now}");
        let decision = authorize_authenticated_with_owner_approval(
            &request,
            principal,
            self.genesis,
            None,
            self.owner_approvals,
            self.audit,
            self.policy.policy(),
            now,
            false,
            &event_id,
            correlation_id,
        );
        if decision.code() == DecisionCode::Allow {
            Ok(())
        } else {
            Err(ConversationError::AuthorizationDenied)
        }
    }
}
