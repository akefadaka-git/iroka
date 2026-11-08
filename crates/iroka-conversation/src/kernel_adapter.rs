//! Narrow adapter to the adopted production IROKA Kernel authorization API.

use crate::{ConversationError, KernelAuthorization, Operation, VerifiedPolicy};
use iroka_kernel::{
    authorize_authenticated_with_owner_approval, AuditSink, AuthorizationRequest, DecisionCode,
    OwnerApprovalVerifier, RiskLevel, VerifiedGenesis, VerifiedPrincipal,
};

pub struct KernelConversationAuthorizer<'a, S: AuditSink> {
    policy: &'a VerifiedPolicy,
    genesis: &'a VerifiedGenesis,
    owner_approvals: &'a OwnerApprovalVerifier,
    audit: &'a S,
}

impl<'a, S: AuditSink> KernelConversationAuthorizer<'a, S> {
    /// All trust dependencies are supplied by the trusted composition root.
    /// The policy can only be obtained from successful signed-policy verification.
    pub fn new(
        policy: &'a VerifiedPolicy,
        genesis: &'a VerifiedGenesis,
        owner_approvals: &'a OwnerApprovalVerifier,
        audit: &'a S,
    ) -> Self {
        Self {
            policy,
            genesis,
            owner_approvals,
            audit,
        }
    }
}

impl<S: AuditSink> KernelAuthorization for KernelConversationAuthorizer<'_, S> {
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
            Operation::SubmitTurn => "conversation.turn.submit",
            Operation::CancelTurn => "conversation.turn.cancel",
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
