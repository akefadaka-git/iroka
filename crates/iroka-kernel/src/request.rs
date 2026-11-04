use crate::RiskLevel;

/// Proposed operation data; subject is descriptive and is not authenticated identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    subject: String,
    capability: String,
    resource: String,
    risk: RiskLevel,
}

impl AuthorizationRequest {
    pub fn new(
        subject: impl Into<String>,
        capability: impl Into<String>,
        resource: impl Into<String>,
        risk: RiskLevel,
    ) -> Self {
        Self { subject: subject.into(), capability: capability.into(), resource: resource.into(), risk }
    }

    pub fn subject(&self) -> &str { &self.subject }
    pub fn capability(&self) -> &str { &self.capability }
    pub fn resource(&self) -> &str { &self.resource }
    pub fn risk(&self) -> RiskLevel { self.risk }

    pub(crate) fn is_well_formed(&self) -> bool {
        !self.subject.trim().is_empty()
            && !self.capability.trim().is_empty()
            && !self.resource.trim().is_empty()
    }
}
