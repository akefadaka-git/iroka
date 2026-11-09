#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Moderate,
    High,
    Critical,
}

/// In-memory policy input. Signing, approval and persistence are not implemented yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    version: String,
    allowed_capabilities: Vec<String>,
    approval_required: Vec<String>,
    maximum_risk: RiskLevel,
}

impl Policy {
    pub fn new(
        version: impl Into<String>,
        allowed_capabilities: Vec<String>,
        approval_required: Vec<String>,
        maximum_risk: RiskLevel,
    ) -> Self {
        Self {
            version: version.into(),
            allowed_capabilities,
            approval_required,
            maximum_risk,
        }
    }

    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn maximum_risk(&self) -> RiskLevel {
        self.maximum_risk
    }

    pub(crate) fn allows_capability(&self, capability: &str) -> bool {
        self.allowed_capabilities
            .iter()
            .any(|item| item == capability)
    }

    pub(crate) fn requires_approval(&self, capability: &str) -> bool {
        self.approval_required.iter().any(|item| item == capability)
    }
}
