//! Bounded operational self-model claims.
//!
//! These records describe claims about the system's capabilities, configuration,
//! runtime state and limitations. They are not identity credentials, permissions,
//! execution approvals or proof of subjective consciousness. The caller-supplied
//! status is not authenticated by this module; authoritative verification remains
//! the responsibility of the owning provider and its governance boundary.

use std::collections::BTreeSet;

use crate::{EvidenceKind, EvidenceReference};

/// The subject area of an operational self-report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelfClaimCategory {
    Identity,
    Capability,
    RuntimeState,
    Configuration,
    Limitation,
    ErrorState,
}

/// Epistemic status asserted by the report producer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelfClaimStatus {
    /// The claim is linked to non-generated source evidence. This module does not
    /// authenticate that evidence or establish the authority of its issuer.
    Verified,
    /// The claim is explicitly declared but not independently verified.
    Declared,
    /// The claim is an inference and must retain its supporting evidence links.
    Inferred,
    /// The requested state is unavailable; no evidence is asserted for the value.
    Unavailable,
}

/// One bounded statement about the system's operational state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfModelClaim {
    id: String,
    category: SelfClaimCategory,
    statement: String,
    status: SelfClaimStatus,
    evidence_ids: Vec<String>,
    rationale: String,
}

impl SelfModelClaim {
    pub fn new(
        id: impl Into<String>,
        category: SelfClaimCategory,
        statement: impl Into<String>,
        status: SelfClaimStatus,
        evidence_ids: Vec<String>,
        rationale: impl Into<String>,
    ) -> Result<Self, SelfModelError> {
        let claim = Self {
            id: id.into(),
            category,
            statement: statement.into(),
            status,
            evidence_ids,
            rationale: rationale.into(),
        };
        claim.validate()?;
        Ok(claim)
    }

    fn validate(&self) -> Result<(), SelfModelError> {
        if self.id.trim().is_empty() {
            return Err(SelfModelError::EmptyClaimId);
        }
        if self.statement.trim().is_empty() {
            return Err(SelfModelError::EmptyStatement);
        }
        if self.rationale.trim().is_empty() {
            return Err(SelfModelError::EmptyRationale);
        }
        if self.evidence_ids.iter().any(|id| id.trim().is_empty()) {
            return Err(SelfModelError::EmptyEvidenceId);
        }
        match self.status {
            SelfClaimStatus::Verified | SelfClaimStatus::Inferred
                if self.evidence_ids.is_empty() =>
            {
                Err(SelfModelError::EvidenceRequired)
            }
            SelfClaimStatus::Unavailable if !self.evidence_ids.is_empty() => {
                Err(SelfModelError::UnavailableClaimHasEvidence)
            }
            _ => Ok(()),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn category(&self) -> SelfClaimCategory {
        self.category
    }

    pub fn statement(&self) -> &str {
        &self.statement
    }

    pub fn status(&self) -> SelfClaimStatus {
        self.status
    }

    pub fn evidence_ids(&self) -> &[String] {
        &self.evidence_ids
    }

    pub fn rationale(&self) -> &str {
        &self.rationale
    }
}

/// A non-authoritative snapshot whose evidence references resolve locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationalSelfModel {
    snapshot_id: String,
    claims: Vec<SelfModelClaim>,
    evidence: Vec<EvidenceReference>,
}

impl OperationalSelfModel {
    pub fn new(
        snapshot_id: impl Into<String>,
        claims: Vec<SelfModelClaim>,
        evidence: Vec<EvidenceReference>,
    ) -> Result<Self, SelfModelError> {
        let model = Self {
            snapshot_id: snapshot_id.into(),
            claims,
            evidence,
        };
        model.validate()?;
        Ok(model)
    }

    pub fn validate(&self) -> Result<(), SelfModelError> {
        if self.snapshot_id.trim().is_empty() {
            return Err(SelfModelError::EmptySnapshotId);
        }
        if self.claims.is_empty() {
            return Err(SelfModelError::NoClaims);
        }

        let mut claim_ids = BTreeSet::new();
        for claim in &self.claims {
            claim.validate()?;
            if !claim_ids.insert(claim.id()) {
                return Err(SelfModelError::DuplicateClaimId);
            }
        }

        let mut evidence_ids = BTreeSet::new();
        for reference in &self.evidence {
            reference
                .validate()
                .map_err(SelfModelError::InvalidEvidence)?;
            if !evidence_ids.insert(reference.id().to_owned()) {
                return Err(SelfModelError::DuplicateEvidenceId);
            }
        }

        for claim in &self.claims {
            if claim
                .evidence_ids()
                .iter()
                .any(|id| !evidence_ids.contains(id))
            {
                return Err(SelfModelError::UnresolvedEvidenceReference);
            }
            if claim.status() == SelfClaimStatus::Verified
                && claim.evidence_ids().iter().all(|id| {
                    self.evidence
                        .iter()
                        .find(|reference| reference.id() == id)
                        .is_some_and(|reference| reference.kind() == EvidenceKind::GeneratedSynthesis)
                })
            {
                return Err(SelfModelError::GeneratedEvidenceCannotVerifyClaim);
            }
        }
        Ok(())
    }

    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }

    pub fn claims(&self) -> &[SelfModelClaim] {
        &self.claims
    }

    pub fn evidence(&self) -> &[EvidenceReference] {
        &self.evidence
    }
}

/// Validation failures for bounded operational self-model reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfModelError {
    EmptySnapshotId,
    NoClaims,
    EmptyClaimId,
    EmptyStatement,
    EmptyRationale,
    EmptyEvidenceId,
    EvidenceRequired,
    UnavailableClaimHasEvidence,
    DuplicateClaimId,
    DuplicateEvidenceId,
    UnresolvedEvidenceReference,
    GeneratedEvidenceCannotVerifyClaim,
    InvalidEvidence(crate::EvidenceValidationError),
}
