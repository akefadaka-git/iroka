//! Bounded teaching, mentoring and advisory task profiles.
//!
//! These profiles classify a task and its review requirements. They do not
//! provide an autonomous agent, professional licence, authority, execution
//! permission or substitute for qualified human judgment.

use std::collections::BTreeSet;

use crate::EvidenceReference;

/// The bounded interaction mode requested for a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TeachingMode {
    Teacher,
    Mentor,
    Advisor,
    Researcher,
    Coach,
    Creator,
}

/// Qualitative impact category used to select safeguards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImpactLevel {
    Low,
    Moderate,
    High,
    Critical,
}

/// Required level of human review for the task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HumanReviewRequirement {
    NotRequired,
    Recommended,
    Required,
}

/// A non-executable profile for a bounded teaching or advisory task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeachingTaskProfile {
    id: String,
    mode: TeachingMode,
    task_description: String,
    impact: ImpactLevel,
    human_review: HumanReviewRequirement,
    evidence: Vec<EvidenceReference>,
}

impl TeachingTaskProfile {
    pub fn new(
        id: impl Into<String>,
        mode: TeachingMode,
        task_description: impl Into<String>,
        impact: ImpactLevel,
        human_review: HumanReviewRequirement,
        evidence: Vec<EvidenceReference>,
    ) -> Result<Self, TeachingProfileError> {
        let profile = Self {
            id: id.into(),
            mode,
            task_description: task_description.into(),
            impact,
            human_review,
            evidence,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<(), TeachingProfileError> {
        if self.id.trim().is_empty() {
            return Err(TeachingProfileError::EmptyProfileId);
        }
        if self.task_description.trim().is_empty() {
            return Err(TeachingProfileError::EmptyTaskDescription);
        }
        match (self.impact, self.human_review) {
            (ImpactLevel::High | ImpactLevel::Critical, HumanReviewRequirement::Required) => {}
            (ImpactLevel::High | ImpactLevel::Critical, _) => {
                return Err(TeachingProfileError::HighImpactRequiresHumanReview);
            }
            (ImpactLevel::Moderate, HumanReviewRequirement::NotRequired) => {
                return Err(TeachingProfileError::ModerateImpactRequiresSafeguard);
            }
            _ => {}
        }

        let mut evidence_ids = BTreeSet::new();
        for reference in &self.evidence {
            reference
                .validate()
                .map_err(TeachingProfileError::InvalidEvidence)?;
            if !evidence_ids.insert(reference.id().to_owned()) {
                return Err(TeachingProfileError::DuplicateEvidenceId);
            }
        }
        if matches!(self.impact, ImpactLevel::High | ImpactLevel::Critical)
            && self.evidence.is_empty()
        {
            return Err(TeachingProfileError::HighImpactEvidenceRequired);
        }
        Ok(())
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn mode(&self) -> TeachingMode {
        self.mode
    }

    pub fn task_description(&self) -> &str {
        &self.task_description
    }

    pub fn impact(&self) -> ImpactLevel {
        self.impact
    }

    pub fn human_review(&self) -> HumanReviewRequirement {
        self.human_review
    }

    pub fn evidence(&self) -> &[EvidenceReference] {
        &self.evidence
    }
}

/// Validation failures for teaching and advisory task profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeachingProfileError {
    EmptyProfileId,
    EmptyTaskDescription,
    HighImpactRequiresHumanReview,
    ModerateImpactRequiresSafeguard,
    HighImpactEvidenceRequired,
    DuplicateEvidenceId,
    InvalidEvidence(crate::EvidenceValidationError),
}
