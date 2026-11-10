//! Ethical-programme evidence and observable-character primitives.
//!
//! These types are deliberately non-authoritative: they do not grant access,
//! approve actions, persist data, interpret scripture, or certify virtue.
//! Canonical identity, governance, memory, execution and audit remain owned by
//! their existing IROKA chromosomes.

use std::collections::BTreeSet;

/// The epistemic/source class of a reference; classes must not be conflated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceKind {
    BiblicalPrimaryText,
    TheologicalInterpretation,
    CulturalTradition,
    EmpiricalEvidence,
    LegalOrPolicy,
    GeneratedSynthesis,
}

/// The recorded state of source-use permission; this is metadata, not a licence grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LicenceStatus {
    Verified,
    Unverified,
    Restricted,
    NotApplicable,
}

/// A provenance-bearing reference. Content itself is intentionally not stored here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceReference {
    id: String,
    kind: EvidenceKind,
    title: String,
    language_tag: Option<String>,
    source_version: Option<String>,
    provenance: String,
    licence_status: LicenceStatus,
}

impl EvidenceReference {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        kind: EvidenceKind,
        title: impl Into<String>,
        language_tag: Option<String>,
        source_version: Option<String>,
        provenance: impl Into<String>,
        licence_status: LicenceStatus,
    ) -> Result<Self, EvidenceValidationError> {
        let reference = Self {
            id: id.into(),
            kind,
            title: title.into(),
            language_tag,
            source_version,
            provenance: provenance.into(),
            licence_status,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn validate(&self) -> Result<(), EvidenceValidationError> {
        if self.id.trim().is_empty() {
            return Err(EvidenceValidationError::EmptyId);
        }
        if self.title.trim().is_empty() {
            return Err(EvidenceValidationError::EmptyTitle);
        }
        if self.provenance.trim().is_empty() {
            return Err(EvidenceValidationError::EmptyProvenance);
        }
        if self.language_tag.as_ref().is_some_and(|value| value.trim().is_empty()) {
            return Err(EvidenceValidationError::EmptyLanguageTag);
        }
        if self
            .source_version
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(EvidenceValidationError::EmptySourceVersion);
        }
        Ok(())
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn kind(&self) -> EvidenceKind {
        self.kind
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn language_tag(&self) -> Option<&str> {
        self.language_tag.as_deref()
    }

    pub fn source_version(&self) -> Option<&str> {
        self.source_version.as_deref()
    }

    pub fn provenance(&self) -> &str {
        &self.provenance
    }

    pub fn licence_status(&self) -> LicenceStatus {
        self.licence_status
    }
}

/// Validation failures for provenance-bearing evidence references.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceValidationError {
    EmptyId,
    EmptyTitle,
    EmptyProvenance,
    EmptyLanguageTag,
    EmptySourceVersion,
}

/// The ethical principle being examined; this is not a policy grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EthicalPrinciple {
    Truthfulness,
    Wisdom,
    Compassion,
    Justice,
    HumanDignity,
    Integrity,
    Humility,
    Stewardship,
    Patience,
    Courage,
    Service,
    Responsibility,
    Accountability,
}

/// Observable behavioral trait under review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BehavioralTrait {
    Truthfulness,
    Integrity,
    Humility,
    Compassion,
    Justice,
    Responsibility,
    Patience,
    Stewardship,
    Courage,
    Accountability,
}

/// Evidence outcome. No numeric score is provided or implied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BehavioralOutcome {
    Observed,
    NotObserved,
    InsufficientEvidence,
}

/// One evidence-linked observation about a behavioral trait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraitAssessment {
    trait_name: BehavioralTrait,
    outcome: BehavioralOutcome,
    evidence_ids: Vec<String>,
    rationale: String,
}

impl TraitAssessment {
    pub fn new(
        trait_name: BehavioralTrait,
        outcome: BehavioralOutcome,
        evidence_ids: Vec<String>,
        rationale: impl Into<String>,
    ) -> Result<Self, BehavioralReviewError> {
        let assessment = Self {
            trait_name,
            outcome,
            evidence_ids,
            rationale: rationale.into(),
        };
        assessment.validate()?;
        Ok(assessment)
    }

    fn validate(&self) -> Result<(), BehavioralReviewError> {
        if self.rationale.trim().is_empty() {
            return Err(BehavioralReviewError::EmptyRationale);
        }
        if self
            .evidence_ids
            .iter()
            .any(|reference| reference.trim().is_empty())
        {
            return Err(BehavioralReviewError::EmptyEvidenceId);
        }
        if self.outcome != BehavioralOutcome::InsufficientEvidence
            && self.evidence_ids.is_empty()
        {
            return Err(BehavioralReviewError::EvidenceRequired);
        }
        Ok(())
    }

    pub fn trait_name(&self) -> BehavioralTrait {
        self.trait_name
    }

    pub fn outcome(&self) -> BehavioralOutcome {
        self.outcome
    }

    pub fn evidence_ids(&self) -> &[String] {
        &self.evidence_ids
    }

    pub fn rationale(&self) -> &str {
        &self.rationale
    }
}

/// A bounded review whose evidence references must resolve within the review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BehavioralReview {
    review_id: String,
    assessments: Vec<TraitAssessment>,
    evidence: Vec<EvidenceReference>,
}

impl BehavioralReview {
    pub fn new(
        review_id: impl Into<String>,
        assessments: Vec<TraitAssessment>,
        evidence: Vec<EvidenceReference>,
    ) -> Result<Self, BehavioralReviewError> {
        let review = Self {
            review_id: review_id.into(),
            assessments,
            evidence,
        };
        review.validate()?;
        Ok(review)
    }

    pub fn validate(&self) -> Result<(), BehavioralReviewError> {
        if self.review_id.trim().is_empty() {
            return Err(BehavioralReviewError::EmptyReviewId);
        }
        if self.assessments.is_empty() {
            return Err(BehavioralReviewError::NoAssessments);
        }

        let mut evidence_ids = BTreeSet::new();
        for reference in &self.evidence {
            reference
                .validate()
                .map_err(BehavioralReviewError::InvalidEvidence)?;
            if !evidence_ids.insert(reference.id().to_owned()) {
                return Err(BehavioralReviewError::DuplicateEvidenceId);
            }
        }

        for assessment in &self.assessments {
            assessment.validate()?;
            if assessment
                .evidence_ids()
                .iter()
                .any(|id| !evidence_ids.contains(id))
            {
                return Err(BehavioralReviewError::UnresolvedEvidenceReference);
            }
        }
        Ok(())
    }

    pub fn review_id(&self) -> &str {
        &self.review_id
    }

    pub fn assessments(&self) -> &[TraitAssessment] {
        &self.assessments
    }

    pub fn evidence(&self) -> &[EvidenceReference] {
        &self.evidence
    }
}

/// Validation failures for behavioral reviews.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BehavioralReviewError {
    EmptyReviewId,
    NoAssessments,
    EmptyRationale,
    EmptyEvidenceId,
    EvidenceRequired,
    DuplicateEvidenceId,
    UnresolvedEvidenceReference,
    InvalidEvidence(EvidenceValidationError),
}
