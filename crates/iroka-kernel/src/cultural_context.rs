//! Provenance-aware cultural context metadata.
//!
//! This adapter describes metadata around an existing evidence reference. It
//! does not ingest cultural content, define authoritative orthography, convert
//! calendars, establish community consent, or authenticate reviewers. Canonical
//! knowledge, identity, governance and consent providers remain authoritative.

use crate::{EvidenceKind, EvidenceReference};

/// Script metadata. Unspecified is intentional where orthography is unresolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptSystem {
    Latin,
    Ethiopic,
    Other,
    Unspecified,
}

/// Calendar metadata only; this module does not convert dates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CalendarSystem {
    Gregorian,
    Ethiopian,
    Other,
    Unspecified,
}

/// Whether a source has undergone the documented community-review process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommunityReviewStatus {
    NotReviewed,
    Pending,
    Reviewed,
}

/// Context metadata attached to an existing cultural-tradition evidence source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CulturalContextRecord {
    id: String,
    source: EvidenceReference,
    language_tag: String,
    region_scope: String,
    community_scope: String,
    attribution: String,
    script: ScriptSystem,
    calendar: CalendarSystem,
    review_status: CommunityReviewStatus,
    review_evidence: Option<EvidenceReference>,
}

impl CulturalContextRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        source: EvidenceReference,
        language_tag: impl Into<String>,
        region_scope: impl Into<String>,
        community_scope: impl Into<String>,
        attribution: impl Into<String>,
        script: ScriptSystem,
        calendar: CalendarSystem,
        review_status: CommunityReviewStatus,
        review_evidence: Option<EvidenceReference>,
    ) -> Result<Self, CulturalContextError> {
        let record = Self {
            id: id.into(),
            source,
            language_tag: language_tag.into(),
            region_scope: region_scope.into(),
            community_scope: community_scope.into(),
            attribution: attribution.into(),
            script,
            calendar,
            review_status,
            review_evidence,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), CulturalContextError> {
        if self.id.trim().is_empty() {
            return Err(CulturalContextError::EmptyRecordId);
        }
        self.source
            .validate()
            .map_err(CulturalContextError::InvalidSource)?;
        if self.source.kind() != EvidenceKind::CulturalTradition {
            return Err(CulturalContextError::SourceIsNotCulturalTradition);
        }
        if !is_valid_language_tag(&self.language_tag) {
            return Err(CulturalContextError::InvalidLanguageTag);
        }
        if self.region_scope.trim().is_empty() {
            return Err(CulturalContextError::EmptyRegionScope);
        }
        if self.community_scope.trim().is_empty() {
            return Err(CulturalContextError::EmptyCommunityScope);
        }
        if self.attribution.trim().is_empty() {
            return Err(CulturalContextError::EmptyAttribution);
        }

        match (self.review_status, &self.review_evidence) {
            (CommunityReviewStatus::Reviewed, None) => {
                return Err(CulturalContextError::ReviewEvidenceRequired);
            }
            (CommunityReviewStatus::NotReviewed | CommunityReviewStatus::Pending, Some(_)) => {
                return Err(CulturalContextError::UnexpectedReviewEvidence);
            }
            (_, Some(reference)) => {
                reference
                    .validate()
                    .map_err(CulturalContextError::InvalidSource)?;
                if reference.kind() == EvidenceKind::GeneratedSynthesis {
                    return Err(CulturalContextError::GeneratedSynthesisCannotProveReview);
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn source(&self) -> &EvidenceReference {
        &self.source
    }

    pub fn language_tag(&self) -> &str {
        &self.language_tag
    }

    pub fn region_scope(&self) -> &str {
        &self.region_scope
    }

    pub fn community_scope(&self) -> &str {
        &self.community_scope
    }

    pub fn attribution(&self) -> &str {
        &self.attribution
    }

    pub fn script(&self) -> ScriptSystem {
        self.script
    }

    pub fn calendar(&self) -> CalendarSystem {
        self.calendar
    }

    pub fn review_status(&self) -> CommunityReviewStatus {
        self.review_status
    }

    pub fn review_evidence(&self) -> Option<&EvidenceReference> {
        self.review_evidence.as_ref()
    }
}

/// Validation failures for cultural-context metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CulturalContextError {
    EmptyRecordId,
    InvalidSource(crate::EvidenceValidationError),
    SourceIsNotCulturalTradition,
    InvalidLanguageTag,
    EmptyRegionScope,
    EmptyCommunityScope,
    EmptyAttribution,
    ReviewEvidenceRequired,
    UnexpectedReviewEvidence,
    GeneratedSynthesisCannotProveReview,
}

fn is_valid_language_tag(tag: &str) -> bool {
    let mut subtags = tag.split('-');
    let Some(language) = subtags.next() else {
        return false;
    };
    if !(2..=8).contains(&language.len())
        || !language.bytes().all(|byte| byte.is_ascii_alphabetic())
    {
        return false;
    }
    subtags.all(|subtag| {
        (1..=8).contains(&subtag.len()) && subtag.bytes().all(|byte| byte.is_ascii_alphanumeric())
    })
}
