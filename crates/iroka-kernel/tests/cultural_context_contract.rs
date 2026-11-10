use iroka_kernel::{
    CalendarSystem, CommunityReviewStatus, CulturalContextError, CulturalContextRecord,
    EvidenceKind, EvidenceReference, LicenceStatus, ScriptSystem,
};

fn source(id: &str, kind: EvidenceKind) -> EvidenceReference {
    EvidenceReference::new(
        id,
        kind,
        "Community source record",
        Some("mdy".into()),
        Some("catalogue-v1".into()),
        "community archive metadata",
        LicenceStatus::Unverified,
    )
    .unwrap()
}

fn record(
    language: &str,
    review: CommunityReviewStatus,
    review_evidence: Option<EvidenceReference>,
) -> Result<CulturalContextRecord, CulturalContextError> {
    CulturalContextRecord::new(
        "culture:1",
        source("source:1", EvidenceKind::CulturalTradition),
        language,
        "South Omo",
        "Maale",
        "Source attribution retained",
        ScriptSystem::Unspecified,
        CalendarSystem::Ethiopian,
        review,
        review_evidence,
    )
}

#[test]
fn maale_metadata_preserves_unresolved_orthography_and_calendar_context() {
    let context = record("mdy", CommunityReviewStatus::NotReviewed, None).unwrap();
    assert_eq!(context.language_tag(), "mdy");
    assert_eq!(context.script(), ScriptSystem::Unspecified);
    assert_eq!(context.calendar(), CalendarSystem::Ethiopian);
    assert_eq!(context.review_status(), CommunityReviewStatus::NotReviewed);
}

#[test]
fn invalid_language_tag_is_rejected() {
    assert_eq!(
        record("mdy--ET", CommunityReviewStatus::NotReviewed, None),
        Err(CulturalContextError::InvalidLanguageTag)
    );
}

#[test]
fn cultural_context_requires_cultural_tradition_source_kind() {
    let result = CulturalContextRecord::new(
        "culture:1",
        source("source:1", EvidenceKind::EmpiricalEvidence),
        "mdy",
        "South Omo",
        "Maale",
        "Source attribution retained",
        ScriptSystem::Unspecified,
        CalendarSystem::Ethiopian,
        CommunityReviewStatus::NotReviewed,
        None,
    );
    assert_eq!(
        result,
        Err(CulturalContextError::SourceIsNotCulturalTradition)
    );
}

#[test]
fn reviewed_status_requires_review_evidence_reference() {
    assert_eq!(
        record("mdy", CommunityReviewStatus::Reviewed, None),
        Err(CulturalContextError::ReviewEvidenceRequired)
    );
}

#[test]
fn pending_status_cannot_claim_review_evidence() {
    assert_eq!(
        record(
            "mdy",
            CommunityReviewStatus::Pending,
            Some(source("review:1", EvidenceKind::EmpiricalEvidence))
        ),
        Err(CulturalContextError::UnexpectedReviewEvidence)
    );
}

#[test]
fn generated_synthesis_cannot_prove_community_review() {
    assert_eq!(
        record(
            "mdy",
            CommunityReviewStatus::Reviewed,
            Some(source("review:1", EvidenceKind::GeneratedSynthesis))
        ),
        Err(CulturalContextError::GeneratedSynthesisCannotProveReview)
    );
}

#[test]
fn reviewed_context_retains_review_evidence_reference() {
    let context = record(
        "mdy",
        CommunityReviewStatus::Reviewed,
        Some(source("review:1", EvidenceKind::EmpiricalEvidence)),
    )
    .unwrap();
    assert_eq!(context.review_evidence().unwrap().id(), "review:1");
}

#[test]
fn non_canonical_language_tags_can_be_retained_without_normalization() {
    let context = record("mdy-Latn", CommunityReviewStatus::NotReviewed, None).unwrap();
    assert_eq!(context.language_tag(), "mdy-Latn");
}
