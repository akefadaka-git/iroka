use iroka_kernel::{
    ethiopian_to_gregorian, gregorian_to_ethiopian, transform_script, CalendarError,
    CalendarSystem, CommunityReviewStatus, CulturalContextError, CulturalContextRecord,
    EthiopianDate, EvidenceKind, EvidenceReference, GregorianDate, LicenceStatus,
    LocalizationEntry, LocalizationError, ScriptSystem, ScriptTransformStatus,
    TranslationState,
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
    assert_eq!(result, Err(CulturalContextError::SourceIsNotCulturalTradition));
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

#[test]
fn script_adapter_passes_through_only_identical_declared_scripts() {
    let result = transform_script("sample text", ScriptSystem::Latin, ScriptSystem::Latin);
    assert_eq!(result.status(), ScriptTransformStatus::ExactPassThrough);
    assert_eq!(result.output_text(), Some("sample text"));
}

#[test]
fn script_adapter_preserves_original_and_fails_closed_for_cross_script_conversion() {
    let result = transform_script("source form", ScriptSystem::Unspecified, ScriptSystem::Ethiopic);
    assert_eq!(result.status(), ScriptTransformStatus::Unsupported);
    assert_eq!(result.original_text(), "source form");
    assert_eq!(result.output_text(), None);
}

#[test]
fn localization_entry_retains_original_and_unverified_translation_separately() {
    let entry = LocalizationEntry::new(
        "loc:1",
        source("source:1", EvidenceKind::CulturalTradition),
        "mdy",
        "am",
        "original source text",
        Some("draft target text".into()),
        TranslationState::Unverified,
        None,
    )
    .unwrap();
    assert_eq!(entry.source_text(), "original source text");
    assert_eq!(entry.translated_text(), Some("draft target text"));
    assert_eq!(entry.state(), TranslationState::Unverified);
}

#[test]
fn untranslated_entry_cannot_smuggle_in_target_text() {
    assert_eq!(
        LocalizationEntry::new(
            "loc:1",
            source("source:1", EvidenceKind::CulturalTradition),
            "mdy",
            "am",
            "original",
            Some("unreviewed target".into()),
            TranslationState::NotTranslated,
            None,
        ),
        Err(LocalizationError::UnexpectedTranslation)
    );
}

#[test]
fn review_evidence_is_required_but_does_not_authenticate_a_reviewer() {
    assert_eq!(
        LocalizationEntry::new(
            "loc:1",
            source("source:1", EvidenceKind::CulturalTradition),
            "mdy",
            "am",
            "original",
            Some("candidate translation".into()),
            TranslationState::ReviewEvidenceRecorded,
            None,
        ),
        Err(LocalizationError::ReviewEvidenceRequired)
    );
}

#[test]
fn generated_synthesis_cannot_be_recorded_as_review_evidence() {
    assert_eq!(
        LocalizationEntry::new(
            "loc:1",
            source("source:1", EvidenceKind::CulturalTradition),
            "mdy",
            "am",
            "original",
            Some("candidate translation".into()),
            TranslationState::ReviewEvidenceRecorded,
            Some(source("review:1", EvidenceKind::GeneratedSynthesis)),
        ),
        Err(LocalizationError::GeneratedSynthesisCannotEvidenceReview)
    );
}

#[test]
fn ethiopian_calendar_known_new_year_conversion_is_correct() {
    let ethiopian = EthiopianDate::new(2016, 1, 1).unwrap();
    let gregorian = ethiopian_to_gregorian(ethiopian).unwrap();
    assert_eq!(gregorian, GregorianDate::new(2023, 9, 12).unwrap());
    assert_eq!(gregorian_to_ethiopian(gregorian).unwrap(), ethiopian);
}

#[test]
fn ethiopian_leap_day_conversion_is_correct() {
    let ethiopian = EthiopianDate::new(2015, 13, 6).unwrap();
    let gregorian = ethiopian_to_gregorian(ethiopian).unwrap();
    assert_eq!(gregorian, GregorianDate::new(2023, 9, 11).unwrap());
    assert_eq!(gregorian_to_ethiopian(gregorian).unwrap(), ethiopian);
}

#[test]
fn invalid_ethiopian_thirteenth_month_day_is_rejected() {
    assert_eq!(
        EthiopianDate::new(2016, 13, 6),
        Err(CalendarError::InvalidDate)
    );
}

#[test]
fn gregorian_century_leap_year_rules_are_respected() {
    assert_eq!(GregorianDate::new(1900, 2, 29), Err(CalendarError::InvalidDate));
    assert!(GregorianDate::new(2000, 2, 29).is_ok());
}

#[test]
fn calendar_round_trip_holds_across_ethiopian_month_boundaries() {
    for year in 2010..=2030 {
        for month in 1..=13 {
            let max_day = if month == 13 {
                if year % 4 == 3 { 6 } else { 5 }
            } else {
                30
            };
            for day in [1, max_day] {
                let date = EthiopianDate::new(year, month, day).unwrap();
                let converted = ethiopian_to_gregorian(date).unwrap();
                assert_eq!(gregorian_to_ethiopian(converted).unwrap(), date);
            }
        }
    }
}
