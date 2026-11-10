use iroka_kernel::{
    BehavioralOutcome, BehavioralReview, BehavioralReviewError, BehavioralTrait, EvidenceKind,
    EvidenceReference, EvidenceValidationError, LicenceStatus, TraitAssessment,
};

fn reference(id: &str, kind: EvidenceKind) -> EvidenceReference {
    EvidenceReference::new(
        id,
        kind,
        "Reviewed source",
        Some("en".into()),
        Some("v1".into()),
        "source catalogue record",
        LicenceStatus::Verified,
    )
    .unwrap()
}

#[test]
fn evidence_kinds_keep_scripture_interpretation_and_synthesis_distinct() {
    assert_ne!(EvidenceKind::BiblicalPrimaryText, EvidenceKind::TheologicalInterpretation);
    assert_ne!(EvidenceKind::TheologicalInterpretation, EvidenceKind::GeneratedSynthesis);
    assert_ne!(EvidenceKind::CulturalTradition, EvidenceKind::EmpiricalEvidence);
    assert_ne!(EvidenceKind::LegalOrPolicy, EvidenceKind::GeneratedSynthesis);
}

#[test]
fn evidence_reference_rejects_empty_provenance() {
    let result = EvidenceReference::new(
        "src:1",
        EvidenceKind::EmpiricalEvidence,
        "Study",
        None,
        None,
        "  ",
        LicenceStatus::Unverified,
    );
    assert_eq!(result, Err(EvidenceValidationError::EmptyProvenance));
}

#[test]
fn evidence_reference_rejects_empty_language_and_version_metadata() {
    let language = EvidenceReference::new(
        "src:1", EvidenceKind::CulturalTradition, "Oral history",
        Some(" ".into()), None, "catalogue:1", LicenceStatus::Unverified,
    );
    assert_eq!(language, Err(EvidenceValidationError::EmptyLanguageTag));

    let version = EvidenceReference::new(
        "src:1", EvidenceKind::CulturalTradition, "Oral history",
        None, Some(" ".into()), "catalogue:1", LicenceStatus::Unverified,
    );
    assert_eq!(version, Err(EvidenceValidationError::EmptySourceVersion));
}

#[test]
fn observed_trait_requires_evidence() {
    let result = TraitAssessment::new(
        BehavioralTrait::Truthfulness,
        BehavioralOutcome::Observed,
        vec![],
        "The behavior was truthful",
    );
    assert_eq!(result, Err(BehavioralReviewError::EvidenceRequired));
}

#[test]
fn insufficient_evidence_can_be_recorded_without_inventing_support() {
    let assessment = TraitAssessment::new(
        BehavioralTrait::Humility,
        BehavioralOutcome::InsufficientEvidence,
        vec![],
        "No reliable observation is available",
    )
    .unwrap();
    assert_eq!(assessment.outcome(), BehavioralOutcome::InsufficientEvidence);
    assert!(assessment.evidence_ids().is_empty());
}

#[test]
fn review_rejects_unresolved_evidence_ids() {
    let assessment = TraitAssessment::new(
        BehavioralTrait::Integrity,
        BehavioralOutcome::Observed,
        vec!["missing:source".into()],
        "Consistent behavior observed",
    )
    .unwrap();
    let result = BehavioralReview::new("review:1", vec![assessment], vec![]);
    assert_eq!(result, Err(BehavioralReviewError::UnresolvedEvidenceReference));
}

#[test]
fn review_rejects_duplicate_evidence_ids() {
    let assessment = TraitAssessment::new(
        BehavioralTrait::Justice,
        BehavioralOutcome::Observed,
        vec!["source:1".into()],
        "Consistent criteria applied",
    )
    .unwrap();
    let result = BehavioralReview::new(
        "review:1",
        vec![assessment],
        vec![
            reference("source:1", EvidenceKind::EmpiricalEvidence),
            reference("source:1", EvidenceKind::CulturalTradition),
        ],
    );
    assert_eq!(result, Err(BehavioralReviewError::DuplicateEvidenceId));
}

#[test]
fn valid_review_preserves_source_class_and_evidence_linkage() {
    let assessment = TraitAssessment::new(
        BehavioralTrait::Compassion,
        BehavioralOutcome::Observed,
        vec!["source:1".into()],
        "The response considered foreseeable harm",
    )
    .unwrap();
    let review = BehavioralReview::new(
        "review:1",
        vec![assessment],
        vec![reference("source:1", EvidenceKind::EmpiricalEvidence)],
    )
    .unwrap();

    assert_eq!(review.review_id(), "review:1");
    assert_eq!(review.assessments()[0].outcome(), BehavioralOutcome::Observed);
    assert_eq!(review.evidence()[0].kind(), EvidenceKind::EmpiricalEvidence);
}

#[test]
fn review_rejects_empty_rationale() {
    let result = TraitAssessment::new(
        BehavioralTrait::Accountability,
        BehavioralOutcome::NotObserved,
        vec!["source:1".into()],
        " ",
    );
    assert_eq!(result, Err(BehavioralReviewError::EmptyRationale));
}

#[test]
fn review_rejects_blank_review_identifier() {
    let result = BehavioralReview::new(
        " ",
        vec![TraitAssessment::new(
            BehavioralTrait::Patience,
            BehavioralOutcome::InsufficientEvidence,
            vec![],
            "No observation available",
        )
        .unwrap()],
        vec![],
    );
    assert_eq!(result, Err(BehavioralReviewError::EmptyReviewId));
}
