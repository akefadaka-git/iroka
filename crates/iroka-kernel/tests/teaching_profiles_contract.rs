use iroka_kernel::{
    EvidenceKind, EvidenceReference, HumanReviewRequirement, ImpactLevel, LicenceStatus,
    TeachingMode, TeachingProfileError, TeachingTaskProfile,
};

fn evidence(id: &str) -> EvidenceReference {
    EvidenceReference::new(
        id,
        EvidenceKind::EmpiricalEvidence,
        "Reference source",
        Some("en".into()),
        Some("v1".into()),
        "approved evidence catalogue",
        LicenceStatus::Verified,
    )
    .unwrap()
}

fn profile(
    impact: ImpactLevel,
    review: HumanReviewRequirement,
    evidence: Vec<EvidenceReference>,
) -> Result<TeachingTaskProfile, TeachingProfileError> {
    TeachingTaskProfile::new(
        "task:1",
        TeachingMode::Teacher,
        "Explain a general learning concept",
        impact,
        review,
        evidence,
    )
}

#[test]
fn all_six_teaching_modes_are_distinct_bounded_profiles() {
    assert_ne!(TeachingMode::Teacher, TeachingMode::Mentor);
    assert_ne!(TeachingMode::Mentor, TeachingMode::Advisor);
    assert_ne!(TeachingMode::Advisor, TeachingMode::Researcher);
    assert_ne!(TeachingMode::Researcher, TeachingMode::Coach);
    assert_ne!(TeachingMode::Coach, TeachingMode::Creator);
}

#[test]
fn high_impact_tasks_require_human_review() {
    assert_eq!(
        profile(
            ImpactLevel::High,
            HumanReviewRequirement::Recommended,
            vec![]
        ),
        Err(TeachingProfileError::HighImpactRequiresHumanReview)
    );
}

#[test]
fn critical_tasks_require_human_review() {
    assert_eq!(
        profile(
            ImpactLevel::Critical,
            HumanReviewRequirement::NotRequired,
            vec![]
        ),
        Err(TeachingProfileError::HighImpactRequiresHumanReview)
    );
}

#[test]
fn moderate_impact_tasks_cannot_disable_safeguards() {
    assert_eq!(
        profile(
            ImpactLevel::Moderate,
            HumanReviewRequirement::NotRequired,
            vec![]
        ),
        Err(TeachingProfileError::ModerateImpactRequiresSafeguard)
    );
}

#[test]
fn high_impact_tasks_require_evidence_even_with_review() {
    assert_eq!(
        profile(ImpactLevel::High, HumanReviewRequirement::Required, vec![]),
        Err(TeachingProfileError::HighImpactEvidenceRequired)
    );
}

#[test]
fn high_impact_task_accepts_evidence_and_required_review() {
    let task = profile(
        ImpactLevel::High,
        HumanReviewRequirement::Required,
        vec![evidence("source:1")],
    )
    .unwrap();
    assert_eq!(task.impact(), ImpactLevel::High);
    assert_eq!(task.human_review(), HumanReviewRequirement::Required);
}

#[test]
fn low_impact_task_can_be_self_contained() {
    let task = profile(
        ImpactLevel::Low,
        HumanReviewRequirement::NotRequired,
        vec![],
    )
    .unwrap();
    assert_eq!(task.mode(), TeachingMode::Teacher);
}

#[test]
fn task_rejects_duplicate_evidence_identifiers() {
    assert_eq!(
        profile(
            ImpactLevel::Moderate,
            HumanReviewRequirement::Recommended,
            vec![evidence("source:1"), evidence("source:1")],
        ),
        Err(TeachingProfileError::DuplicateEvidenceId)
    );
}
