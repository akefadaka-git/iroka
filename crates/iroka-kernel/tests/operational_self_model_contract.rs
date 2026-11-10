use iroka_kernel::{
    EvidenceKind, EvidenceReference, LicenceStatus, OperationalSelfModel, SelfClaimCategory,
    SelfClaimStatus, SelfModelClaim, SelfModelError,
};

fn evidence(id: &str, kind: EvidenceKind) -> EvidenceReference {
    EvidenceReference::new(
        id,
        kind,
        "Operational source",
        Some("en".into()),
        Some("v1".into()),
        "system evidence catalogue",
        LicenceStatus::Verified,
    )
    .unwrap()
}

fn claim(status: SelfClaimStatus, evidence_ids: Vec<String>) -> SelfModelClaim {
    SelfModelClaim::new(
        "claim:1",
        SelfClaimCategory::Capability,
        "The feature is available",
        status,
        evidence_ids,
        "Bounded operational report",
    )
    .unwrap()
}

#[test]
fn verified_claim_requires_evidence() {
    let result = SelfModelClaim::new(
        "claim:1",
        SelfClaimCategory::RuntimeState,
        "Service is running",
        SelfClaimStatus::Verified,
        vec![],
        "No source evidence supplied",
    );
    assert_eq!(result, Err(SelfModelError::EvidenceRequired));
}

#[test]
fn inferred_claim_requires_evidence() {
    let result = SelfModelClaim::new(
        "claim:1",
        SelfClaimCategory::Capability,
        "Capability may be available",
        SelfClaimStatus::Inferred,
        vec![],
        "Inference without evidence is not accepted",
    );
    assert_eq!(result, Err(SelfModelError::EvidenceRequired));
}

#[test]
fn unavailable_claim_cannot_assert_value_evidence() {
    let result = SelfModelClaim::new(
        "claim:1",
        SelfClaimCategory::RuntimeState,
        "Runtime status unavailable",
        SelfClaimStatus::Unavailable,
        vec!["source:1".into()],
        "Provider did not return status",
    );
    assert_eq!(result, Err(SelfModelError::UnavailableClaimHasEvidence));
}

#[test]
fn generated_synthesis_alone_cannot_support_verified_claim() {
    let result = OperationalSelfModel::new(
        "snapshot:1",
        vec![claim(SelfClaimStatus::Verified, vec!["source:1".into()])],
        vec![evidence("source:1", EvidenceKind::GeneratedSynthesis)],
    );
    assert_eq!(
        result,
        Err(SelfModelError::GeneratedEvidenceCannotVerifyClaim)
    );
}

#[test]
fn verified_claim_accepts_linked_non_generated_evidence() {
    let model = OperationalSelfModel::new(
        "snapshot:1",
        vec![claim(
            SelfClaimStatus::Verified,
            vec!["source:1".into()],
        )],
        vec![evidence("source:1", EvidenceKind::EmpiricalEvidence)],
    )
    .unwrap();
    assert_eq!(model.claims()[0].status(), SelfClaimStatus::Verified);
}

#[test]
fn declared_claim_remains_distinct_from_verified_claim() {
    let declared = claim(SelfClaimStatus::Declared, vec![]);
    assert_eq!(declared.status(), SelfClaimStatus::Declared);
    assert_ne!(declared.status(), SelfClaimStatus::Verified);
}

#[test]
fn snapshot_rejects_unresolved_evidence_references() {
    let result = OperationalSelfModel::new(
        "snapshot:1",
        vec![claim(
            SelfClaimStatus::Inferred,
            vec!["missing:source".into()],
        )],
        vec![],
    );
    assert_eq!(result, Err(SelfModelError::UnresolvedEvidenceReference));
}

#[test]
fn snapshot_rejects_duplicate_claim_identifiers() {
    let first = claim(SelfClaimStatus::Declared, vec![]);
    let second = SelfModelClaim::new(
        "claim:1",
        SelfClaimCategory::Limitation,
        "Network access is unavailable",
        SelfClaimStatus::Declared,
        vec![],
        "Declared configuration limitation",
    )
    .unwrap();
    let result = OperationalSelfModel::new("snapshot:1", vec![first, second], vec![]);
    assert_eq!(result, Err(SelfModelError::DuplicateClaimId));
}

#[test]
fn unavailable_status_is_preserved_as_uncertainty() {
    let unavailable = SelfModelClaim::new(
        "claim:unavailable",
        SelfClaimCategory::RuntimeState,
        "Live provider state is unavailable",
        SelfClaimStatus::Unavailable,
        vec![],
        "No authoritative provider response",
    )
    .unwrap();
    let model = OperationalSelfModel::new("snapshot:2", vec![unavailable], vec![]).unwrap();
    assert_eq!(model.claims()[0].status(), SelfClaimStatus::Unavailable);
}
