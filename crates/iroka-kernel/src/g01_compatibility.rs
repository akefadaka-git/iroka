//! G01 compatibility evaluator for contract v1.1.0.
//!
//! The resolver is a trusted boundary: it resolves exact source/target contract
//! identities under a named version grammar, authenticates an immutable scoped
//! policy, compares semantics independently of caller claims, and verifies
//! migration artifacts. This gene never grants authority or execution rights.

use serde::{Deserialize, Serialize};
use serde_json::Value;

fn deserialize_required_nullable_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityInput {
    pub source_version: String,
    pub target_version: String,
    pub contract_registry_id: String,
    pub version_grammar_id: String,
    pub policy_id: String,
    pub policy_version: String,
    pub policy_issuer_id: String,
    pub policy_digest: String,
    pub declared_compatible: bool,
    #[serde(deserialize_with = "deserialize_required_nullable_string")]
    pub migration_digest: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable_string")]
    pub migration_ref: Option<String>,
    pub provenance: Value,
    pub version_bound_evidence: Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityDecision {
    Compatible,
    Incompatible,
    MigrationRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityEvidence {
    pub provenance: Value,
    pub version_bound_evidence: Value,
    pub contract_registry_id: String,
    pub version_grammar_id: String,
    pub source_contract_id: String,
    pub target_contract_id: String,
    pub canonical_source_version: String,
    pub canonical_target_version: String,
    pub policy_issuer_id: String,
    pub policy_version: String,
    pub policy_digest: String,
    pub policy_scope_verified: bool,
    pub policy_validity_verified: bool,
    pub comparison_digest: String,
    pub policy_decision: CompatibilityDecision,
    pub declaration_conflict: bool,
    pub migration_ref: Option<String>,
    pub migration_digest: Option<String>,
    pub migration_verified: bool,
    pub no_migration_required: bool,
    pub decision_rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityOutput {
    pub compatibility: bool,
    pub decision: CompatibilityDecision,
    pub policy_id: String,
    pub evidence: CompatibilityEvidence,
    pub version_bound_evidence: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompatibilityProof {
    pub contract_registry_id: String,
    pub version_grammar_id: String,
    pub source_contract_id: String,
    pub target_contract_id: String,
    pub canonical_source_version: String,
    pub canonical_target_version: String,
    pub policy_id: String,
    pub policy_version: String,
    pub policy_issuer_id: String,
    pub policy_digest: String,
    pub policy_scope_verified: bool,
    pub policy_validity_verified: bool,
    pub comparison_digest: String,
    pub policy_decision: CompatibilityDecision,
    pub migration_ref: Option<String>,
    pub migration_digest: Option<String>,
    pub migration_verified: bool,
    pub no_migration_required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatibilityError {
    Malformed,
    UnknownVersion,
    AmbiguousVersion,
    VersionResolutionInvalid,
    UnknownPolicy,
    PolicyUnauthenticated,
    PolicyOutOfScope,
    PolicyExpired,
    MigrationMissing,
    MigrationInvalid,
    EvidenceInvalid,
    RegistryUnavailable,
}

/// Must resolve exact canonical contract identities, authenticate policy issuer
/// and immutable policy version/scope/validity, independently compare semantics,
/// and authenticate any migration artifact against the exact source/target pair.
pub trait CompatibilityResolver: Send + Sync {
    fn evaluate(
        &self,
        input: &CompatibilityInput,
    ) -> Result<CompatibilityProof, CompatibilityError>;
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

pub fn evaluate_compatibility<R: CompatibilityResolver>(
    resolver: &R,
    input: &CompatibilityInput,
) -> Result<CompatibilityOutput, CompatibilityError> {
    if input.source_version.trim().is_empty()
        || input.target_version.trim().is_empty()
        || input.contract_registry_id.trim().is_empty()
        || input.version_grammar_id.trim().is_empty()
        || input.policy_id.trim().is_empty()
        || input.policy_version.trim().is_empty()
        || input.policy_issuer_id.trim().is_empty()
        || !valid_sha256(&input.policy_digest)
        || input.provenance.is_null()
        || !input.provenance.is_object()
        || input.provenance.as_object().is_some_and(|v| v.is_empty())
        || input.version_bound_evidence.is_null()
        || !input.version_bound_evidence.is_object()
        || input
            .version_bound_evidence
            .as_object()
            .is_some_and(|v| v.is_empty())
        || input
            .migration_digest
            .as_ref()
            .is_some_and(|v| !valid_sha256(v))
        || input
            .migration_ref
            .as_ref()
            .is_some_and(|v| v.trim().is_empty())
        || input.migration_digest.is_some() != input.migration_ref.is_some()
    {
        return Err(CompatibilityError::Malformed);
    }

    let proof = resolver.evaluate(input)?;
    if proof.contract_registry_id != input.contract_registry_id
        || proof.version_grammar_id != input.version_grammar_id
        || proof.canonical_source_version != input.source_version
        || proof.canonical_target_version != input.target_version
        || proof.source_contract_id.trim().is_empty()
        || proof.target_contract_id.trim().is_empty()
    {
        return Err(CompatibilityError::VersionResolutionInvalid);
    }
    if proof.policy_id != input.policy_id
        || proof.policy_version != input.policy_version
        || proof.policy_issuer_id != input.policy_issuer_id
        || proof.policy_digest != input.policy_digest
        || !valid_sha256(&proof.policy_digest)
    {
        return Err(CompatibilityError::PolicyUnauthenticated);
    }
    if !proof.policy_scope_verified {
        return Err(CompatibilityError::PolicyOutOfScope);
    }
    if !proof.policy_validity_verified {
        return Err(CompatibilityError::PolicyExpired);
    }
    if !valid_sha256(&proof.comparison_digest) {
        return Err(CompatibilityError::EvidenceInvalid);
    }

    match (&input.migration_ref, &input.migration_digest) {
        (None, None) => {
            if !proof.no_migration_required
                || proof.migration_verified
                || proof.migration_ref.is_some()
                || proof.migration_digest.is_some()
            {
                return Err(CompatibilityError::MigrationMissing);
            }
        }
        (Some(reference), Some(digest)) => {
            if proof.migration_ref.as_ref() != Some(reference)
                || proof.migration_digest.as_ref() != Some(digest)
                || !proof.migration_verified
                || proof.no_migration_required
            {
                return Err(CompatibilityError::MigrationInvalid);
            }
        }
        _ => return Err(CompatibilityError::Malformed),
    }

    if proof.policy_decision == CompatibilityDecision::Compatible && input.migration_ref.is_some() {
        return Err(CompatibilityError::MigrationInvalid);
    }
    if proof.policy_decision == CompatibilityDecision::MigrationRequired
        && input.migration_ref.is_none()
    {
        return Err(CompatibilityError::MigrationMissing);
    }

    let declaration_conflict =
        input.declared_compatible != (proof.policy_decision == CompatibilityDecision::Compatible);
    let decision = if declaration_conflict {
        match proof.policy_decision {
            CompatibilityDecision::Compatible | CompatibilityDecision::Incompatible => {
                CompatibilityDecision::Incompatible
            }
            CompatibilityDecision::MigrationRequired => CompatibilityDecision::MigrationRequired,
        }
    } else {
        proof.policy_decision
    };
    let compatibility = decision == CompatibilityDecision::Compatible;
    let decision_rationale = if declaration_conflict {
        "caller compatibility declaration conflicts with independently authenticated policy; fail closed"
            .to_owned()
    } else {
        "exact contract identities compared under authenticated immutable policy".to_owned()
    };
    let version_bound_evidence = serde_json::json!({
        "input_evidence": input.version_bound_evidence,
        "contract_registry_id": proof.contract_registry_id,
        "version_grammar_id": proof.version_grammar_id,
        "source_contract_id": proof.source_contract_id,
        "target_contract_id": proof.target_contract_id,
        "source_version": proof.canonical_source_version,
        "target_version": proof.canonical_target_version,
        "policy_version": proof.policy_version
    });
    let evidence = CompatibilityEvidence {
        provenance: input.provenance.clone(),
        version_bound_evidence: version_bound_evidence.clone(),
        contract_registry_id: proof.contract_registry_id,
        version_grammar_id: proof.version_grammar_id,
        source_contract_id: proof.source_contract_id,
        target_contract_id: proof.target_contract_id,
        canonical_source_version: proof.canonical_source_version,
        canonical_target_version: proof.canonical_target_version,
        policy_issuer_id: proof.policy_issuer_id,
        policy_version: proof.policy_version,
        policy_digest: proof.policy_digest,
        policy_scope_verified: proof.policy_scope_verified,
        policy_validity_verified: proof.policy_validity_verified,
        comparison_digest: proof.comparison_digest,
        policy_decision: proof.policy_decision,
        declaration_conflict,
        migration_ref: proof.migration_ref,
        migration_digest: proof.migration_digest,
        migration_verified: proof.migration_verified,
        no_migration_required: proof.no_migration_required,
        decision_rationale,
    };
    Ok(CompatibilityOutput {
        compatibility,
        decision,
        policy_id: input.policy_id.clone(),
        evidence,
        version_bound_evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestResolver {
        proof: CompatibilityProof,
    }

    impl CompatibilityResolver for TestResolver {
        fn evaluate(
            &self,
            _: &CompatibilityInput,
        ) -> Result<CompatibilityProof, CompatibilityError> {
            Ok(self.proof.clone())
        }
    }

    fn input() -> CompatibilityInput {
        CompatibilityInput {
            source_version: "contract-vA".into(),
            target_version: "contract-vB".into(),
            contract_registry_id: "registry:canonical-contracts".into(),
            version_grammar_id: "grammar:opaque-identifiers-v1".into(),
            policy_id: "compatibility-policy:stable".into(),
            policy_version: "3.2.0".into(),
            policy_issuer_id: "issuer:policy-authority".into(),
            policy_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            declared_compatible: true,
            migration_digest: None,
            migration_ref: None,
            provenance: serde_json::json!({"source":"version-registry"}),
            version_bound_evidence: serde_json::json!({
                "gene":"g01.compatibility",
                "version":"1.1.0"
            }),
        }
    }

    fn proof() -> CompatibilityProof {
        CompatibilityProof {
            contract_registry_id: "registry:canonical-contracts".into(),
            version_grammar_id: "grammar:opaque-identifiers-v1".into(),
            source_contract_id: "contract-id:source-001".into(),
            target_contract_id: "contract-id:target-002".into(),
            canonical_source_version: "contract-vA".into(),
            canonical_target_version: "contract-vB".into(),
            policy_id: "compatibility-policy:stable".into(),
            policy_version: "3.2.0".into(),
            policy_issuer_id: "issuer:policy-authority".into(),
            policy_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            policy_scope_verified: true,
            policy_validity_verified: true,
            comparison_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            policy_decision: CompatibilityDecision::Compatible,
            migration_ref: None,
            migration_digest: None,
            migration_verified: false,
            no_migration_required: true,
        }
    }

    #[test]
    fn compatibility_accepts_canonical_versions_and_authenticated_policy() {
        let output = evaluate_compatibility(&TestResolver { proof: proof() }, &input()).unwrap();
        assert!(output.compatibility);
        assert_eq!(output.decision, CompatibilityDecision::Compatible);
        assert!(!output.evidence.declaration_conflict);
        assert!(output.evidence.policy_scope_verified);
        assert!(output.evidence.policy_validity_verified);
        assert_eq!(output.evidence.source_contract_id, "contract-id:source-001");
    }

    #[test]
    fn compatibility_records_declaration_conflict_and_fails_closed() {
        let mut candidate = input();
        candidate.declared_compatible = false;
        let output = evaluate_compatibility(&TestResolver { proof: proof() }, &candidate).unwrap();
        assert!(!output.compatibility);
        assert_eq!(output.decision, CompatibilityDecision::Incompatible);
        assert!(output.evidence.declaration_conflict);
    }

    #[test]
    fn compatibility_requires_authenticated_migration_for_migration_required() {
        let mut candidate = input();
        candidate.declared_compatible = false;
        candidate.migration_ref = Some("migration:source-to-target".into());
        candidate.migration_digest =
            Some("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into());
        let mut migration_proof = proof();
        migration_proof.policy_decision = CompatibilityDecision::MigrationRequired;
        migration_proof.migration_ref = candidate.migration_ref.clone();
        migration_proof.migration_digest = candidate.migration_digest.clone();
        migration_proof.migration_verified = true;
        migration_proof.no_migration_required = false;
        let output = evaluate_compatibility(
            &TestResolver {
                proof: migration_proof,
            },
            &candidate,
        )
        .unwrap();
        assert!(!output.compatibility);
        assert_eq!(output.decision, CompatibilityDecision::MigrationRequired);
        assert!(output.evidence.migration_verified);
    }

    #[test]
    fn compatibility_rejects_policy_scope_or_validity_failure() {
        let mut scope = proof();
        scope.policy_scope_verified = false;
        assert_eq!(
            evaluate_compatibility(&TestResolver { proof: scope }, &input()),
            Err(CompatibilityError::PolicyOutOfScope)
        );
        let mut validity = proof();
        validity.policy_validity_verified = false;
        assert_eq!(
            evaluate_compatibility(&TestResolver { proof: validity }, &input()),
            Err(CompatibilityError::PolicyExpired)
        );
    }

    #[test]
    fn compatibility_rejects_unknown_or_ambiguous_version_resolution() {
        let mut version = proof();
        version.canonical_target_version = "guessed-target".into();
        assert_eq!(
            evaluate_compatibility(&TestResolver { proof: version }, &input()),
            Err(CompatibilityError::VersionResolutionInvalid)
        );
    }

    #[test]
    fn compatibility_rejects_policy_identity_or_digest_mismatch() {
        let mut policy = proof();
        policy.policy_version = "9.9.9".into();
        assert_eq!(
            evaluate_compatibility(&TestResolver { proof: policy }, &input()),
            Err(CompatibilityError::PolicyUnauthenticated)
        );
    }

    #[test]
    fn compatibility_rejects_unproven_null_migration_and_invalid_artifact() {
        let mut no_migration = proof();
        no_migration.no_migration_required = false;
        assert_eq!(
            evaluate_compatibility(
                &TestResolver {
                    proof: no_migration,
                },
                &input()
            ),
            Err(CompatibilityError::MigrationMissing)
        );
        let mut candidate = input();
        candidate.migration_ref = Some("migration:source-to-target".into());
        candidate.migration_digest =
            Some("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into());
        let mut invalid = proof();
        invalid.migration_ref = candidate.migration_ref.clone();
        invalid.migration_digest = candidate.migration_digest.clone();
        invalid.migration_verified = false;
        invalid.no_migration_required = false;
        assert_eq!(
            evaluate_compatibility(&TestResolver { proof: invalid }, &candidate),
            Err(CompatibilityError::MigrationInvalid)
        );
    }

    #[test]
    fn compatibility_requires_nullable_migration_fields_to_be_present() {
        let mut value = serde_json::to_value(input()).unwrap();
        value.as_object_mut().unwrap().remove("migration_digest");
        assert!(serde_json::from_value::<CompatibilityInput>(value).is_err());
        let value = serde_json::to_value(input()).unwrap();
        assert!(serde_json::from_value::<CompatibilityInput>(value).is_ok());
    }

    #[test]
    fn compatibility_output_keeps_boolean_and_decision_consistent() {
        for decision in [
            CompatibilityDecision::Compatible,
            CompatibilityDecision::Incompatible,
            CompatibilityDecision::MigrationRequired,
        ] {
            let mut candidate = input();
            if decision != CompatibilityDecision::Compatible {
                candidate.declared_compatible = false;
            }
            let mut candidate_proof = proof();
            candidate_proof.policy_decision = decision;
            if decision == CompatibilityDecision::MigrationRequired {
                candidate.migration_ref = Some("migration:source-to-target".into());
                candidate.migration_digest = Some(
                    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                        .into(),
                );
                candidate_proof.migration_ref = candidate.migration_ref.clone();
                candidate_proof.migration_digest = candidate.migration_digest.clone();
                candidate_proof.migration_verified = true;
                candidate_proof.no_migration_required = false;
            }
            let output = evaluate_compatibility(
                &TestResolver {
                    proof: candidate_proof,
                },
                &candidate,
            )
            .unwrap();
            assert_eq!(
                output.compatibility,
                output.decision == CompatibilityDecision::Compatible
            );
        }
    }
}
