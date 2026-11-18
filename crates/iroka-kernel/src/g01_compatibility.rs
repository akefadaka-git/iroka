//! G01 compatibility gene evaluator. Compatibility does not grant authority.

use serde::{Deserialize, Serialize};
use serde_json::Value;

fn deserialize_required_nullable_string<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
    #[test]
    fn compatibility_input_requires_nullable_migration_digest_field() {
        let mut value = serde_json::to_value(input()).unwrap();
        value.as_object_mut().unwrap().remove("migration_digest");
        assert!(serde_json::from_value::<CompatibilityInput>(value).is_err());
        let value = serde_json::to_value(input()).unwrap();
        assert!(serde_json::from_value::<CompatibilityInput>(value).is_ok());
    }

}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityInput {
    pub source_version: String,
    pub target_version: String,
    pub policy_id: String,
    pub declared_compatible: bool,
    #[serde(deserialize_with = "deserialize_required_nullable_string")]
    pub migration_digest: Option<String>,
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
pub struct CompatibilityOutput {
    pub compatibility: bool,
    pub decision: CompatibilityDecision,
    pub policy_id: String,
    pub evidence: CompatibilityEvidence,
    pub version_bound_evidence: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityEvidence {
    pub provenance: Value,
    pub version_bound_evidence: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompatibilityProof {
    pub source_digest: String,
    pub target_digest: String,
    pub policy_version: String,
    pub comparison_digest: String,
    pub migration_verified: bool,
    pub no_migration_required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatibilityError {
    Malformed,
    UnknownVersion,
    AmbiguousVersion,
    UnknownPolicy,
    PolicyUnauthenticated,
    PolicyOutOfScope,
    MigrationMissing,
    MigrationInvalid,
    DeclarationMismatch,
    EvidenceInvalid,
    RegistryUnavailable,
}

/// Trusted compatibility policy/registry boundary. It must resolve exact
/// canonical versions and an authenticated immutable policy, independently
/// compare semantics, and authenticate any migration artifact against both
/// exact versions. It must never trust declared_compatible as the decision.
pub trait CompatibilityResolver: Send + Sync {
    fn evaluate(
        &self,
        input: &CompatibilityInput,
    ) -> Result<(CompatibilityDecision, CompatibilityProof), CompatibilityError>;
}

pub fn evaluate_compatibility<R: CompatibilityResolver>(
    resolver: &R,
    input: &CompatibilityInput,
) -> Result<CompatibilityOutput, CompatibilityError> {
    if input.source_version.trim().is_empty()
        || input.target_version.trim().is_empty()
        || input.policy_id.trim().is_empty()
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
            .is_some_and(|v| v.trim().is_empty())
    {
        return Err(CompatibilityError::Malformed);
    }

    let (decision, proof) = resolver.evaluate(input)?;
    if proof.source_digest.trim().is_empty()
        || proof.target_digest.trim().is_empty()
        || proof.policy_version.trim().is_empty()
        || proof.comparison_digest.trim().is_empty()
    {
        return Err(CompatibilityError::EvidenceInvalid);
    }

    match decision {
        CompatibilityDecision::Compatible => {
            if !input.declared_compatible {
                return Err(CompatibilityError::DeclarationMismatch);
            }
            if input.migration_digest.is_some() && !proof.migration_verified {
                return Err(CompatibilityError::MigrationInvalid);
            }
            if input.migration_digest.is_none() && !proof.no_migration_required {
                return Err(CompatibilityError::MigrationMissing);
            }
        }
        CompatibilityDecision::Incompatible => {
            if input.declared_compatible {
                return Err(CompatibilityError::DeclarationMismatch);
            }
            if input.migration_digest.is_some() && !proof.migration_verified {
                return Err(CompatibilityError::MigrationInvalid);
            }
        }
        CompatibilityDecision::MigrationRequired => {
            if input.declared_compatible {
                return Err(CompatibilityError::DeclarationMismatch);
            }
            if input.migration_digest.is_none() {
                return Err(CompatibilityError::MigrationMissing);
            }
            if !proof.migration_verified {
                return Err(CompatibilityError::MigrationInvalid);
            }
        }
    }

    let compatibility = decision == CompatibilityDecision::Compatible;
    let provenance = serde_json::json!({
        "input_provenance": input.provenance,
        "source_digest": proof.source_digest,
        "target_digest": proof.target_digest,
        "policy_id": input.policy_id,
        "policy_version": proof.policy_version,
        "comparison_digest": proof.comparison_digest,
        "migration_digest": input.migration_digest,
        "migration_verified": proof.migration_verified,
        "no_migration_required": proof.no_migration_required
    });
    let version_bound_evidence = serde_json::json!({
        "input_evidence": input.version_bound_evidence,
        "source_version": input.source_version,
        "target_version": input.target_version,
        "policy_version": proof.policy_version
    });
    Ok(CompatibilityOutput {
        compatibility,
        decision,
        policy_id: input.policy_id.clone(),
        evidence: CompatibilityEvidence {
            provenance,
            version_bound_evidence: version_bound_evidence.clone(),
        },
        version_bound_evidence,
    })
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;

    struct CompatiblePolicy;
    impl CompatibilityResolver for CompatiblePolicy {
        fn evaluate(
            &self,
            _: &CompatibilityInput,
        ) -> Result<(CompatibilityDecision, CompatibilityProof), CompatibilityError> {
            Ok((
                CompatibilityDecision::Compatible,
                CompatibilityProof {
                    source_digest: "sha256:source".into(),
                    target_digest: "sha256:target".into(),
                    policy_version: "policy-v3".into(),
                    comparison_digest: "sha256:comparison".into(),
                    migration_verified: false,
                    no_migration_required: true,
                },
            ))
        }
    }

    fn input() -> CompatibilityInput {
        CompatibilityInput {
            source_version: "1.2.0".into(),
            target_version: "1.3.0".into(),
            policy_id: "compatibility-policy:stable".into(),
            declared_compatible: true,
            migration_digest: None,
            provenance: serde_json::json!({"source":"version-registry"}),
            version_bound_evidence: serde_json::json!({"gene":"g01.compatibility","version":"1.0.0"}),
        }
    }

    #[test]
    fn compatibility_accepts_independently_verified_policy_result() {
        let output = evaluate_compatibility(&CompatiblePolicy, &input()).unwrap();
        assert!(output.compatibility);
        assert_eq!(output.decision, CompatibilityDecision::Compatible);
        assert_eq!(output.policy_id, "compatibility-policy:stable");
        assert!(output.evidence.provenance["comparison_digest"].is_string());
    }

    #[test]
    fn compatibility_rejects_caller_declaration_conflict() {
        let mut candidate = input();
        candidate.declared_compatible = false;
        assert_eq!(
            evaluate_compatibility(&CompatiblePolicy, &candidate),
            Err(CompatibilityError::DeclarationMismatch)
        );
    }

    #[test]
    fn compatibility_requires_evidence_that_no_migration_is_needed() {
        struct NoMigrationProofMissing;
        impl CompatibilityResolver for NoMigrationProofMissing {
            fn evaluate(
                &self,
                _: &CompatibilityInput,
            ) -> Result<(CompatibilityDecision, CompatibilityProof), CompatibilityError>
            {
                Ok((
                    CompatibilityDecision::Compatible,
                    CompatibilityProof {
                        source_digest: "sha256:source".into(),
                        target_digest: "sha256:target".into(),
                        policy_version: "policy-v3".into(),
                        comparison_digest: "sha256:comparison".into(),
                        migration_verified: false,
                        no_migration_required: false,
                    },
                ))
            }
        }
        assert_eq!(
            evaluate_compatibility(&NoMigrationProofMissing, &input()),
            Err(CompatibilityError::MigrationMissing)
        );
    }

    #[test]
    fn compatibility_requires_verified_migration_when_policy_requires_it() {
        struct MigrationPolicy;
        impl CompatibilityResolver for MigrationPolicy {
            fn evaluate(
                &self,
                _: &CompatibilityInput,
            ) -> Result<(CompatibilityDecision, CompatibilityProof), CompatibilityError>
            {
                Ok((
                    CompatibilityDecision::MigrationRequired,
                    CompatibilityProof {
                        source_digest: "sha256:source".into(),
                        target_digest: "sha256:target".into(),
                        policy_version: "policy-v3".into(),
                        comparison_digest: "sha256:comparison".into(),
                        migration_verified: false,
                        no_migration_required: false,
                    },
                ))
            }
        }
        let mut candidate = input();
        candidate.declared_compatible = false;
        candidate.migration_digest = Some("sha256:migration".into());
        assert_eq!(
            evaluate_compatibility(&MigrationPolicy, &candidate),
            Err(CompatibilityError::MigrationInvalid)
        );
    }
    #[test]
    fn compatibility_input_requires_nullable_migration_digest_field() {
        let mut value = serde_json::to_value(input()).unwrap();
        value.as_object_mut().unwrap().remove("migration_digest");
        assert!(serde_json::from_value::<CompatibilityInput>(value).is_err());
        let value = serde_json::to_value(input()).unwrap();
        assert!(serde_json::from_value::<CompatibilityInput>(value).is_ok());
    }

}
