//! G07 agent-principal identity binding over verified credential registry evidence.
//! Principal identity is not a capability grant or execution authorization.
use crate::canonical_json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentPrincipalInput {
    pub agent_id: String,
    pub credential_ref: String,
    pub runtime_instance_id: String,
    pub principal_class: String,
    pub provenance: BTreeMap<String, Value>,
    pub version_bound_evidence: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentCredentialBinding {
    pub credential_ref: String,
    pub agent_id: String,
    pub runtime_instance_id: String,
    pub principal_class: String,
    pub credential_digest: String,
    pub active: bool,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentPrincipalPolicy {
    pub credential_bindings: BTreeMap<String, AgentCredentialBinding>,
    pub allowed_principal_classes: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentPrincipalEvidence {
    pub provenance: BTreeMap<String, Value>,
    pub version_bound_evidence: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentPrincipalOutput {
    pub agent_id: String,
    pub principal_valid: bool,
    pub principal_digest: String,
    pub identity_status: String,
    pub evidence: AgentPrincipalEvidence,
    pub version_bound_evidence: BTreeMap<String, Value>,
}

fn canonical<T: Serialize>(value: &T) -> Option<Vec<u8>> {
    canonical_json(&serde_json::to_value(value).ok()?).ok()
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(*byte, b'_' | b'-' | b'.' | b':')
        })
}

/// Resolve an agent's principal identity against an explicit credential registry snapshot.
/// This does not verify signatures itself and never grants capabilities or execution rights.
pub fn evaluate_agent_principal(
    input: &AgentPrincipalInput,
    policy: &AgentPrincipalPolicy,
) -> Result<AgentPrincipalOutput, String> {
    if !valid_identifier(&input.agent_id)
        || !valid_identifier(&input.credential_ref)
        || !valid_identifier(&input.runtime_instance_id)
        || !policy
            .allowed_principal_classes
            .contains(&input.principal_class)
    {
        return Err("agent_principal_input_invalid".into());
    }
    if input.provenance.is_empty() || input.version_bound_evidence.is_empty() {
        return Err("provenance_or_version_evidence_missing".into());
    }
    let Some(binding) = policy.credential_bindings.get(&input.credential_ref) else {
        return Err("credential_binding_not_registered".into());
    };
    if binding.credential_ref != input.credential_ref || !valid_digest(&binding.credential_digest) {
        return Err("credential_binding_malformed".into());
    }
    let Some(registry_digest) = canonical(&policy.credential_bindings).map(|bytes| digest(&bytes))
    else {
        return Err("credential_registry_canonicalization_failed".into());
    };
    let Some(bound_registry_digest) = input
        .version_bound_evidence
        .get("agent_registry_digest")
        .and_then(Value::as_str)
    else {
        return Err("agent_registry_digest_missing".into());
    };
    let Some(policy_digest) = canonical(policy).map(|bytes| digest(&bytes)) else {
        return Err("agent_policy_canonicalization_failed".into());
    };
    let Some(bound_policy_digest) = input
        .version_bound_evidence
        .get("agent_policy_digest")
        .and_then(Value::as_str)
    else {
        return Err("agent_policy_digest_missing".into());
    };
    let Some(bound_credential_digest) = input
        .version_bound_evidence
        .get("credential_digest")
        .and_then(Value::as_str)
    else {
        return Err("credential_digest_evidence_missing".into());
    };
    if !valid_digest(bound_registry_digest)
        || bound_registry_digest != registry_digest
        || !valid_digest(bound_policy_digest)
        || bound_policy_digest != policy_digest
        || bound_credential_digest != binding.credential_digest
    {
        return Err("agent_registry_or_credential_digest_mismatch".into());
    }
    if canonical(&input.provenance).is_none() || canonical(&input.version_bound_evidence).is_none()
    {
        return Err("agent_principal_evidence_canonicalization_failed".into());
    }
    let identity_matches = binding.agent_id == input.agent_id
        && binding.runtime_instance_id == input.runtime_instance_id
        && binding.principal_class == input.principal_class
        && policy
            .allowed_principal_classes
            .contains(&binding.principal_class);
    let identity_status = if binding.revoked {
        "revoked"
    } else if binding.active && identity_matches {
        "valid"
    } else {
        "invalid"
    };
    let principal_valid = identity_status == "valid";
    let principal_material = canonical(&(input, binding))
        .ok_or_else(|| "principal_digest_canonicalization_failed".to_owned())?;
    Ok(AgentPrincipalOutput {
        agent_id: input.agent_id.clone(),
        principal_valid,
        principal_digest: digest(&principal_material),
        identity_status: identity_status.into(),
        evidence: AgentPrincipalEvidence {
            provenance: input.provenance.clone(),
            version_bound_evidence: input.version_bound_evidence.clone(),
        },
        version_bound_evidence: input.version_bound_evidence.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn binding() -> AgentCredentialBinding {
        AgentCredentialBinding {
            credential_ref: "credential-agent-1".into(),
            agent_id: "agent-1".into(),
            runtime_instance_id: "runtime-1".into(),
            principal_class: "task".into(),
            credential_digest: "a".repeat(64),
            active: true,
            revoked: false,
        }
    }

    fn policy() -> AgentPrincipalPolicy {
        AgentPrincipalPolicy {
            credential_bindings: BTreeMap::from([("credential-agent-1".into(), binding())]),
            allowed_principal_classes: ["system", "service", "task", "subagent"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }
    }

    fn input(policy: &AgentPrincipalPolicy) -> AgentPrincipalInput {
        let registry_digest = digest(&canonical(&policy.credential_bindings).unwrap());
        AgentPrincipalInput {
            agent_id: "agent-1".into(),
            credential_ref: "credential-agent-1".into(),
            runtime_instance_id: "runtime-1".into(),
            principal_class: "task".into(),
            provenance: BTreeMap::from([("issuer".into(), json!("synthetic-test"))]),
            version_bound_evidence: BTreeMap::from([
                ("agent_registry_digest".into(), json!(registry_digest)),
                (
                    "agent_policy_digest".into(),
                    json!(digest(&canonical(policy).unwrap())),
                ),
                ("credential_digest".into(), json!("a".repeat(64))),
            ]),
        }
    }

    #[test]
    fn accepts_exact_active_registry_binding() {
        let p = policy();
        let result = evaluate_agent_principal(&input(&p), &p).unwrap();
        assert!(result.principal_valid);
        assert_eq!(result.identity_status, "valid");
        assert_eq!(result.principal_digest.len(), 64);
    }

    #[test]
    fn rejects_substituted_agent_runtime_and_class() {
        let p = policy();
        let mut value = input(&p);
        value.agent_id = "agent-2".into();
        let result = evaluate_agent_principal(&value, &p).unwrap();
        assert!(!result.principal_valid);
        assert_eq!(result.identity_status, "invalid");
        let mut value = input(&p);
        value.runtime_instance_id = "runtime-2".into();
        assert_eq!(
            evaluate_agent_principal(&value, &p)
                .unwrap()
                .identity_status,
            "invalid"
        );
        let mut value = input(&p);
        value.principal_class = "service".into();
        assert_eq!(
            evaluate_agent_principal(&value, &p)
                .unwrap()
                .identity_status,
            "invalid"
        );
    }

    #[test]
    fn revoked_binding_never_validates() {
        let mut p = policy();
        p.credential_bindings
            .get_mut("credential-agent-1")
            .unwrap()
            .revoked = true;
        let result = evaluate_agent_principal(&input(&p), &p).unwrap();
        assert!(!result.principal_valid);
        assert_eq!(result.identity_status, "revoked");
    }

    #[test]
    fn rejects_registry_or_credential_digest_substitution() {
        let p = policy();
        let mut value = input(&p);
        value
            .version_bound_evidence
            .insert("agent_registry_digest".into(), json!("f".repeat(64)));
        assert_eq!(
            evaluate_agent_principal(&value, &p),
            Err("agent_registry_or_credential_digest_mismatch".into())
        );
        let mut value = input(&p);
        value
            .version_bound_evidence
            .insert("credential_digest".into(), json!("f".repeat(64)));
        assert_eq!(
            evaluate_agent_principal(&value, &p),
            Err("agent_registry_or_credential_digest_mismatch".into())
        );
    }

    #[test]
    fn rejects_unknown_credential_and_missing_evidence() {
        let p = policy();
        let mut value = input(&p);
        value.credential_ref = "credential-unknown".into();
        assert_eq!(
            evaluate_agent_principal(&value, &p),
            Err("credential_binding_not_registered".into())
        );
        let mut value = input(&p);
        value.provenance.clear();
        assert_eq!(
            evaluate_agent_principal(&value, &p),
            Err("provenance_or_version_evidence_missing".into())
        );
    }
}
