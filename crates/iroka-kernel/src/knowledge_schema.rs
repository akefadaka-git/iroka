//! G04 knowledge-schema registry validation with a non-executable constraint vocabulary.
use crate::canonical_json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeValueType {
    String,
    Integer,
    Number,
    Boolean,
    Object,
    Array,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeFieldDefinition {
    pub field_id: String,
    pub name: String,
    pub value_type: KnowledgeValueType,
    pub required: bool,
    pub nullable: bool,
    pub description: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeConstraint {
    pub constraint_id: String,
    pub field_id: String,
    pub constraint_type: String,
    pub expression: String,
    pub parameters: BTreeMap<String, Value>,
    pub parameters_digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeSchemaInput {
    pub knowledge_type: String,
    pub fields: Vec<KnowledgeFieldDefinition>,
    pub constraints: Vec<KnowledgeConstraint>,
    pub schema_version: String,
    pub provenance: BTreeMap<String, Value>,
    pub version_bound_evidence: BTreeMap<String, Value>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnowledgeSchemaPolicy {
    allowed_knowledge_types: BTreeSet<String>,
    allowed_constraint_types: BTreeSet<String>,
    maximum_fields: usize,
    maximum_constraints: usize,
    maximum_collection_size: usize,
}
impl KnowledgeSchemaPolicy {
    pub fn new(
        allowed_knowledge_types: BTreeSet<String>,
        allowed_constraint_types: BTreeSet<String>,
        maximum_fields: usize,
        maximum_constraints: usize,
        maximum_collection_size: usize,
    ) -> Self {
        Self {
            allowed_knowledge_types,
            allowed_constraint_types,
            maximum_fields,
            maximum_constraints,
            maximum_collection_size,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NormalizedKnowledgeSchema {
    pub schema_id: String,
    pub knowledge_type: String,
    pub schema_version: String,
    pub fields: Vec<KnowledgeFieldDefinition>,
    pub constraints: Vec<KnowledgeConstraint>,
    pub closed_object: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeSchemaEvidence {
    pub field_count: u64,
    pub constraint_count: u64,
    pub schema_digest: String,
    pub provenance_digest: String,
    pub version_bound_evidence_digest: String,
    pub closed_object: bool,
    pub constraint_language: String,
    pub decision_reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeSchemaOutput {
    pub schema_id: String,
    pub normalized_schema: NormalizedKnowledgeSchema,
    pub schema_digest: String,
    pub validation_status: String,
    pub validation_errors: Vec<String>,
    pub evidence: KnowledgeSchemaEvidence,
    pub version_bound_evidence: BTreeMap<String, Value>,
}
fn canonical<T: Serialize>(v: &T) -> Option<Vec<u8>> {
    canonical_json(&serde_json::to_value(v).ok()?).ok()
}
fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn valid_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn valid_slug(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-' || *c == b'.'
        })
}
fn valid_semver(s: &str) -> bool {
    let parts: Vec<_> = s.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && (*p == "0" || !p.starts_with('0'))
        })
}
fn parameters_digest(p: &BTreeMap<String, Value>) -> Option<String> {
    let mut bytes = b"IROKA-KNOWLEDGE-CONSTRAINT-PARAMETERS-V1\0".to_vec();
    bytes.extend(canonical(p)?);
    Some(digest(&bytes))
}
fn number_param(c: &KnowledgeConstraint) -> Option<f64> {
    c.parameters
        .get("value")?
        .as_f64()
        .filter(|v| v.is_finite())
}
fn integer_param(c: &KnowledgeConstraint) -> Option<u64> {
    c.parameters.get("value")?.as_u64()
}
fn signed_integer_param(c: &KnowledgeConstraint) -> Option<i64> {
    c.parameters.get("value")?.as_i64()
}
fn numeric_bound_valid(c: &KnowledgeConstraint, field: &KnowledgeFieldDefinition) -> bool {
    match field.value_type {
        KnowledgeValueType::Integer => {
            signed_integer_param(c).is_some() || integer_param(c).is_some()
        }
        KnowledgeValueType::Number => number_param(c).is_some(),
        _ => false,
    }
}
fn exact_parameter_keys(c: &KnowledgeConstraint) -> bool {
    let expected: &[&str] = match c.constraint_type.as_str() {
        "min_length" | "max_length" | "minimum" | "maximum" | "min_items" | "max_items"
        | "min_properties" | "max_properties" => &["value"],
        "enum" => &["values"],
        "item_type" => &["value_type"],
        "closed_object" => &["allow_unknown"],
        "required_properties" => &["names"],
        "format" => &["format"],
        _ => return false,
    };
    c.parameters.len() == expected.len()
        && expected.iter().all(|key| c.parameters.contains_key(*key))
}
fn cross_bound_errors(constraints: &[KnowledgeConstraint]) -> Vec<String> {
    let mut bounds: BTreeMap<(String, String), (Option<f64>, Option<f64>)> = BTreeMap::new();
    for c in constraints {
        let group = match c.constraint_type.as_str() {
            "min_length" | "max_length" => "length",
            "minimum" | "maximum" => "numeric",
            "min_items" | "max_items" => "items",
            "min_properties" | "max_properties" => "properties",
            _ => continue,
        };
        let value = if matches!(
            c.constraint_type.as_str(),
            "min_length"
                | "max_length"
                | "min_items"
                | "max_items"
                | "min_properties"
                | "max_properties"
        ) {
            integer_param(c).map(|v| v as f64)
        } else {
            number_param(c)
        };
        let Some(value) = value else { continue };
        let entry = bounds
            .entry((c.field_id.clone(), group.into()))
            .or_default();
        if c.constraint_type.starts_with("min") || c.constraint_type == "minimum" {
            entry.0 = Some(entry.0.map_or(value, |old| old.max(value)));
        } else {
            entry.1 = Some(entry.1.map_or(value, |old| old.min(value)));
        }
    }
    bounds
        .into_iter()
        .filter_map(|((field, group), (min, max))| {
            if min.zip(max).is_some_and(|(lo, hi)| lo > hi) {
                Some(format!("constraint_bounds_inverted:{field}:{group}"))
            } else {
                None
            }
        })
        .collect()
}
fn constraint_error(
    c: &KnowledgeConstraint,
    field: &KnowledgeFieldDefinition,
    policy: &KnowledgeSchemaPolicy,
) -> Option<String> {
    if !policy.allowed_constraint_types.contains(&c.constraint_type) {
        return Some("constraint_type_not_approved".into());
    }
    if !exact_parameter_keys(c) {
        return Some("constraint_parameter_shape_invalid".into());
    }
    if c.expression != format!("field.{}", c.constraint_type) {
        return Some("constraint_expression_outside_non_executable_grammar".into());
    }
    if !valid_digest(&c.parameters_digest)
        || parameters_digest(&c.parameters).as_deref() != Some(c.parameters_digest.as_str())
    {
        return Some("constraint_parameters_digest_mismatch".into());
    }
    let err = match c.constraint_type.as_str() {
        "min_length" | "max_length" if field.value_type == KnowledgeValueType::String => {
            if integer_param(c).map_or(true, |v| v as usize > policy.maximum_collection_size) {
                Some("length_constraint_invalid_or_exceeds_policy".into())
            } else {
                None
            }
        }
        "minimum" | "maximum"
            if matches!(
                field.value_type,
                KnowledgeValueType::Integer | KnowledgeValueType::Number
            ) =>
        {
            if !numeric_bound_valid(c, field) {
                Some("numeric_constraint_requires_type_compatible_finite_number".into())
            } else {
                None
            }
        }
        "enum" if field.value_type == KnowledgeValueType::String => {
            let values = c.parameters.get("values").and_then(Value::as_array);
            if values.map_or(true, |v| {
                v.is_empty()
                    || v.len() > policy.maximum_collection_size
                    || v.iter().any(|x| !x.is_string())
                    || {
                        let mut s = BTreeSet::new();
                        v.iter().any(|x| !s.insert(x.as_str().unwrap_or_default()))
                    }
            }) {
                Some("enum_requires_unique_nonempty_string_values".into())
            } else {
                None
            }
        }
        "min_items" | "max_items" if field.value_type == KnowledgeValueType::Array => {
            if integer_param(c).map_or(true, |v| v as usize > policy.maximum_collection_size) {
                Some("array_bound_invalid_or_exceeds_policy".into())
            } else {
                None
            }
        }
        "item_type" if field.value_type == KnowledgeValueType::Array => {
            match c.parameters.get("value_type").and_then(Value::as_str) {
                Some("string" | "integer" | "number" | "boolean") => None,
                _ => Some("array_item_type_not_supported".into()),
            }
        }
        "closed_object" if field.value_type == KnowledgeValueType::Object => {
            if c.parameters.get("allow_unknown").and_then(Value::as_bool) == Some(false) {
                None
            } else {
                Some("object_must_reject_unknown_properties".into())
            }
        }
        "min_properties" | "max_properties" if field.value_type == KnowledgeValueType::Object => {
            if integer_param(c).map_or(true, |v| v as usize > policy.maximum_collection_size) {
                Some("object_property_bound_invalid_or_exceeds_policy".into())
            } else {
                None
            }
        }
        "required_properties" if field.value_type == KnowledgeValueType::Object => {
            let values = c.parameters.get("names").and_then(Value::as_array);
            if values.map_or(true, |v| {
                v.is_empty()
                    || v.len() > policy.maximum_collection_size
                    || v.iter()
                        .any(|x| x.as_str().map_or(true, |s| !valid_slug(s)))
                    || {
                        let mut s = BTreeSet::new();
                        v.iter().any(|x| !s.insert(x.as_str().unwrap_or_default()))
                    }
            }) {
                Some("required_properties_must_be_unique_bounded_canonical_names".into())
            } else {
                None
            }
        }
        "format" if field.value_type == KnowledgeValueType::String => {
            match c.parameters.get("format").and_then(Value::as_str) {
                Some("uri" | "sha256" | "utc_timestamp") => None,
                _ => Some("string_format_not_supported".into()),
            }
        }
        _ => Some("constraint_not_applicable_to_field_type".into()),
    };
    err
}
fn normalized_schema(input: &KnowledgeSchemaInput) -> NormalizedKnowledgeSchema {
    let mut fields = input.fields.clone();
    fields.sort_by(|a, b| a.field_id.cmp(&b.field_id));
    let mut constraints = input.constraints.clone();
    constraints.sort_by(|a, b| a.constraint_id.cmp(&b.constraint_id));
    NormalizedKnowledgeSchema {
        schema_id: format!(
            "urn:iroka:knowledge-schema:{}:{}",
            input.knowledge_type, input.schema_version
        ),
        knowledge_type: input.knowledge_type.clone(),
        schema_version: input.schema_version.clone(),
        fields,
        constraints,
        closed_object: true,
    }
}
/// Validate schema definitions and their bounded constraint vocabulary. No expression is executed.
pub fn evaluate_knowledge_schema(
    input: &KnowledgeSchemaInput,
    policy: &KnowledgeSchemaPolicy,
) -> KnowledgeSchemaOutput {
    let mut errors = Vec::new();
    if !valid_slug(&input.knowledge_type)
        || !policy
            .allowed_knowledge_types
            .contains(&input.knowledge_type)
    {
        errors.push("knowledge_type_not_approved_or_noncanonical".into());
    }
    if !valid_semver(&input.schema_version) {
        errors.push("schema_version_not_canonical_semver".into());
    }
    if input.fields.is_empty() || input.fields.len() > policy.maximum_fields {
        errors.push("field_count_outside_policy".into());
    }
    if input.constraints.len() > policy.maximum_constraints {
        errors.push("constraint_count_exceeds_policy".into());
    }
    if input.provenance.is_empty() || input.version_bound_evidence.is_empty() {
        errors.push("provenance_or_version_evidence_missing".into());
    }
    let mut field_ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for f in &input.fields {
        if !valid_slug(&f.field_id) || f.name.trim().is_empty() || f.description.trim().is_empty() {
            errors.push(format!("field_malformed:{}", f.field_id));
        }
        if !field_ids.insert(f.field_id.as_str()) || !names.insert(f.name.to_lowercase()) {
            errors.push(format!("field_id_or_name_duplicate:{}", f.field_id));
        }
    }
    let fields: BTreeMap<_, _> = input
        .fields
        .iter()
        .map(|f| (f.field_id.as_str(), f))
        .collect();
    let mut constraint_ids = BTreeSet::new();
    let mut field_constraint_kinds = BTreeSet::new();
    for c in &input.constraints {
        if !valid_slug(&c.constraint_id) || !constraint_ids.insert(c.constraint_id.as_str()) {
            errors.push(format!(
                "constraint_id_duplicate_or_empty:{}",
                c.constraint_id
            ));
            continue;
        }
        let Some(field) = fields.get(c.field_id.as_str()) else {
            errors.push(format!("constraint_field_unresolved:{}", c.constraint_id));
            continue;
        };
        if !field_constraint_kinds.insert((c.field_id.as_str(), c.constraint_type.as_str())) {
            errors.push(format!(
                "constraint_type_duplicate_for_field:{}:{}",
                c.field_id, c.constraint_type
            ));
        }
        if let Some(e) = constraint_error(c, field, policy) {
            errors.push(format!("{}:{}", c.constraint_id, e));
        }
    }
    errors.extend(cross_bound_errors(&input.constraints));
    for f in &input.fields {
        let kinds: BTreeSet<_> = input
            .constraints
            .iter()
            .filter(|c| c.field_id == f.field_id)
            .map(|c| c.constraint_type.as_str())
            .collect();
        if f.value_type == KnowledgeValueType::String && !kinds.contains("max_length") {
            errors.push(format!(
                "string_field_requires_bounded_max_length:{}",
                f.field_id
            ));
        }
        if f.value_type == KnowledgeValueType::Array
            && (!kinds.contains("item_type") || !kinds.contains("max_items"))
        {
            errors.push(format!(
                "array_field_requires_item_type_and_max_items:{}",
                f.field_id
            ));
        }
        if f.value_type == KnowledgeValueType::Object
            && (!kinds.contains("closed_object") || !kinds.contains("max_properties"))
        {
            errors.push(format!(
                "object_field_requires_closed_object_and_max_properties:{}",
                f.field_id
            ));
        }
    }
    let normalized = normalized_schema(input);
    let schema_bytes = canonical(&normalized).unwrap_or_default();
    let schema_digest = digest(&schema_bytes);
    let provenance_digest = canonical(&input.provenance)
        .map(|b| digest(&b))
        .unwrap_or_default();
    let version_digest = canonical(&input.version_bound_evidence)
        .map(|b| digest(&b))
        .unwrap_or_default();
    let valid = errors.is_empty();
    KnowledgeSchemaOutput {
        schema_id: normalized.schema_id.clone(),
        normalized_schema: normalized,
        schema_digest: schema_digest.clone(),
        validation_status: if valid { "valid" } else { "invalid" }.into(),
        validation_errors: errors,
        evidence: KnowledgeSchemaEvidence {
            field_count: input.fields.len() as u64,
            constraint_count: input.constraints.len() as u64,
            schema_digest,
            provenance_digest,
            version_bound_evidence_digest: version_digest,
            closed_object: true,
            constraint_language: "iroka-knowledge-constraints-v1".into(),
            decision_reason: if valid {
                "schema_definition_validated"
            } else {
                "schema_definition_rejected"
            }
            .into(),
        },
        version_bound_evidence: input.version_bound_evidence.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn constraint(
        id: &str,
        field: &str,
        kind: &str,
        params: BTreeMap<String, Value>,
    ) -> KnowledgeConstraint {
        let mut bytes = b"IROKA-KNOWLEDGE-CONSTRAINT-PARAMETERS-V1\0".to_vec();
        bytes.extend(canonical(&params).unwrap());
        KnowledgeConstraint {
            constraint_id: id.into(),
            field_id: field.into(),
            constraint_type: kind.into(),
            expression: format!("field.{kind}"),
            parameters: params,
            parameters_digest: digest(&bytes),
        }
    }
    fn fixture() -> (KnowledgeSchemaInput, KnowledgeSchemaPolicy) {
        let fields = vec![
            KnowledgeFieldDefinition {
                field_id: "title".into(),
                name: "title".into(),
                value_type: KnowledgeValueType::String,
                required: true,
                nullable: false,
                description: "Knowledge title".into(),
            },
            KnowledgeFieldDefinition {
                field_id: "year".into(),
                name: "year".into(),
                value_type: KnowledgeValueType::Integer,
                required: false,
                nullable: true,
                description: "Publication year".into(),
            },
        ];
        let constraints = vec![
            constraint(
                "title-min",
                "title",
                "min_length",
                BTreeMap::from([("value".into(), serde_json::json!(1))]),
            ),
            constraint(
                "title-max",
                "title",
                "max_length",
                BTreeMap::from([("value".into(), serde_json::json!(256))]),
            ),
            constraint(
                "year-min",
                "year",
                "minimum",
                BTreeMap::from([("value".into(), serde_json::json!(1800))]),
            ),
        ];
        let input = KnowledgeSchemaInput {
            knowledge_type: "book".into(),
            fields,
            constraints,
            schema_version: "1.0.0".into(),
            provenance: BTreeMap::from([("owner".into(), serde_json::json!("synthetic"))]),
            version_bound_evidence: BTreeMap::from([(
                "genome_digest".into(),
                serde_json::json!("a".repeat(64)),
            )]),
        };
        let policy = KnowledgeSchemaPolicy::new(
            ["book".into()].into_iter().collect(),
            [
                "min_length".into(),
                "minimum".into(),
                "maximum".into(),
                "max_length".into(),
                "enum".into(),
                "min_items".into(),
                "max_items".into(),
                "item_type".into(),
                "closed_object".into(),
                "min_properties".into(),
                "max_properties".into(),
                "required_properties".into(),
                "format".into(),
            ]
            .into_iter()
            .collect(),
            128,
            512,
            4096,
        );
        (input, policy)
    }
    #[test]
    fn validates_and_digests_canonical_schema() {
        let (i, p) = fixture();
        let o = evaluate_knowledge_schema(&i, &p);
        assert_eq!(o.validation_status, "valid");
        assert_eq!(o.normalized_schema.fields[0].field_id, "title");
        assert_eq!(o.schema_digest.len(), 64);
        assert!(o.normalized_schema.closed_object);
    }
    #[test]
    fn rejects_duplicate_fields_unresolved_constraints_and_bad_digest() {
        let (i, p) = fixture();
        let mut bad = i.clone();
        bad.fields[1].name = "title".into();
        assert_eq!(
            evaluate_knowledge_schema(&bad, &p).validation_status,
            "invalid"
        );
        let mut bad = i.clone();
        bad.constraints[0].field_id = "missing".into();
        assert!(evaluate_knowledge_schema(&bad, &p)
            .validation_errors
            .iter()
            .any(|e| e.contains("constraint_field_unresolved")));
        let mut bad = i;
        bad.constraints[0].parameters_digest = "f".repeat(64);
        assert!(evaluate_knowledge_schema(&bad, &p)
            .validation_errors
            .iter()
            .any(|e| e.contains("parameters_digest_mismatch")));
    }
    #[test]
    fn rejects_executable_constraints_and_unbounded_arrays() {
        let (i, p) = fixture();
        let mut bad = i.clone();
        bad.constraints[0].expression = "exec(system)".into();
        assert!(evaluate_knowledge_schema(&bad, &p)
            .validation_errors
            .iter()
            .any(|e| e.contains("non_executable_grammar")));
        let (mut bad, p) = fixture();
        bad.fields.push(KnowledgeFieldDefinition {
            field_id: "tags".into(),
            name: "tags".into(),
            value_type: KnowledgeValueType::Array,
            required: false,
            nullable: false,
            description: "Tags".into(),
        });
        assert!(evaluate_knowledge_schema(&bad, &p)
            .validation_errors
            .iter()
            .any(|e| e.contains("array_field_requires_item_type_and_max_items")));
    }
    #[test]
    fn rejects_type_incompatible_integer_decimal_bounds() {
        let (mut i, p) = fixture();
        i.constraints.push(constraint(
            "year-max",
            "year",
            "maximum",
            BTreeMap::from([("value".into(), serde_json::json!(2025.5))]),
        ));
        assert!(evaluate_knowledge_schema(&i, &p)
            .validation_errors
            .iter()
            .any(|e| e.contains("type_compatible_finite_number")));
    }
    #[test]
    fn rejects_unbounded_strings_and_excessive_enum_values() {
        let (mut i, p) = fixture();
        i.constraints.retain(|c| c.constraint_id != "title-max");
        assert!(evaluate_knowledge_schema(&i, &p)
            .validation_errors
            .iter()
            .any(|e| e.contains("string_field_requires_bounded_max_length")));
        let mut i = fixture().0;
        i.constraints.push(constraint(
            "title-enum",
            "title",
            "enum",
            BTreeMap::from([(
                "values".into(),
                serde_json::json!(["a", "b", "c", "d", "e"]),
            )]),
        ));
        let mut p = fixture().1;
        p.maximum_collection_size = 4;
        assert!(evaluate_knowledge_schema(&i, &p)
            .validation_errors
            .iter()
            .any(|e| e.contains("enum_requires_unique_nonempty_string_values")));
    }
    #[test]
    fn rejects_duplicate_constraint_kinds_and_inverted_bounds() {
        let (mut i, p) = fixture();
        i.constraints.push(constraint(
            "title-min-2",
            "title",
            "min_length",
            BTreeMap::from([("value".into(), serde_json::json!(2))]),
        ));
        assert!(evaluate_knowledge_schema(&i, &p)
            .validation_errors
            .iter()
            .any(|e| e.contains("constraint_type_duplicate_for_field")));
        let (mut i, p) = fixture();
        i.constraints.push(constraint(
            "title-max-small",
            "title",
            "max_length",
            BTreeMap::from([("value".into(), serde_json::json!(0))]),
        ));
        assert!(evaluate_knowledge_schema(&i, &p)
            .validation_errors
            .iter()
            .any(|e| e.contains("constraint_bounds_inverted")));
    }
    #[test]
    fn rejects_invalid_required_property_names() {
        let (mut i, p) = fixture();
        i.fields.push(KnowledgeFieldDefinition {
            field_id: "meta".into(),
            name: "meta".into(),
            value_type: KnowledgeValueType::Object,
            required: false,
            nullable: false,
            description: "Metadata".into(),
        });
        i.constraints.push(constraint(
            "meta-closed",
            "meta",
            "closed_object",
            BTreeMap::from([("allow_unknown".into(), serde_json::json!(false))]),
        ));
        i.constraints.push(constraint(
            "meta-max",
            "meta",
            "max_properties",
            BTreeMap::from([("value".into(), serde_json::json!(4))]),
        ));
        i.constraints.push(constraint(
            "meta-required",
            "meta",
            "required_properties",
            BTreeMap::from([(
                "names".into(),
                serde_json::json!(["valid_name", "Invalid Name"]),
            )]),
        ));
        assert!(evaluate_knowledge_schema(&i, &p)
            .validation_errors
            .iter()
            .any(|e| e.contains("required_properties_must_be_unique_bounded_canonical_names")));
    }
}
