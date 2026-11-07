//! Machine-readable A2 conformance catalog validator and executable adapter registry.
//! Unimplemented cases remain BLOCKED; catalog presence is never treated as a pass.

use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    assess_anchoring, record_decision, AnchoringState, AuditError, AuditEvent, AuditSink,
    CheckpointPolicy, Decision, DecisionCode, DecisionReason, SqliteSecurityStore,
};

pub const CONFORMANCE_HARNESS_VERSION: &str = "0.1.0";
pub const REQUIRED_CASE_COUNT: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaseStatus {
    Pass,
    Fail,
    Blocked,
    NotRun,
    NotApplicable,
}

impl CaseStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Blocked => "BLOCKED",
            Self::NotRun => "NOT RUN",
            Self::NotApplicable => "NOT APPLICABLE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CaseOutcome {
    status: CaseStatus,
    reason_code: &'static str,
    detail: &'static str,
}

fn execute_registered_case(test_id: &str) -> Option<CaseOutcome> {
    match test_id {
        "OS-BOOT-003" => {
            let store = match SqliteSecurityStore::open_in_memory() {
                Ok(store) => store,
                Err(_) => {
                    return Some(CaseOutcome {
                        status: CaseStatus::Fail,
                        reason_code: "FIXTURE_STORE_UNAVAILABLE",
                        detail: "The synthetic trust-store fixture could not be initialized.",
                    });
                }
            };
            let digest = [0xA5; 32];
            let installed = store.install_trust_bundle(2, &digest, 100, 200, 110);
            let rollback = store.install_trust_bundle(1, &digest, 100, 200, 120);
            if installed.is_ok()
                && matches!(rollback, Err(crate::SecurityStoreError::Rollback))
            {
                Some(CaseOutcome {
                    status: CaseStatus::Pass,
                    reason_code: "ROLLBACK_REJECTED",
                    detail: "The durable trust store rejected a lower version after version 2 was installed.",
                })
            } else {
                Some(CaseOutcome {
                    status: CaseStatus::Fail,
                    reason_code: "ROLLBACK_NOT_REJECTED",
                    detail: "The trust store did not enforce monotonic version installation.",
                })
            }
        }
        "OS-AUD-001" => {
            struct FailingAuditSink;
            impl AuditSink for FailingAuditSink {
                fn append(&self, _event: &AuditEvent) -> Result<(), AuditError> {
                    Err(AuditError::Unavailable)
                }
            }
            let event = AuditEvent::new(
                "conformance:os-aud-001",
                "conformance:trace",
                "synthetic:principal",
                "synthetic:protected-effect",
                "synthetic:resource",
                "conformance-policy-v1",
                DecisionCode::Allow,
                1_000,
            );
            let proposed = Decision::new(
                DecisionCode::Allow,
                DecisionReason::PolicySatisfied,
                "conformance-policy-v1",
            );
            let actual = record_decision(&FailingAuditSink, &event, proposed);
            if actual.code() == DecisionCode::Escalate
                && actual.reason() == DecisionReason::AuditUnavailable
            {
                Some(CaseOutcome {
                    status: CaseStatus::Pass,
                    reason_code: "AUDIT_FAILURE_ESCALATED",
                    detail: "An unavailable audit sink converts the proposed Allow decision to Escalate; protected callers must not execute on Escalate.",
                })
            } else {
                Some(CaseOutcome {
                    status: CaseStatus::Fail,
                    reason_code: "AUDIT_FAILURE_NOT_ESCALATED",
                    detail: "An unavailable audit sink did not produce the required escalation decision.",
                })
            }
        }
        "OS-TIME-001" => {
            let assessment = assess_anchoring(
                CheckpointPolicy {
                    max_staleness_seconds: Some(60),
                    max_unanchored_events: Some(100),
                },
                1_000,
                Some(1_001),
                0,
                true,
            );
            if assessment.state == AnchoringState::ClockAnomaly
                && !assessment.high_risk_operations_allowed
            {
                Some(CaseOutcome {
                    status: CaseStatus::Pass,
                    reason_code: "CLOCK_ANOMALY_DENIED",
                    detail: "A future checkpoint timestamp is treated as a clock anomaly and high-risk operations are denied.",
                })
            } else {
                Some(CaseOutcome {
                    status: CaseStatus::Fail,
                    reason_code: "CLOCK_ANOMALY_NOT_DENIED",
                    detail: "A future checkpoint timestamp did not fail closed.",
                })
            }
        }
        _ => None,
    }
}

fn validate_catalog(catalog: &Value) -> Result<&Vec<Value>, String> {
    let object = catalog
        .as_object()
        .ok_or_else(|| "catalog root must be a JSON object".to_owned())?;
    if object.get("schema_version").and_then(Value::as_str) != Some("1.0.0") {
        return Err("unsupported conformance catalog schema_version".into());
    }
    if object.get("contract_id").and_then(Value::as_str)
        != Some("IROKA-A2-CONFORMANCE-001")
    {
        return Err("unexpected conformance contract_id".into());
    }
    if object.get("zero_tolerance").and_then(Value::as_bool) != Some(true) {
        return Err("zero_tolerance must be true".into());
    }
    let cases = object
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| "catalog cases must be an array".to_owned())?;
    if cases.len() != REQUIRED_CASE_COUNT {
        return Err(format!(
            "expected {REQUIRED_CASE_COUNT} conformance cases, found {}",
            cases.len()
        ));
    }
    let mut ids = BTreeSet::new();
    for case in cases {
        let id = case
            .get("test_id")
            .and_then(Value::as_str)
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| "case missing non-empty test_id".to_owned())?;
        if !ids.insert(id.to_owned()) {
            return Err(format!("duplicate test_id: {id}"));
        }
        for field in ["suite", "test_class", "title", "expected_result", "severity"] {
            if case.get(field).and_then(Value::as_str).is_none() {
                return Err(format!("{id}: missing string field {field}"));
            }
        }
        let requirements = case
            .get("requirement_ids")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{id}: requirement_ids must be an array"))?;
        if requirements.is_empty()
            || requirements.iter().any(|value| {
                value.as_str().is_none_or(|text| text.trim().is_empty())
            })
        {
            return Err(format!("{id}: requirement_ids must contain non-empty strings"));
        }
        let status = case
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{id}: status missing"))?;
        if !["PASS", "FAIL", "BLOCKED", "NOT RUN", "NOT APPLICABLE"].contains(&status) {
            return Err(format!("{id}: unsupported status {status}"));
        }
    }
    Ok(cases)
}

/// Validate the frozen 40-case catalog, execute only registered synthetic adapters,
/// and retain every missing fixture/adapter as BLOCKED rather than silently passing.
pub fn build_conformance_report(
    catalog_text: &str,
    metadata: &BTreeMap<String, String>,
    started_at_unix_ms: u128,
    finished_at_unix_ms: u128,
) -> Result<Value, String> {
    let catalog: Value =
        serde_json::from_str(catalog_text).map_err(|_| "catalog JSON is invalid".to_owned())?;
    let cases = validate_catalog(&catalog)?;
    let mut results = Vec::with_capacity(cases.len());
    let mut counts = BTreeMap::<String, usize>::new();

    for case in cases {
        let test_id = case["test_id"].as_str().unwrap_or("UNKNOWN");
        let fixture_ref = case.get("fixture_ref").and_then(Value::as_str);
        let outcome = match fixture_ref {
            None => CaseOutcome {
                status: CaseStatus::Blocked,
                reason_code: "FIXTURE_MISSING",
                detail: "No reviewed or synthetic fixture is registered for this case.",
            },
            Some(_) => execute_registered_case(test_id).unwrap_or(CaseOutcome {
                status: CaseStatus::Blocked,
                reason_code: "EXECUTOR_MISSING",
                detail: "A fixture reference exists, but no executable adapter is registered.",
            }),
        };
        *counts.entry(outcome.status.as_str().to_owned()).or_default() += 1;
        results.push(json!({
            "test_id": test_id,
            "suite": case["suite"],
            "severity": case["severity"],
            "requirement_ids": case["requirement_ids"],
            "expected_result": case["expected_result"],
            "fixture_ref": fixture_ref,
            "status": outcome.status.as_str(),
            "reason_code": outcome.reason_code,
            "detail": outcome.detail,
            "tested_sha": metadata.get("GITHUB_SHA").cloned().unwrap_or_else(|| "UNKNOWN".into()),
            "evidence_ref": metadata.get("GITHUB_RUN_URL").cloned(),
        }));
    }

    let pass = *counts.get("PASS").unwrap_or(&0);
    let fail = *counts.get("FAIL").unwrap_or(&0);
    let blocked = *counts.get("BLOCKED").unwrap_or(&0);
    let not_run = *counts.get("NOT RUN").unwrap_or(&0);
    let not_applicable = *counts.get("NOT APPLICABLE").unwrap_or(&0);
    let gate = if fail > 0 {
        "FAIL"
    } else if blocked > 0 || not_run > 0 {
        "BLOCKED"
    } else if pass + not_applicable == REQUIRED_CASE_COUNT {
        "PASS"
    } else {
        "PARTIAL"
    };

    Ok(json!({
        "report_schema_version": "1.0.0",
        "contract_id": "IROKA-A2-CONFORMANCE-001",
        "harness_version": CONFORMANCE_HARNESS_VERSION,
        "gate_status": gate,
        "zero_tolerance": true,
        "repository": metadata.get("GITHUB_REPOSITORY"),
        "ref": metadata.get("GITHUB_REF"),
        "commit_sha": metadata.get("GITHUB_SHA").cloned().unwrap_or_else(|| "UNKNOWN".into()),
        "workflow": metadata.get("GITHUB_WORKFLOW"),
        "workflow_run_id": metadata.get("GITHUB_RUN_ID"),
        "workflow_run_attempt": metadata.get("GITHUB_RUN_ATTEMPT"),
        "runner_os": metadata.get("RUNNER_OS"),
        "runner_arch": metadata.get("RUNNER_ARCH"),
        "started_at_unix_ms": started_at_unix_ms.to_string(),
        "finished_at_unix_ms": finished_at_unix_ms.to_string(),
        "case_count": REQUIRED_CASE_COUNT,
        "counts": {
            "PASS": pass,
            "FAIL": fail,
            "BLOCKED": blocked,
            "NOT RUN": not_run,
            "NOT APPLICABLE": not_applicable
        },
        "results": results
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CATALOG: &str = include_str!("../../../tests/conformance/catalog.json");

    #[test]
    fn validates_and_dispositions_all_forty_cases_without_false_passes() {
        let report = build_conformance_report(CATALOG, &BTreeMap::new(), 10, 20).unwrap();
        assert_eq!(report["case_count"], REQUIRED_CASE_COUNT);
        assert_eq!(report["gate_status"], "BLOCKED");
        assert_eq!(report["counts"]["PASS"], 3);
        assert_eq!(report["counts"]["BLOCKED"], 37);
        assert_eq!(report["counts"]["FAIL"], 0);
    }

    #[test]
    fn malformed_or_duplicate_catalog_ids_are_rejected() {
        let mut catalog: Value = serde_json::from_str(CATALOG).unwrap();
        let cases = catalog["cases"].as_array_mut().unwrap();
        cases[1]["test_id"] = cases[0]["test_id"].clone();
        assert!(build_conformance_report(
            &catalog.to_string(),
            &BTreeMap::new(),
            10,
            20
        )
        .is_err());
    }

    #[test]
    fn critical_unimplemented_cases_remain_blocked() {
        let report = build_conformance_report(CATALOG, &BTreeMap::new(), 10, 20).unwrap();
        let results = report["results"].as_array().unwrap();
        let critical = results
            .iter()
            .filter(|case| case["severity"] == "critical")
            .collect::<Vec<_>>();
        assert!(!critical.is_empty());
        assert!(critical.iter().all(|case| case["status"] != "PASS"));
    }
}
