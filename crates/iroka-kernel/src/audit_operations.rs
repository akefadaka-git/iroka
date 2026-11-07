//! K-04 operational freshness and degraded-mode policy.
//! Missing production thresholds are explicit UNCONFIGURED states, never permissive defaults.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointPolicy {
    pub max_staleness_seconds: Option<u64>,
    pub max_unanchored_events: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchoringState {
    Healthy,
    Stale,
    Unconfigured,
    QuorumUnavailable,
    ClockAnomaly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualCheckpointRequest {
    pub request_id: String,
    pub requested_by: String,
    pub reason: String,
    pub requested_at: u64,
}

impl ManualCheckpointRequest {
    pub fn validate(&self) -> bool {
        !self.request_id.trim().is_empty()
            && self.request_id.len() <= 256
            && !self.requested_by.trim().is_empty()
            && self.requested_by.len() <= 256
            && !self.reason.trim().is_empty()
            && self.reason.len() <= 1024
    }

    pub fn validate_at(&self, now: u64) -> bool {
        self.validate()
            && self.requested_at <= now.saturating_add(30)
            && now.saturating_sub(self.requested_at) <= 900
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualCheckpointError {
    MalformedRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchoringAssessment {
    pub state: AnchoringState,
    pub high_risk_operations_allowed: bool,
    pub age_seconds: Option<u64>,
    pub unanchored_events: u64,
}

pub fn assess_anchoring(
    policy: CheckpointPolicy,
    now: u64,
    last_quorum_checkpoint_at: Option<u64>,
    unanchored_events: u64,
    quorum_available: bool,
) -> AnchoringAssessment {
    let age = match last_quorum_checkpoint_at {
        Some(t) if now >= t => Some(now - t),
        Some(_) => {
            return AnchoringAssessment {
                state: AnchoringState::ClockAnomaly,
                high_risk_operations_allowed: false,
                age_seconds: None,
                unanchored_events,
            }
        }
        None => None,
    };
    let max_age = match policy.max_staleness_seconds {
        Some(v) if v > 0 => v,
        _ => {
            return AnchoringAssessment {
                state: AnchoringState::Unconfigured,
                high_risk_operations_allowed: false,
                age_seconds: age,
                unanchored_events,
            }
        }
    };
    let max_events = match policy.max_unanchored_events {
        Some(v) if v > 0 => v,
        _ => {
            return AnchoringAssessment {
                state: AnchoringState::Unconfigured,
                high_risk_operations_allowed: false,
                age_seconds: age,
                unanchored_events,
            };
        }
    };
    let age_value = match age {
        Some(v) => v,
        None => {
            return AnchoringAssessment {
                state: AnchoringState::Stale,
                high_risk_operations_allowed: false,
                age_seconds: None,
                unanchored_events,
            }
        }
    };
    if age_value > max_age || unanchored_events > max_events {
        return AnchoringAssessment {
            state: AnchoringState::Stale,
            high_risk_operations_allowed: false,
            age_seconds: age,
            unanchored_events,
        };
    }
    if !quorum_available {
        return AnchoringAssessment {
            state: AnchoringState::QuorumUnavailable,
            high_risk_operations_allowed: false,
            age_seconds: age,
            unanchored_events,
        };
    }
    AnchoringAssessment {
        state: AnchoringState::Healthy,
        high_risk_operations_allowed: true,
        age_seconds: age,
        unanchored_events,
    }
}

pub fn checkpoint_due(
    policy: CheckpointPolicy,
    elapsed_since_quorum_seconds: u64,
    unanchored_events: u64,
) -> bool {
    let (Some(max_age), Some(max_events)) =
        (policy.max_staleness_seconds, policy.max_unanchored_events)
    else {
        // Missing controls must be surfaced immediately, not silently disable scheduling.
        return true;
    };
    max_age == 0
        || max_events == 0
        || elapsed_since_quorum_seconds >= max_age
        || unanchored_events >= max_events
}

/// Manual checkpoint requests are explicit and attributable. The caller must authorize the requester.
pub fn checkpoint_due_with_manual_request(
    policy: CheckpointPolicy,
    elapsed_since_quorum_seconds: u64,
    unanchored_events: u64,
    request: Option<&ManualCheckpointRequest>,
    now: u64,
) -> Result<bool, ManualCheckpointError> {
    if let Some(request) = request {
        if !request.validate_at(now) {
            return Err(ManualCheckpointError::MalformedRequest);
        }
        return Ok(true);
    }
    Ok(checkpoint_due(
        policy,
        elapsed_since_quorum_seconds,
        unanchored_events,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_threshold_blocks_high_risk_instead_of_using_default() {
        let a = assess_anchoring(
            CheckpointPolicy {
                max_staleness_seconds: None,
                max_unanchored_events: None,
            },
            100,
            Some(99),
            0,
            true,
        );
        assert_eq!(a.state, AnchoringState::Unconfigured);
        assert!(!a.high_risk_operations_allowed);
    }

    #[test]
    fn stale_checkpoint_blocks_high_risk_but_keeps_count_visible() {
        let a = assess_anchoring(
            CheckpointPolicy {
                max_staleness_seconds: Some(30),
                max_unanchored_events: Some(100),
            },
            140,
            Some(100),
            12,
            true,
        );
        assert_eq!(a.state, AnchoringState::Stale);
        assert!(!a.high_risk_operations_allowed);
        assert_eq!(a.unanchored_events, 12);
    }

    #[test]
    fn witness_outage_is_not_misreported_as_healthy() {
        let a = assess_anchoring(
            CheckpointPolicy {
                max_staleness_seconds: Some(60),
                max_unanchored_events: Some(100),
            },
            120,
            Some(100),
            2,
            false,
        );
        assert_eq!(a.state, AnchoringState::QuorumUnavailable);
        assert!(!a.high_risk_operations_allowed);
        assert_eq!(a.state, AnchoringState::QuorumUnavailable);
    }

    #[test]
    fn witness_outage_after_freshness_limit_blocks_high_risk() {
        let a = assess_anchoring(
            CheckpointPolicy {
                max_staleness_seconds: Some(10),
                max_unanchored_events: Some(100),
            },
            120,
            Some(100),
            2,
            false,
        );
        assert_eq!(a.state, AnchoringState::Stale);
        assert!(!a.high_risk_operations_allowed);
    }

    #[test]
    fn either_missing_threshold_is_unconfigured_and_forces_checkpoint_due() {
        let a = assess_anchoring(
            CheckpointPolicy {
                max_staleness_seconds: Some(60),
                max_unanchored_events: None,
            },
            100,
            Some(99),
            0,
            true,
        );
        assert_eq!(a.state, AnchoringState::Unconfigured);
        assert!(!a.high_risk_operations_allowed);
        assert!(checkpoint_due(
            CheckpointPolicy {
                max_staleness_seconds: Some(60),
                max_unanchored_events: None,
            },
            1,
            0
        ));
    }

    #[test]
    fn manual_checkpoint_request_forces_checkpoint_and_requires_attribution() {
        let policy = CheckpointPolicy {
            max_staleness_seconds: Some(60),
            max_unanchored_events: Some(100),
        };
        let valid = ManualCheckpointRequest {
            request_id: "request:1".into(),
            requested_by: "principal:owner".into(),
            reason: "pre-maintenance anchor".into(),
            requested_at: 100,
        };
        assert_eq!(
            checkpoint_due_with_manual_request(policy, 1, 1, Some(&valid), 100),
            Ok(true)
        );
        let invalid = ManualCheckpointRequest {
            reason: " ".into(),
            ..valid
        };
        assert_eq!(
            checkpoint_due_with_manual_request(policy, 1, 1, Some(&invalid), 100),
            Err(ManualCheckpointError::MalformedRequest)
        );
    }

    #[test]
    fn due_trigger_supports_time_or_event_count() {
        let p = CheckpointPolicy {
            max_staleness_seconds: Some(60),
            max_unanchored_events: Some(50),
        };
        assert!(checkpoint_due(p, 10, 50));
        assert!(checkpoint_due(p, 60, 1));
        assert!(!checkpoint_due(p, 10, 1));
    }
}
