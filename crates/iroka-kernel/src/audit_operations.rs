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
        Some(_) => return AnchoringAssessment {
            state: AnchoringState::ClockAnomaly,
            high_risk_operations_allowed: false,
            age_seconds: None,
            unanchored_events,
        },
        None => None,
    };
    if !quorum_available {
        return AnchoringAssessment { state: AnchoringState::QuorumUnavailable,
            high_risk_operations_allowed: false, age_seconds: age, unanchored_events };
    }
    let max_age = match policy.max_staleness_seconds {
        Some(v) => v,
        None => return AnchoringAssessment { state: AnchoringState::Unconfigured,
            high_risk_operations_allowed: false, age_seconds: age, unanchored_events },
    };
    let age_value = match age {
        Some(v) => v,
        None => return AnchoringAssessment { state: AnchoringState::Stale,
            high_risk_operations_allowed: false, age_seconds: None, unanchored_events },
    };
    if age_value > max_age
        || policy.max_unanchored_events.map(|limit| unanchored_events > limit).unwrap_or(false)
    {
        return AnchoringAssessment { state: AnchoringState::Stale,
            high_risk_operations_allowed: false, age_seconds: age, unanchored_events };
    }
    AnchoringAssessment { state: AnchoringState::Healthy,
        high_risk_operations_allowed: true, age_seconds: age, unanchored_events }
}

pub fn checkpoint_due(
    policy: CheckpointPolicy,
    elapsed_since_quorum_seconds: u64,
    unanchored_events: u64,
) -> bool {
    policy.max_staleness_seconds.map(|v| elapsed_since_quorum_seconds >= v).unwrap_or(false)
        || policy.max_unanchored_events.map(|v| unanchored_events >= v).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_threshold_blocks_high_risk_instead_of_using_default() {
        let a = assess_anchoring(CheckpointPolicy { max_staleness_seconds: None,
            max_unanchored_events: None }, 100, Some(99), 0, true);
        assert_eq!(a.state, AnchoringState::Unconfigured);
        assert!(!a.high_risk_operations_allowed);
    }

    #[test]
    fn stale_checkpoint_blocks_high_risk_but_keeps_count_visible() {
        let a = assess_anchoring(CheckpointPolicy { max_staleness_seconds: Some(30),
            max_unanchored_events: Some(100) }, 140, Some(100), 12, true);
        assert_eq!(a.state, AnchoringState::Stale);
        assert!(!a.high_risk_operations_allowed);
        assert_eq!(a.unanchored_events, 12);
    }

    #[test]
    fn witness_outage_is_not_misreported_as_healthy() {
        let a = assess_anchoring(CheckpointPolicy { max_staleness_seconds: Some(60),
            max_unanchored_events: Some(100) }, 120, Some(100), 2, false);
        assert_eq!(a.state, AnchoringState::QuorumUnavailable);
        assert!(!a.high_risk_operations_allowed);
    }

    #[test]
    fn due_trigger_supports_time_or_event_count() {
        let p = CheckpointPolicy { max_staleness_seconds: Some(60), max_unanchored_events: Some(50) };
        assert!(checkpoint_due(p, 10, 50));
        assert!(checkpoint_due(p, 60, 1));
        assert!(!checkpoint_due(p, 10, 1));
    }
}
