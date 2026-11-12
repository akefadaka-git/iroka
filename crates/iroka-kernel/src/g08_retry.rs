//! Deterministic retry policy primitives for the G08 coordinator.
//!
//! This module computes bounded retry eligibility only. It does not persist
//! schedules, enqueue work, execute tasks, or establish trusted time. Durable
//! scheduling and worker integration remain separate A3 work.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryFailureClass {
    TransientStore,
    WorkerUnavailable,
    LeaseExpired,
    InvalidInput,
    AuthorityRejected,
    IntegrityFailure,
    Cancelled,
}

impl RetryFailureClass {
    fn is_retryable(self) -> bool {
        matches!(self, Self::TransientStore | Self::WorkerUnavailable | Self::LeaseExpired)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetrySchedule {
    pub attempts_completed: u32,
    pub not_before: u64,
    pub delay_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryPolicyError {
    InvalidConfiguration,
    InvalidAttemptCount,
    TimestampOverflow,
}

/// A bounded exponential-backoff policy. max_attempts includes the initial
/// execution; 3 permits one initial execution and at most two retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    max_attempts: u32,
    initial_backoff_secs: u64,
    max_backoff_secs: u64,
}

impl RetryPolicy {
    pub const HARD_MAX_ATTEMPTS: u32 = 10;
    pub const HARD_MAX_BACKOFF_SECS: u64 = 3_600;

    pub fn new(max_attempts: u32, initial_backoff_secs: u64, max_backoff_secs: u64)
        -> Result<Self, RetryPolicyError>
    {
        if max_attempts == 0
            || max_attempts > Self::HARD_MAX_ATTEMPTS
            || initial_backoff_secs == 0
            || max_backoff_secs == 0
            || initial_backoff_secs > max_backoff_secs
            || max_backoff_secs > Self::HARD_MAX_BACKOFF_SECS
        {
            return Err(RetryPolicyError::InvalidConfiguration);
        }
        Ok(Self { max_attempts, initial_backoff_secs, max_backoff_secs })
    }

    pub fn max_attempts(self) -> u32 { self.max_attempts }

    /// Returns no schedule for terminal failures or after the attempt budget.
    /// attempts_completed must be at least one (the failed initial attempt).
    pub fn schedule_after_failure(
        self,
        failure: RetryFailureClass,
        attempts_completed: u32,
        now: u64,
    ) -> Result<Option<RetrySchedule>, RetryPolicyError> {
        if attempts_completed == 0 || attempts_completed > self.max_attempts {
            return Err(RetryPolicyError::InvalidAttemptCount);
        }
        if !failure.is_retryable() || attempts_completed >= self.max_attempts {
            return Ok(None);
        }
        let exponent = attempts_completed.saturating_sub(1).min(63);
        let multiplier = 1_u64.checked_shl(exponent).unwrap_or(u64::MAX);
        let delay = self.initial_backoff_secs.saturating_mul(multiplier).min(self.max_backoff_secs);
        let not_before = now.checked_add(delay).ok_or(RetryPolicyError::TimestampOverflow)?;
        Ok(Some(RetrySchedule { attempts_completed, not_before, delay_seconds: delay }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> RetryPolicy { RetryPolicy::new(5, 2, 10).unwrap() }

    #[test]
    fn retry_delay_grows_exponentially_and_is_capped() {
        for (attempt, delay) in [(1, 2), (2, 4), (3, 8), (4, 10)] {
            let schedule = policy().schedule_after_failure(
                RetryFailureClass::TransientStore, attempt, 1_000
            ).unwrap().unwrap();
            assert_eq!(schedule.delay_seconds, delay);
            assert_eq!(schedule.not_before, 1_000 + delay);
        }
    }

    #[test]
    fn attempt_budget_includes_initial_execution() {
        assert_eq!(policy().schedule_after_failure(
            RetryFailureClass::TransientStore, 5, 1_000
        ).unwrap(), None);
    }

    #[test]
    fn permanent_failures_are_never_retried() {
        for failure in [
            RetryFailureClass::InvalidInput,
            RetryFailureClass::AuthorityRejected,
            RetryFailureClass::IntegrityFailure,
            RetryFailureClass::Cancelled,
        ] {
            assert_eq!(policy().schedule_after_failure(failure, 1, 1_000).unwrap(), None);
        }
    }

    #[test]
    fn invalid_attempt_counts_are_rejected() {
        assert_eq!(policy().schedule_after_failure(
            RetryFailureClass::TransientStore, 0, 1_000
        ), Err(RetryPolicyError::InvalidAttemptCount));
        assert_eq!(policy().schedule_after_failure(
            RetryFailureClass::TransientStore, 6, 1_000
        ), Err(RetryPolicyError::InvalidAttemptCount));
    }

    #[test]
    fn timestamp_overflow_fails_closed() {
        assert_eq!(policy().schedule_after_failure(
            RetryFailureClass::TransientStore, 1, u64::MAX
        ), Err(RetryPolicyError::TimestampOverflow));
    }

    #[test]
    fn policy_configuration_is_hard_bounded() {
        assert_eq!(RetryPolicy::new(11, 1, 10), Err(RetryPolicyError::InvalidConfiguration));
        assert_eq!(RetryPolicy::new(3, 1, 3_601), Err(RetryPolicyError::InvalidConfiguration));
        assert_eq!(RetryPolicy::new(3, 4, 3), Err(RetryPolicyError::InvalidConfiguration));
    }
}
