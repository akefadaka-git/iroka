//! Mandatory per-subject and per-tenant request budgets.
//! No default/unlimited configuration exists; callers must construct this
//! guard from a verified signed policy snapshot.

use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::Instant,
};

use crate::{BudgetLimits, ConversationError};

#[derive(Default)]
struct BudgetState {
    active_subject: HashMap<String, u32>,
    active_tenant: HashMap<String, u32>,
    requests_subject: HashMap<String, VecDeque<u64>>,
    requests_tenant: HashMap<String, VecDeque<u64>>,
    spend_subject: HashMap<(String, u64), u64>,
    spend_tenant: HashMap<(String, u64), u64>,
}

pub struct BudgetGuard {
    limits: BudgetLimits,
    state: Mutex<BudgetState>,
}

impl BudgetGuard {
    pub fn from_verified_limits(limits: &BudgetLimits) -> Result<Self, ConversationError> {
        if !limits.is_valid() {
            return Err(ConversationError::BudgetExceeded);
        }
        Ok(Self {
            limits: limits.clone(),
            state: Mutex::new(BudgetState::default()),
        })
    }

    pub fn validate_retry_attempt(&self, attempt: u32) -> Result<(), ConversationError> {
        if attempt == 0 || attempt > self.limits.max_retries {
            return Err(ConversationError::BudgetExceeded);
        }
        Ok(())
    }

    pub fn reserve<'a>(
        &'a self,
        subject: &str,
        tenant: &str,
        input_bytes: u64,
        now: u64,
    ) -> Result<BudgetReservation<'a>, ConversationError> {
        if subject.trim().is_empty()
            || tenant.trim().is_empty()
            || input_bytes == 0
            || input_bytes > self.limits.max_input_bytes
        {
            return Err(ConversationError::BudgetExceeded);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| ConversationError::BudgetExceeded)?;
        let subject_active = *state.active_subject.get(subject).unwrap_or(&0);
        let tenant_active = *state.active_tenant.get(tenant).unwrap_or(&0);
        if subject_active >= self.limits.max_concurrent_per_subject
            || tenant_active >= self.limits.max_concurrent_per_tenant
        {
            return Err(ConversationError::BudgetExceeded);
        }

        let subject_request_count = {
            let requests = state
                .requests_subject
                .entry(subject.to_owned())
                .or_default();
            Self::prune_window(requests, now)?;
            requests.len()
        };
        let tenant_request_count = {
            let requests = state.requests_tenant.entry(tenant.to_owned()).or_default();
            Self::prune_window(requests, now)?;
            requests.len()
        };
        if subject_request_count >= self.limits.requests_per_minute as usize
            || tenant_request_count >= self.limits.requests_per_minute as usize
        {
            return Err(ConversationError::BudgetExceeded);
        }
        state
            .requests_subject
            .entry(subject.to_owned())
            .or_default()
            .push_back(now);
        state
            .requests_tenant
            .entry(tenant.to_owned())
            .or_default()
            .push_back(now);
        *state.active_subject.entry(subject.to_owned()).or_default() += 1;
        *state.active_tenant.entry(tenant.to_owned()).or_default() += 1;

        Ok(BudgetReservation {
            guard: self,
            subject: subject.to_owned(),
            tenant: tenant.to_owned(),
            day: now / 86_400,
            started: Instant::now(),
        })
    }

    fn prune_window(queue: &mut VecDeque<u64>, now: u64) -> Result<(), ConversationError> {
        if queue.back().is_some_and(|last| now < *last) {
            return Err(ConversationError::BudgetExceeded);
        }
        while queue
            .front()
            .is_some_and(|stamp| now.saturating_sub(*stamp) >= 60)
        {
            queue.pop_front();
        }
        Ok(())
    }
}

pub struct BudgetReservation<'a> {
    guard: &'a BudgetGuard,
    subject: String,
    tenant: String,
    day: u64,
    started: Instant,
}

impl BudgetReservation<'_> {
    pub fn finish(
        &self,
        output_tokens: u32,
        spend_micro_units: u64,
    ) -> Result<(), ConversationError> {
        if output_tokens == 0
            || output_tokens > self.guard.limits.max_output_tokens
            || self.started.elapsed().as_millis() > self.guard.limits.max_wall_clock_ms as u128
        {
            return Err(ConversationError::BudgetExceeded);
        }
        let mut state = self
            .guard
            .state
            .lock()
            .map_err(|_| ConversationError::BudgetExceeded)?;
        let subject_key = (self.subject.clone(), self.day);
        let tenant_key = (self.tenant.clone(), self.day);
        let subject_spend = *state.spend_subject.get(&subject_key).unwrap_or(&0);
        let tenant_spend = *state.spend_tenant.get(&tenant_key).unwrap_or(&0);
        if subject_spend.saturating_add(spend_micro_units)
            > self.guard.limits.max_spend_micro_units_per_day
            || tenant_spend.saturating_add(spend_micro_units)
                > self.guard.limits.max_spend_micro_units_per_day
        {
            return Err(ConversationError::BudgetExceeded);
        }
        *state.spend_subject.entry(subject_key).or_default() += spend_micro_units;
        *state.spend_tenant.entry(tenant_key).or_default() += spend_micro_units;
        Ok(())
    }
}

impl Drop for BudgetReservation<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.guard.state.lock() {
            if let Some(active) = state.active_subject.get_mut(&self.subject) {
                *active = active.saturating_sub(1);
                if *active == 0 {
                    state.active_subject.remove(&self.subject);
                }
            }
            if let Some(active) = state.active_tenant.get_mut(&self.tenant) {
                *active = active.saturating_sub(1);
                if *active == 0 {
                    state.active_tenant.remove(&self.tenant);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> BudgetLimits {
        BudgetLimits {
            max_input_bytes: 100,
            max_output_tokens: 20,
            max_concurrent_per_subject: 1,
            max_concurrent_per_tenant: 2,
            requests_per_minute: 2,
            max_wall_clock_ms: 5_000,
            max_retries: 1,
            max_spend_micro_units_per_day: 10,
        }
    }

    #[test]
    fn rejects_input_and_missing_or_invalid_limits() {
        let mut invalid = limits();
        invalid.max_output_tokens = 0;
        assert!(BudgetGuard::from_verified_limits(&invalid).is_err());
        let guard = BudgetGuard::from_verified_limits(&limits()).unwrap();
        assert!(guard.reserve("s1", "t1", 101, 100).is_err());
    }

    #[test]
    fn enforces_concurrency_rate_output_and_daily_spend() {
        let mut config = limits();
        config.requests_per_minute = 1;
        let guard = BudgetGuard::from_verified_limits(&config).unwrap();
        let permit = guard.reserve("s1", "t1", 10, 100).unwrap();
        assert!(guard.reserve("s1", "t1", 10, 100).is_err());
        assert!(permit.finish(21, 0).is_err());
        assert!(permit.finish(10, 11).is_err());
        permit.finish(10, 5).unwrap();
        drop(permit);
        assert!(guard.reserve("s1", "t1", 10, 120).is_err());
        let next = guard.reserve("s1", "t1", 10, 160).unwrap();
        next.finish(10, 5).unwrap();
    }

    #[test]
    fn retry_count_is_bounded_by_signed_configuration() {
        let guard = BudgetGuard::from_verified_limits(&limits()).unwrap();
        assert!(guard.validate_retry_attempt(1).is_ok());
        assert!(guard.validate_retry_attempt(2).is_err());
    }
}
