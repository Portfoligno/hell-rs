//! Thread-safe shared work and live-resource accounting.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use crate::policy::{Limit, RuntimePolicy};
use crate::{RuntimeError, RuntimeResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetKind {
    EvaluatorSteps,
    Allocations,
    LiveThunks,
    MaterializedElements,
    CapturedBytes,
    Tasks,
    Handles,
    Processes,
    HttpConnections,
    TempResources,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BudgetSnapshot {
    pub evaluator_steps: u64,
    pub allocations: u64,
    pub live_thunks: u64,
    pub materialized_elements: u64,
    pub captured_bytes: u64,
    pub live_tasks: u64,
    pub live_handles: u64,
    pub live_processes: u64,
    pub live_http_connections: u64,
    pub live_temp_resources: u64,
}

#[derive(Debug)]
pub struct Budget {
    policy: Arc<RuntimePolicy>,
    evaluator_steps: Arc<AtomicU64>,
    allocations: Arc<AtomicU64>,
    live_thunks: Arc<AtomicU64>,
    materialized_elements: Arc<AtomicU64>,
    captured_bytes: Arc<AtomicU64>,
    live_tasks: Arc<AtomicU64>,
    live_handles: Arc<AtomicU64>,
    live_processes: Arc<AtomicU64>,
    live_http_connections: Arc<AtomicU64>,
    live_temp_resources: Arc<AtomicU64>,
}

impl Budget {
    #[must_use]
    pub fn new(policy: Arc<RuntimePolicy>) -> Self {
        Self {
            policy,
            evaluator_steps: Arc::new(AtomicU64::new(0)),
            allocations: Arc::new(AtomicU64::new(0)),
            live_thunks: Arc::new(AtomicU64::new(0)),
            materialized_elements: Arc::new(AtomicU64::new(0)),
            captured_bytes: Arc::new(AtomicU64::new(0)),
            live_tasks: Arc::new(AtomicU64::new(0)),
            live_handles: Arc::new(AtomicU64::new(0)),
            live_processes: Arc::new(AtomicU64::new(0)),
            live_http_connections: Arc::new(AtomicU64::new(0)),
            live_temp_resources: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Charges evaluator work.
    ///
    /// # Errors
    ///
    /// Returns a resource-limit error when the charge exceeds policy.
    pub fn charge_steps(&self, amount: u64) -> RuntimeResult<()> {
        charge(
            &self.evaluator_steps,
            self.policy.limits.evaluator_steps,
            BudgetKind::EvaluatorSteps,
            "evaluator transition",
            &self.policy.id,
            amount,
        )
    }

    /// Charges one or more guest-visible runtime allocations.
    ///
    /// # Errors
    ///
    /// Returns a resource-limit error when the charge exceeds policy.
    pub fn charge_allocation(&self, amount: u64) -> RuntimeResult<()> {
        charge(
            &self.allocations,
            self.policy.limits.allocations,
            BudgetKind::Allocations,
            "runtime allocation",
            &self.policy.id,
            amount,
        )
    }

    /// Acquires one live-thunk permit.
    ///
    /// # Errors
    ///
    /// Returns a resource-limit error when no permit remains.
    pub fn acquire_live_thunk(&self) -> RuntimeResult<BudgetPermit> {
        acquire_u64(
            &self.live_thunks,
            self.policy.limits.live_thunks,
            BudgetKind::LiveThunks,
            "thunk construction",
            &self.policy.id,
        )
    }

    /// Charges list materialization work.
    ///
    /// # Errors
    ///
    /// Returns a resource-limit error when the charge exceeds policy.
    pub fn charge_materialization(&self, amount: u64) -> RuntimeResult<()> {
        charge(
            &self.materialized_elements,
            self.policy.limits.list_materialized_elements,
            BudgetKind::MaterializedElements,
            "list materialization",
            &self.policy.id,
            amount,
        )
    }

    /// Charges captured process bytes.
    ///
    /// # Errors
    ///
    /// Returns a resource-limit error when the charge exceeds policy.
    pub fn charge_capture(&self, amount: u64) -> RuntimeResult<()> {
        charge(
            &self.captured_bytes,
            self.policy.limits.process_capture_bytes,
            BudgetKind::CapturedBytes,
            "process output capture",
            &self.policy.id,
            amount,
        )
    }

    /// Acquires one live task permit.
    ///
    /// # Errors
    ///
    /// Returns a resource-limit error when no permit remains.
    pub fn acquire_task(&self) -> RuntimeResult<BudgetPermit> {
        acquire(
            &self.live_tasks,
            self.policy.limits.concurrent_tasks,
            BudgetKind::Tasks,
            "task spawn",
            &self.policy.id,
        )
    }

    /// Acquires one live handle permit.
    ///
    /// # Errors
    ///
    /// Returns a resource-limit error when no permit remains.
    pub fn acquire_handle(&self) -> RuntimeResult<BudgetPermit> {
        acquire(
            &self.live_handles,
            self.policy.limits.open_handles,
            BudgetKind::Handles,
            "handle open",
            &self.policy.id,
        )
    }

    /// Acquires one live child-process permit.
    ///
    /// # Errors
    ///
    /// Returns a resource-limit error when no permit remains.
    pub fn acquire_process(&self) -> RuntimeResult<BudgetPermit> {
        acquire(
            &self.live_processes,
            self.policy.limits.child_processes,
            BudgetKind::Processes,
            "child process spawn",
            &self.policy.id,
        )
    }

    /// Acquires one live HTTP-connection permit.
    ///
    /// # Errors
    ///
    /// Returns a resource-limit error when no permit remains.
    pub fn acquire_http_connection(&self) -> RuntimeResult<BudgetPermit> {
        acquire(
            &self.live_http_connections,
            self.policy.limits.http_connections,
            BudgetKind::HttpConnections,
            "HTTP connection admission",
            &self.policy.id,
        )
    }

    /// Acquires one live temporary-resource permit.
    ///
    /// # Errors
    ///
    /// Returns a resource-limit error when no permit remains.
    pub fn acquire_temp_resource(&self) -> RuntimeResult<BudgetPermit> {
        acquire(
            &self.live_temp_resources,
            self.policy.limits.temp_resources,
            BudgetKind::TempResources,
            "temporary resource creation",
            &self.policy.id,
        )
    }

    #[must_use]
    pub fn snapshot(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            evaluator_steps: self.evaluator_steps.load(Ordering::Acquire),
            allocations: self.allocations.load(Ordering::Acquire),
            live_thunks: self.live_thunks.load(Ordering::Acquire),
            materialized_elements: self.materialized_elements.load(Ordering::Acquire),
            captured_bytes: self.captured_bytes.load(Ordering::Acquire),
            live_tasks: self.live_tasks.load(Ordering::Acquire),
            live_handles: self.live_handles.load(Ordering::Acquire),
            live_processes: self.live_processes.load(Ordering::Acquire),
            live_http_connections: self.live_http_connections.load(Ordering::Acquire),
            live_temp_resources: self.live_temp_resources.load(Ordering::Acquire),
        }
    }
}

#[derive(Debug)]
pub struct BudgetPermit {
    counter: Weak<AtomicU64>,
}

impl Drop for BudgetPermit {
    fn drop(&mut self) {
        if let Some(counter) = self.counter.upgrade() {
            counter.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

fn charge(
    counter: &AtomicU64,
    limit: Limit<u64>,
    kind: BudgetKind,
    operation: &'static str,
    profile: &str,
    amount: u64,
) -> RuntimeResult<()> {
    update(counter, limit, kind, operation, profile, amount).map(|_| ())
}

fn acquire(
    counter: &Arc<AtomicU64>,
    limit: Limit<usize>,
    kind: BudgetKind,
    operation: &'static str,
    profile: &str,
) -> RuntimeResult<BudgetPermit> {
    let limit = match limit {
        Limit::Unlimited => Limit::Unlimited,
        Limit::At(value) => Limit::At(u64::try_from(value).unwrap_or(u64::MAX)),
    };
    update(counter, limit, kind, operation, profile, 1)?;
    Ok(BudgetPermit {
        counter: Arc::downgrade(counter),
    })
}

fn acquire_u64(
    counter: &Arc<AtomicU64>,
    limit: Limit<u64>,
    kind: BudgetKind,
    operation: &'static str,
    profile: &str,
) -> RuntimeResult<BudgetPermit> {
    update(counter, limit, kind, operation, profile, 1)?;
    Ok(BudgetPermit {
        counter: Arc::downgrade(counter),
    })
}

fn update(
    counter: &AtomicU64,
    limit: Limit<u64>,
    kind: BudgetKind,
    operation: &'static str,
    profile: &str,
    amount: u64,
) -> RuntimeResult<u64> {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let Some(next) = current.checked_add(amount) else {
            return Err(RuntimeError::resource_limit(format!(
                "{kind:?} budget overflowed: configured={limit:?}, observed=integer overflow, operation={operation}, profile={profile}"
            )));
        };
        if let Limit::At(maximum) = limit
            && next > maximum
        {
            return Err(RuntimeError::resource_limit(format!(
                "{kind:?} budget exceeded: configured={maximum}, observed={next}, operation={operation}, profile={profile}"
            )));
        }
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(next),
            Err(observed) => current = observed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ActiveBudgetGuard, RuntimeErrorKind, Thunk, ThunkState, Value};

    #[test]
    fn charges_are_checked_and_shared() {
        let mut policy = RuntimePolicy::sandboxed();
        policy.limits.evaluator_steps = Limit::At(2);
        let budget = Arc::new(Budget::new(Arc::new(policy)));
        let other = Arc::clone(&budget);
        budget.charge_steps(1).unwrap();
        std::thread::spawn(move || other.charge_steps(1))
            .join()
            .unwrap()
            .unwrap();
        let error = budget.charge_steps(1).unwrap_err();
        assert!(error.message.contains("configured=2"));
        assert!(error.message.contains("observed=3"));
        assert!(error.message.contains("operation=evaluator transition"));
        assert!(error.message.contains("profile=sandboxed"));
        assert_eq!(budget.snapshot().evaluator_steps, 2);
    }

    #[test]
    fn live_permits_release_exactly_once() {
        let mut policy = RuntimePolicy::sandboxed();
        policy.limits.open_handles = Limit::At(1);
        let budget = Budget::new(Arc::new(policy));
        let permit = budget.acquire_handle().unwrap();
        assert!(budget.acquire_handle().is_err());
        drop(permit);
        assert_eq!(budget.snapshot().live_handles, 0);
        drop(budget.acquire_handle().unwrap());
        assert_eq!(budget.snapshot().live_handles, 0);
    }

    #[test]
    fn thunk_constructors_enforce_allocation_and_live_limits() {
        let mut policy = RuntimePolicy::sandboxed();
        policy.limits.allocations = Limit::At(1);
        policy.limits.live_thunks = Limit::At(1);
        let budget = Arc::new(Budget::new(Arc::new(policy)));
        let active = ActiveBudgetGuard::enter(&budget);
        let admitted = Thunk::evaluated(Value::Unit);
        let rejected = Thunk::evaluated(Value::Unit);
        assert!(matches!(
            *rejected
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            ThunkState::Failed(ref error) if error.kind == RuntimeErrorKind::ResourceLimit
        ));
        assert_eq!(budget.snapshot().allocations, 1);
        assert_eq!(budget.snapshot().live_thunks, 1);
        drop(active);
        drop(admitted);
        assert_eq!(budget.snapshot().live_thunks, 0);
    }

    #[test]
    fn live_thunk_permit_is_reusable_without_resetting_total_allocations() {
        let mut policy = RuntimePolicy::sandboxed();
        policy.limits.allocations = Limit::Unlimited;
        policy.limits.live_thunks = Limit::At(1);
        let budget = Arc::new(Budget::new(Arc::new(policy)));
        let active = ActiveBudgetGuard::enter(&budget);
        let first = Thunk::evaluated(Value::Unit);
        let rejected = Thunk::evaluated(Value::Unit);
        assert!(matches!(
            *rejected
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            ThunkState::Failed(ref error) if error.kind == RuntimeErrorKind::ResourceLimit
        ));
        drop(first);
        let replacement = Thunk::evaluated(Value::Unit);
        assert!(matches!(
            *replacement
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            ThunkState::Evaluated(_)
        ));
        assert_eq!(budget.snapshot().allocations, 3);
        assert_eq!(budget.snapshot().live_thunks, 1);
        drop(active);
    }
}
