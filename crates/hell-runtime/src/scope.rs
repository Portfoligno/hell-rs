//! Structured cancellation, task ownership, and resource cleanup.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::budget::{Budget, BudgetSnapshot};
use crate::policy::RuntimePolicy;
use crate::{RuntimeError, RuntimeResult};

static NEXT_SCOPE_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_RESOURCE_ID: AtomicU64 = AtomicU64::new(1);
static STALLED_TASKS: OnceLock<Mutex<Vec<JoinHandle<()>>>> = OnceLock::new();

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CancelReason {
    Timeout,
    RaceLost,
    SiblingFailed,
    ParentCancelled,
    UserInterrupt,
    BudgetExceeded,
    ScopeClosed,
}

#[derive(Debug)]
struct CancellationState {
    reason: OnceLock<CancelReason>,
    generation: AtomicU64,
    changed: Mutex<()>,
    waiters: Condvar,
    parent: Option<Weak<CancellationState>>,
    children: Mutex<Vec<Weak<CancellationState>>>,
}

#[derive(Clone, Debug)]
pub struct CancellationToken {
    state: Arc<CancellationState>,
}

impl CancellationToken {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(CancellationState {
                reason: OnceLock::new(),
                generation: AtomicU64::new(0),
                changed: Mutex::new(()),
                waiters: Condvar::new(),
                parent: None,
                children: Mutex::new(Vec::new()),
            }),
        }
    }

    #[must_use]
    pub fn child(&self) -> Self {
        let state = Arc::new(CancellationState {
            reason: OnceLock::new(),
            generation: AtomicU64::new(0),
            changed: Mutex::new(()),
            waiters: Condvar::new(),
            parent: Some(Arc::downgrade(&self.state)),
            children: Mutex::new(Vec::new()),
        });
        let mut children = self
            .state
            .children
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        children.retain(|child| child.strong_count() != 0);
        children.push(Arc::downgrade(&state));
        drop(children);
        Self { state }
    }

    pub fn cancel(&self, reason: CancelReason) {
        self.cancel_once(reason);
    }

    fn cancel_once(&self, reason: CancelReason) -> bool {
        let changed = self
            .state
            .changed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cancelled = if self.state.reason.set(reason).is_ok() {
            self.state.generation.fetch_add(1, Ordering::AcqRel);
            self.state.waiters.notify_all();
            true
        } else {
            false
        };
        drop(changed);
        if cancelled {
            notify_descendants(&self.state);
        }
        cancelled
    }

    #[must_use]
    pub fn reason(&self) -> Option<CancelReason> {
        self.state.reason.get().cloned().or_else(|| {
            self.state
                .parent
                .as_ref()
                .and_then(Weak::upgrade)
                .and_then(|parent| cancellation_reason(&parent))
                .map(|_| CancelReason::ParentCancelled)
        })
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.reason().is_some()
    }

    #[must_use]
    pub fn generation(&self) -> u64 {
        let local = self.state.generation.load(Ordering::Acquire);
        let parent = self
            .state
            .parent
            .as_ref()
            .and_then(Weak::upgrade)
            .map_or(0, |parent| parent.generation.load(Ordering::Acquire));
        local.wrapping_add(parent)
    }

    /// Waits for cancellation or the supplied duration.
    ///
    /// Poisoned wait state is recovered because cancellation remains monotonic.
    #[must_use]
    pub fn wait_timeout(&self, duration: Duration) -> bool {
        let state = self
            .state
            .changed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.is_cancelled() {
            return true;
        }
        let (_state, _timeout) = self
            .state
            .waiters
            .wait_timeout_while(state, duration, |()| !self.is_cancelled())
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.is_cancelled()
    }

    /// Returns a structured cancellation error when cancelled.
    ///
    /// # Errors
    ///
    /// Returns `H0906` after this token or an ancestor is cancelled.
    pub fn check(&self) -> RuntimeResult<()> {
        if self.is_cancelled() {
            Err(RuntimeError::cancelled())
        } else {
            Ok(())
        }
    }
}

fn notify_descendants(state: &CancellationState) {
    let children = {
        let mut children = state
            .children
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        children.retain(|child| child.strong_count() != 0);
        children
            .iter()
            .filter_map(Weak::upgrade)
            .collect::<Vec<_>>()
    };
    for child in children {
        let changed = child
            .changed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        child.generation.fetch_add(1, Ordering::AcqRel);
        child.waiters.notify_all();
        drop(changed);
        notify_descendants(&child);
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for CancellationToken {
    fn drop(&mut self) {
        if Arc::strong_count(&self.state) != 1 {
            return;
        }
        if let Some(parent) = self.state.parent.as_ref().and_then(Weak::upgrade) {
            parent
                .children
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retain(|child| {
                    child
                        .upgrade()
                        .is_some_and(|state| !Arc::ptr_eq(&state, &self.state))
                });
        }
    }
}

fn cancellation_reason(state: &CancellationState) -> Option<CancelReason> {
    state.reason.get().cloned().or_else(|| {
        state
            .parent
            .as_ref()
            .and_then(Weak::upgrade)
            .and_then(|parent| cancellation_reason(&parent))
            .map(|_| CancelReason::ParentCancelled)
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ScopeId(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TaskId(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResourceId(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadline(Option<Instant>);

impl Deadline {
    #[must_use]
    pub const fn none() -> Self {
        Self(None)
    }

    #[must_use]
    pub fn at(instant: Instant) -> Self {
        Self(Some(instant))
    }

    #[must_use]
    pub fn earliest(self, other: Self) -> Self {
        match (self.0, other.0) {
            (Some(left), Some(right)) => Self(Some(left.min(right))),
            (Some(value), None) | (None, Some(value)) => Self(Some(value)),
            (None, None) => Self(None),
        }
    }

    #[must_use]
    pub fn remaining(self) -> Option<Duration> {
        self.0
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    #[must_use]
    pub fn expired(self) -> bool {
        self.0.is_some_and(|deadline| Instant::now() >= deadline)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChildScopePolicy {
    pub deadline: Option<Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceKind {
    Handle,
    Process,
    Listener,
    Socket,
    Temporary,
    Other,
}

pub trait ScopedResource: Send + Sync + 'static {
    fn kind(&self) -> ResourceKind;
    fn request_cancel(&self, reason: &CancelReason);

    /// Releases the underlying host resource.
    ///
    /// # Errors
    ///
    /// Returns a structured host error when release fails.
    fn close(&self) -> RuntimeResult<()>;
    fn is_closed(&self) -> bool;
}

struct ResourceEntry {
    id: ResourceId,
    resource: Arc<dyn ScopedResource>,
}

#[derive(Default)]
struct ResourceRegistry {
    entries: Mutex<Vec<ResourceEntry>>,
    cancellation_failures: Mutex<Vec<CleanupFailure>>,
}

impl ResourceRegistry {
    fn register<R: ScopedResource>(&self, resource: R) -> ResourceGuard<R> {
        let id = ResourceId(NEXT_RESOURCE_ID.fetch_add(1, Ordering::Relaxed));
        let resource = Arc::new(resource);
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(ResourceEntry {
                id,
                resource: Arc::clone(&resource) as Arc<dyn ScopedResource>,
            });
        ResourceGuard { id, resource }
    }

    fn request_cancel(&self, reason: &CancelReason) {
        let resources = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .rev()
            .map(|entry| (entry.id, Arc::clone(&entry.resource)))
            .collect::<Vec<_>>();
        for (id, resource) in resources {
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                resource.request_cancel(reason);
            }))
            .is_err()
            {
                self.cancellation_failures
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(CleanupFailure::Resource {
                        id,
                        kind: resource.kind(),
                        error: RuntimeError::panic_contained(
                            "scoped resource cancellation panicked",
                        ),
                    });
            }
        }
    }

    fn close(&self) -> Vec<CleanupFailure> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut failures = std::mem::take(
            &mut *self
                .cancellation_failures
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        while let Some(entry) = entries.pop() {
            if entry.resource.is_closed() {
                continue;
            }
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| entry.resource.close()));
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => failures.push(CleanupFailure::Resource {
                    id: entry.id,
                    kind: entry.resource.kind(),
                    error,
                }),
                Err(_) => failures.push(CleanupFailure::Resource {
                    id: entry.id,
                    kind: entry.resource.kind(),
                    error: RuntimeError::panic_contained("scoped resource close panicked"),
                }),
            }
        }
        failures
    }

    fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

pub struct ResourceGuard<R> {
    id: ResourceId,
    resource: Arc<R>,
}

impl<R> ResourceGuard<R> {
    #[must_use]
    pub fn id(&self) -> ResourceId {
        self.id
    }

    #[must_use]
    pub fn resource(&self) -> &Arc<R> {
        &self.resource
    }
}

impl<R> Clone for ResourceGuard<R> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            resource: Arc::clone(&self.resource),
        }
    }
}

struct TaskRecord {
    id: TaskId,
    finished: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct TaskGroupState {
    tasks: BTreeMap<TaskId, TaskRecord>,
}

#[derive(Clone, Default)]
pub struct TaskGroup {
    state: Arc<(Mutex<TaskGroupState>, Condvar)>,
}

impl fmt::Debug for TaskGroup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskGroup")
            .field("live", &self.live_count())
            .finish()
    }
}

impl TaskGroup {
    fn insert(&self, record: TaskRecord) {
        self.state
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .tasks
            .insert(record.id, record);
    }

    fn mark_finished(&self, finished: &AtomicBool) {
        let _state = self
            .state
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        finished.store(true, Ordering::Release);
        self.state.1.notify_all();
    }

    #[must_use]
    pub fn live_count(&self) -> usize {
        self.state
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .tasks
            .values()
            .filter(|task| !task.finished.load(Ordering::Acquire))
            .count()
    }

    fn wait_until(&self, deadline: Instant) -> Vec<TaskId> {
        let (lock, changed) = &*self.state;
        let mut state = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if state
                .tasks
                .values()
                .all(|task| task.finished.load(Ordering::Acquire))
            {
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let (next, _) = changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
        }
        state
            .tasks
            .iter()
            .filter_map(|(id, task)| (!task.finished.load(Ordering::Acquire)).then_some(*id))
            .collect()
    }

    fn finalize(&self) -> TaskGroupCloseReport {
        reap_finished_stalled_tasks();
        let mut state = self
            .state
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut stalled = Vec::new();
        let mut panicked = Vec::new();
        for (id, mut task) in std::mem::take(&mut state.tasks) {
            if task.finished.load(Ordering::Acquire) {
                if task
                    .worker
                    .take()
                    .is_some_and(|worker| worker.join().is_err())
                {
                    panicked.push(id);
                }
            } else {
                stalled.push(id);
                if let Some(worker) = task.worker.take() {
                    retain_stalled_task(worker);
                }
            }
        }
        TaskGroupCloseReport { stalled, panicked }
    }
}

fn retain_stalled_task(worker: JoinHandle<()>) {
    STALLED_TASKS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(worker);
}

fn reap_finished_stalled_tasks() {
    let Some(tasks) = STALLED_TASKS.get() else {
        return;
    };
    let mut tasks = tasks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut index = 0;
    while index < tasks.len() {
        if tasks[index].is_finished() {
            let worker = tasks.swap_remove(index);
            let _contained_panic = worker.join();
        } else {
            index += 1;
        }
    }
}

pub struct TaskHandle<T> {
    id: TaskId,
    receiver: mpsc::Receiver<RuntimeResult<T>>,
}

#[derive(Debug)]
struct TaskGroupCloseReport {
    stalled: Vec<TaskId>,
    panicked: Vec<TaskId>,
}

impl<T> TaskHandle<T> {
    #[must_use]
    pub fn id(&self) -> TaskId {
        self.id
    }

    /// Waits up to `timeout` for the task's structured result.
    ///
    /// # Errors
    ///
    /// Returns a receive timeout or disconnect when the task has not
    /// published a result within the requested interval.
    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<RuntimeResult<T>, mpsc::RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }
}

#[derive(Debug)]
pub enum CleanupFailure {
    Resource {
        id: ResourceId,
        kind: ResourceKind,
        error: Arc<RuntimeError>,
    },
    Finalizer {
        error: Arc<RuntimeError>,
    },
    TaskPanic {
        id: TaskId,
    },
    CancellationStalled {
        tasks: Arc<[TaskId]>,
    },
}

impl CleanupFailure {
    fn error(&self) -> Arc<RuntimeError> {
        match self {
            Self::Resource { error, .. } | Self::Finalizer { error } => Arc::clone(error),
            Self::TaskPanic { id } => {
                RuntimeError::panic_contained(format!("scoped task {} panicked", id.0))
            }
            Self::CancellationStalled { tasks } => RuntimeError::cancellation_stalled(format!(
                "CancellationStalled: tasks {:?} did not quiesce before the forced deadline",
                tasks.iter().map(|task| task.0).collect::<Vec<_>>()
            )),
        }
    }
}

#[derive(Debug)]
pub struct ScopeCloseReport {
    pub scope_id: ScopeId,
    pub failures: Arc<[CleanupFailure]>,
    pub before: ScopeSnapshot,
    pub after: ScopeSnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeSnapshot {
    pub child_scopes: usize,
    pub live_tasks: usize,
    pub resources: usize,
    pub finalizers: usize,
    pub budget: BudgetSnapshot,
}

type Finalizer = Box<dyn FnOnce() -> RuntimeResult<()> + Send + 'static>;

struct ExecutionScopeInner {
    id: ScopeId,
    cancellation: CancellationToken,
    deadline: Deadline,
    policy: Arc<RuntimePolicy>,
    budget: Arc<Budget>,
    tasks: TaskGroup,
    resources: ResourceRegistry,
    finalizers: Mutex<Vec<Finalizer>>,
    children: Mutex<BTreeMap<ScopeId, Weak<ExecutionScopeInner>>>,
    parent: Option<Weak<ExecutionScopeInner>>,
    closed: AtomicBool,
}

#[derive(Clone)]
pub struct ExecutionScope {
    inner: Arc<ExecutionScopeInner>,
}

/// Armed owner for an execution scope.
///
/// Dropping an armed guard cancels the scope and performs bounded best-effort
/// cleanup. Call [`ScopeGuard::close`] to receive the structured close result.
#[must_use = "dropping the guard performs bounded scope cleanup"]
pub struct ScopeGuard {
    scope: ExecutionScope,
    armed: bool,
}

impl Deref for ScopeGuard {
    type Target = ExecutionScope;

    fn deref(&self) -> &Self::Target {
        &self.scope
    }
}

impl ScopeGuard {
    /// Closes the scope and reports cleanup failures.
    ///
    /// # Errors
    ///
    /// Returns the primary cleanup failure with later failures suppressed.
    pub fn close(mut self) -> RuntimeResult<ScopeCloseReport> {
        let result = self.scope.close();
        self.armed = false;
        result
    }

    pub(crate) fn close_with_primary(
        mut self,
        primary: Option<Arc<RuntimeError>>,
    ) -> RuntimeResult<ScopeCloseReport> {
        let result = self.scope.close_with_primary(primary);
        self.armed = false;
        result
    }
}

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ignored = self.scope.close();
            self.armed = false;
        }
    }
}

impl fmt::Debug for ExecutionScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionScope")
            .field("id", &self.inner.id)
            .field("snapshot", &self.snapshot())
            .finish_non_exhaustive()
    }
}

impl ExecutionScope {
    #[must_use]
    pub fn root(policy: Arc<RuntimePolicy>, budget: Arc<Budget>) -> Self {
        Self::with_cancellation(policy, budget, CancellationToken::new())
    }

    /// Arms bounded best-effort cleanup for every return and unwind path.
    pub fn guard(self) -> ScopeGuard {
        ScopeGuard {
            scope: self,
            armed: true,
        }
    }

    #[must_use]
    pub(crate) fn with_cancellation(
        policy: Arc<RuntimePolicy>,
        budget: Arc<Budget>,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            inner: Arc::new(ExecutionScopeInner {
                id: ScopeId(NEXT_SCOPE_ID.fetch_add(1, Ordering::Relaxed)),
                cancellation,
                deadline: Deadline::none(),
                policy,
                budget,
                tasks: TaskGroup::default(),
                resources: ResourceRegistry::default(),
                finalizers: Mutex::new(Vec::new()),
                children: Mutex::new(BTreeMap::new()),
                parent: None,
                closed: AtomicBool::new(false),
            }),
        }
    }

    /// Creates a child sharing policy and budget with its parent.
    ///
    /// # Errors
    ///
    /// Returns a resource-closed error after parent closure.
    pub fn child(&self, policy: ChildScopePolicy) -> RuntimeResult<Self> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(RuntimeError::resource_closed(
                "cannot create a child of a closed execution scope",
            ));
        }
        let deadline = self
            .inner
            .deadline
            .earliest(policy.deadline.map_or_else(Deadline::none, Deadline::at));
        let child = Self {
            inner: Arc::new(ExecutionScopeInner {
                id: ScopeId(NEXT_SCOPE_ID.fetch_add(1, Ordering::Relaxed)),
                cancellation: self.inner.cancellation.child(),
                deadline,
                policy: Arc::clone(&self.inner.policy),
                budget: Arc::clone(&self.inner.budget),
                tasks: TaskGroup::default(),
                resources: ResourceRegistry::default(),
                finalizers: Mutex::new(Vec::new()),
                children: Mutex::new(BTreeMap::new()),
                parent: Some(Arc::downgrade(&self.inner)),
                closed: AtomicBool::new(false),
            }),
        };
        self.inner
            .children
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(child.inner.id, Arc::downgrade(&child.inner));
        Ok(child)
    }

    #[must_use]
    pub fn id(&self) -> ScopeId {
        self.inner.id
    }

    #[must_use]
    pub fn cancellation(&self) -> &CancellationToken {
        &self.inner.cancellation
    }

    #[must_use]
    pub fn budget(&self) -> &Arc<Budget> {
        &self.inner.budget
    }

    /// Maximum time allowed for cooperative plus forced task quiescence.
    #[must_use]
    pub fn cleanup_window(&self) -> Duration {
        self.inner
            .policy
            .cancellation
            .graceful_shutdown
            .saturating_add(self.inner.policy.cancellation.forced_shutdown)
    }

    /// Checks cancellation, deadline, and scope closure.
    ///
    /// # Errors
    ///
    /// Returns a cancellation or resource-closed error when work must stop.
    pub fn safepoint(&self) -> RuntimeResult<()> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(RuntimeError::resource_closed("execution scope is closed"));
        }
        if self.inner.deadline.expired() {
            self.cancel(&CancelReason::Timeout);
        }
        self.inner.cancellation.check()
    }

    /// Registers a resource for two-phase cancellation and LIFO closure.
    ///
    /// # Errors
    ///
    /// Returns a resource-closed error after scope closure.
    pub fn register<R: ScopedResource>(&self, resource: R) -> RuntimeResult<ResourceGuard<R>> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(RuntimeError::resource_closed(
                "cannot register a resource in a closed execution scope",
            ));
        }
        Ok(self.inner.resources.register(resource))
    }

    /// Registers a finalizer that runs exactly once in LIFO order.
    ///
    /// # Errors
    ///
    /// Returns a resource-closed error after scope closure.
    pub fn defer(
        &self,
        finalizer: impl FnOnce() -> RuntimeResult<()> + Send + 'static,
    ) -> RuntimeResult<()> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(RuntimeError::resource_closed(
                "cannot register a finalizer in a closed execution scope",
            ));
        }
        self.inner
            .finalizers
            .lock()
            .map_err(|_| RuntimeError::internal("scope finalizer mutex was poisoned"))?
            .push(Box::new(finalizer));
        Ok(())
    }

    /// Spawns a task owned by this scope.
    ///
    /// # Errors
    ///
    /// Returns a resource-limit or resource-closed error when admission fails.
    pub fn spawn<T: Send + 'static>(
        &self,
        task: impl FnOnce(ExecutionScope) -> RuntimeResult<T> + Send + 'static,
    ) -> RuntimeResult<TaskHandle<T>> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(RuntimeError::resource_closed(
                "cannot spawn a task in a closed execution scope",
            ));
        }
        let permit = self.inner.budget.acquire_task()?;
        let child = self.child(ChildScopePolicy::default())?;
        let child_id = child.id();
        let id = TaskId(NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed));
        let finished = Arc::new(AtomicBool::new(false));
        let worker_finished = Arc::clone(&finished);
        let group = self.inner.tasks.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name(format!("hell-scope-task-{}", id.0))
            .spawn(move || {
                let task_scope = child.clone();
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| task(task_scope)))
                        .unwrap_or_else(|_| {
                            Err(RuntimeError::panic_contained("scoped task panicked"))
                        });
                let result = match result {
                    Ok(value) => child.close().map(|_| value),
                    Err(error) => child.close_with_primary(Some(error)).and_then(|_| {
                        Err(RuntimeError::internal(
                            "failed scoped task unexpectedly closed without its primary error",
                        ))
                    }),
                };
                drop(permit);
                group.mark_finished(&worker_finished);
                let _ignored = sender.send(result);
            });
        let worker = match worker {
            Ok(worker) => worker,
            Err(error) => {
                self.inner
                    .children
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&child_id);
                return Err(RuntimeError::internal(format!(
                    "failed to spawn scoped task: {error}"
                )));
            }
        };
        self.inner.tasks.insert(TaskRecord {
            id,
            finished,
            worker: Some(worker),
        });
        Ok(TaskHandle { id, receiver })
    }

    pub fn cancel(&self, reason: &CancelReason) {
        if !self.inner.cancellation.cancel_once(reason.clone()) {
            return;
        }
        self.inner.resources.request_cancel(reason);
        let children = self
            .inner
            .children
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter_map(Weak::upgrade)
            .collect::<Vec<_>>();
        for child in children {
            Self { inner: child }.cancel(&CancelReason::ParentCancelled);
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> ScopeSnapshot {
        let child_scopes = self
            .inner
            .children
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter(|child| child.strong_count() != 0)
            .count();
        ScopeSnapshot {
            child_scopes,
            live_tasks: self.inner.tasks.live_count(),
            resources: self.inner.resources.len(),
            finalizers: self
                .inner
                .finalizers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            budget: self.inner.budget.snapshot(),
        }
    }

    /// Closes all descendants, tasks, resources, and finalizers.
    ///
    /// # Errors
    ///
    /// Returns the first cleanup error, preserving later failures as suppressed errors.
    pub fn close(&self) -> RuntimeResult<ScopeCloseReport> {
        self.close_with_primary(None)
    }

    pub(crate) fn close_with_primary(
        &self,
        primary: Option<Arc<RuntimeError>>,
    ) -> RuntimeResult<ScopeCloseReport> {
        let before = self.snapshot();
        if self.inner.closed.swap(true, Ordering::AcqRel) {
            if let Some(primary) = primary {
                return Err(primary);
            }
            return Ok(ScopeCloseReport {
                scope_id: self.inner.id,
                failures: Arc::from([]),
                before: before.clone(),
                after: before,
            });
        }
        self.cancel(&CancelReason::ScopeClosed);
        let mut failures = Vec::new();
        let children = self
            .inner
            .children
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter_map(Weak::upgrade)
            .map(|inner| Self { inner })
            .collect::<Vec<_>>();
        for child in children.into_iter().rev() {
            if let Err(error) = child.close() {
                failures.push(CleanupFailure::Finalizer { error });
            }
        }
        self.inner
            .children
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        let graceful = Instant::now() + self.inner.policy.cancellation.graceful_shutdown;
        let graceful_stalled = self.inner.tasks.wait_until(graceful);
        if !graceful_stalled.is_empty() {
            let forced = Instant::now() + self.inner.policy.cancellation.forced_shutdown;
            let _still_stalled = self.inner.tasks.wait_until(forced);
        }
        let tasks = self.inner.tasks.finalize();
        for id in tasks.panicked {
            failures.push(CleanupFailure::TaskPanic { id });
        }
        if !tasks.stalled.is_empty() && self.inner.policy.cancellation.stalled_cleanup_is_error {
            failures.push(CleanupFailure::CancellationStalled {
                tasks: tasks.stalled.into(),
            });
        }
        failures.extend(self.inner.resources.close());
        let mut finalizers = self
            .inner
            .finalizers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while let Some(finalizer) = finalizers.pop() {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(finalizer));
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => failures.push(CleanupFailure::Finalizer { error }),
                Err(_) => failures.push(CleanupFailure::Finalizer {
                    error: RuntimeError::panic_contained("scope finalizer panicked"),
                }),
            }
        }
        drop(finalizers);
        if let Some(parent) = self.inner.parent.as_ref().and_then(Weak::upgrade) {
            parent
                .children
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&self.inner.id);
        }
        let after = self.snapshot();
        let report = ScopeCloseReport {
            scope_id: self.inner.id,
            failures: failures.into(),
            before,
            after,
        };
        if primary.is_some() || !report.failures.is_empty() {
            return Err(combine_failures(primary, &report.failures));
        }
        Ok(report)
    }
}

fn combine_failures(
    primary: Option<Arc<RuntimeError>>,
    failures: &[CleanupFailure],
) -> Arc<RuntimeError> {
    let mut errors = failures.iter().map(CleanupFailure::error);
    let primary = primary.or_else(|| errors.next()).unwrap_or_else(|| {
        RuntimeError::internal("execution scope failed without a recorded cleanup error")
    });
    let mut suppressed = primary.suppressed.to_vec();
    suppressed.extend(errors);
    Arc::new(RuntimeError {
        code: primary.code,
        kind: primary.kind.clone(),
        message: Arc::clone(&primary.message),
        presentation: primary.presentation.clone(),
        suppressed: suppressed.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::RuntimePolicy;

    struct RecordedResource {
        name: &'static str,
        events: Arc<Mutex<Vec<String>>>,
        closed: AtomicBool,
        fail_close: bool,
        panic_cancel: bool,
    }

    impl ScopedResource for RecordedResource {
        fn kind(&self) -> ResourceKind {
            ResourceKind::Other
        }

        fn request_cancel(&self, _reason: &CancelReason) {
            assert!(!self.panic_cancel, "cancel panic");
            self.events
                .lock()
                .unwrap()
                .push(format!("cancel:{}", self.name));
        }

        fn close(&self) -> RuntimeResult<()> {
            self.events
                .lock()
                .unwrap()
                .push(format!("close:{}", self.name));
            self.closed.store(true, Ordering::Release);
            if self.fail_close {
                Err(RuntimeError::internal(format!(
                    "{} close failed",
                    self.name
                )))
            } else {
                Ok(())
            }
        }

        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::Acquire)
        }
    }

    fn scope() -> ExecutionScope {
        let policy = Arc::new(RuntimePolicy::deterministic_test());
        let budget = Arc::new(Budget::new(Arc::clone(&policy)));
        ExecutionScope::root(policy, budget)
    }

    #[test]
    fn cancellation_flows_down_but_not_up() {
        let parent = scope();
        let child = parent.child(ChildScopePolicy::default()).unwrap();
        parent.cancel(&CancelReason::UserInterrupt);
        assert_eq!(
            child.cancellation().reason(),
            Some(CancelReason::ParentCancelled)
        );
        let independent = scope();
        let child = independent.child(ChildScopePolicy::default()).unwrap();
        child.cancel(&CancelReason::Timeout);
        assert!(!independent.cancellation().is_cancelled());
    }

    #[test]
    fn parent_cancellation_wakes_child_waiters() {
        let parent = CancellationToken::new();
        let child = parent.child();
        let waiter = std::thread::spawn(move || {
            let started = Instant::now();
            assert!(child.wait_timeout(Duration::from_secs(5)));
            started.elapsed()
        });
        parent.cancel(CancelReason::UserInterrupt);
        assert!(waiter.join().unwrap() < Duration::from_secs(1));
    }

    #[test]
    fn completed_child_tokens_do_not_accumulate_in_parent() {
        let parent = CancellationToken::new();
        for _ in 0..100 {
            drop(parent.child());
        }
        assert!(parent.state.children.lock().unwrap().is_empty());
    }

    #[test]
    fn finalizers_are_lifo_idempotent_and_preserve_failures() {
        let scope = scope();
        let order = Arc::new(Mutex::new(Vec::new()));
        for value in [1, 2, 3] {
            let order = Arc::clone(&order);
            scope
                .defer(move || {
                    order.lock().unwrap().push(value);
                    Ok(())
                })
                .unwrap();
        }
        let report = scope.close().unwrap();
        assert_eq!(*order.lock().unwrap(), [3, 2, 1]);
        assert_eq!(report.after.live_tasks, 0);
        assert!(scope.close().is_ok());
    }

    #[test]
    fn resources_receive_two_phase_lifo_cleanup() {
        let scope = scope();
        let events = Arc::new(Mutex::new(Vec::new()));
        for name in ["first", "second"] {
            scope
                .register(RecordedResource {
                    name,
                    events: Arc::clone(&events),
                    closed: AtomicBool::new(false),
                    fail_close: false,
                    panic_cancel: false,
                })
                .unwrap();
        }
        scope.close().unwrap();
        assert_eq!(
            *events.lock().unwrap(),
            [
                "cancel:second",
                "cancel:first",
                "close:second",
                "close:first"
            ]
        );
    }

    #[test]
    fn cancellation_panic_is_contained_and_resource_still_closes() {
        let scope = scope();
        let events = Arc::new(Mutex::new(Vec::new()));
        scope
            .register(RecordedResource {
                name: "panicking",
                events: Arc::clone(&events),
                closed: AtomicBool::new(false),
                fail_close: false,
                panic_cancel: true,
            })
            .unwrap();
        let error = scope.close().unwrap_err();
        assert_eq!(error.code, "H9004");
        assert_eq!(*events.lock().unwrap(), ["close:panicking"]);
    }

    #[test]
    fn armed_guard_cleans_up_on_error_and_panic() {
        fn return_early(order: Arc<Mutex<Vec<&'static str>>>) -> RuntimeResult<()> {
            let guard = scope().guard();
            guard.defer(move || {
                order.lock().unwrap().push("error");
                Ok(())
            })?;
            Err(RuntimeError::internal("body failed"))
        }

        let order = Arc::new(Mutex::new(Vec::new()));
        assert!(return_early(Arc::clone(&order)).is_err());
        let panic_order = Arc::clone(&order);
        let unwind = std::panic::catch_unwind(move || {
            let guard = scope().guard();
            guard
                .defer(move || {
                    panic_order.lock().unwrap().push("panic");
                    Ok(())
                })
                .unwrap();
            panic!("test unwind");
        });
        assert!(unwind.is_err());
        assert_eq!(*order.lock().unwrap(), ["error", "panic"]);
    }

    #[test]
    fn primary_error_precedes_cleanup_and_survives_second_close() {
        let scope = scope();
        scope
            .defer(|| Err(RuntimeError::internal("cleanup failed")))
            .unwrap();
        let primary = RuntimeError::resource_limit("primary failed");
        let error = scope
            .close_with_primary(Some(Arc::clone(&primary)))
            .unwrap_err();
        assert_eq!(error.code, primary.code);
        assert_eq!(error.message, primary.message);
        assert_eq!(error.suppressed.len(), 1);
        let second = RuntimeError::cancelled();
        let error = scope.close_with_primary(Some(second)).unwrap_err();
        assert_eq!(error.code, "H0906");
    }

    #[test]
    fn cancellation_stall_is_bounded_and_reported() {
        let mut policy = RuntimePolicy::deterministic_test();
        policy.cancellation.graceful_shutdown = Duration::from_millis(10);
        policy.cancellation.forced_shutdown = Duration::from_millis(10);
        let policy = Arc::new(policy);
        let budget = Arc::new(Budget::new(Arc::clone(&policy)));
        let scope = ExecutionScope::root(policy, budget);
        let (started_sender, started_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let task = scope
            .spawn(move |_| {
                started_sender.send(()).unwrap();
                release_receiver.recv().unwrap();
                Ok(())
            })
            .unwrap();
        started_receiver.recv().unwrap();
        let (closed_sender, closed_receiver) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let _ignored = closed_sender.send(scope.close());
        });
        let close_result = closed_receiver.recv_timeout(Duration::from_secs(3));
        release_sender.send(()).unwrap();
        let error = close_result
            .expect("scope cancellation remained bounded")
            .unwrap_err();
        assert!(error.message.contains("CancellationStalled"));
        task.recv_timeout(Duration::from_secs(1)).unwrap().unwrap();
    }

    #[test]
    fn stalled_task_releases_shared_budget_permit_before_result_is_observed() {
        let mut policy = RuntimePolicy::deterministic_test();
        policy.cancellation.graceful_shutdown = Duration::from_millis(5);
        policy.cancellation.forced_shutdown = Duration::from_millis(5);
        let policy = Arc::new(policy);
        let budget = Arc::new(Budget::new(Arc::clone(&policy)));
        let scope = ExecutionScope::root(policy, Arc::clone(&budget));
        let (release, wait) = mpsc::channel();
        let task = scope
            .spawn(move |_| {
                wait.recv()
                    .map_err(|_| RuntimeError::internal("release lost"))?;
                Ok(())
            })
            .unwrap();
        let error = scope.close().unwrap_err();
        assert!(error.message.contains("CancellationStalled"));
        assert_eq!(budget.snapshot().live_tasks, 1);
        release.send(()).unwrap();
        task.recv_timeout(Duration::from_secs(1)).unwrap().unwrap();
        assert_eq!(budget.snapshot().live_tasks, 0);
    }
}
