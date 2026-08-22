//! Safe cross-platform process-group and Windows Job Object supervision.

use std::io;
use std::process::{ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus};
use std::sync::{
    Arc, Condvar, Mutex, OnceLock,
    atomic::{AtomicU64, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

use command_group::{CommandGroup, GroupChild};

/// The result of polling a supervised process tree until a deadline.
#[derive(Clone, Debug)]
pub enum WaitOutcome {
    /// The process leader exited with this status.
    Exited(ExitStatus),
    /// The supplied deadline expired first.
    DeadlineExpired,
}

/// Records how timeout cleanup completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminationReport {
    /// Stable id of the cleanup admission that owned the child before launch.
    pub cleanup_id: u64,
    /// Whether group/job termination was requested.
    pub forced: bool,
    /// Whether the child leader was reaped.
    pub reaped: bool,
}

/// A child launched in a dedicated POSIX process group or Windows Job Object.
///
/// Dropping a live guard makes a best effort to kill and reap the complete
/// tree. Call [`Self::terminate`] to receive cleanup errors explicitly.
#[derive(Debug)]
pub struct SupervisedChild {
    child: Option<GroupChild>,
    cleanup: Option<CleanupLease>,
}

impl SupervisedChild {
    /// Spawns `command` in a fresh platform process-tree boundary.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when the group/job or child cannot be
    /// created.
    pub fn spawn(command: &mut Command) -> io::Result<Self> {
        let _ = termination_executor_sender()?;
        let cleanup = CleanupLease::acquire()?;
        command.group_spawn().map(|child| Self {
            child: Some(child),
            cleanup: Some(cleanup),
        })
    }

    /// Returns the process leader identifier, or zero after reap.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.child.as_ref().map_or(0, GroupChild::id)
    }

    /// Returns a lease that keeps this complete child lifecycle admitted.
    ///
    /// # Errors
    ///
    /// Returns an error after process cleanup ownership has been consumed.
    pub fn cleanup_lease(&self) -> io::Result<CleanupLease> {
        self.cleanup
            .clone()
            .ok_or_else(|| io::Error::other("process cleanup admission was already consumed"))
    }

    /// Takes the configured child standard input pipe.
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.as_mut()?.inner().stdin.take()
    }

    /// Takes the configured child standard output pipe.
    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.as_mut()?.inner().stdout.take()
    }

    /// Takes the configured child standard error pipe.
    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.as_mut()?.inner().stderr.take()
    }

    /// Polls the process leader without consuming the supervision boundary.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when process status cannot be read.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child
            .as_mut()
            .ok_or_else(|| io::Error::other("process tree was already reaped"))?
            .try_wait()
    }

    /// Polls the supervised process-group/job leader until it exits or `deadline` is reached.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when process status cannot be read.
    pub fn wait_until(&mut self, deadline: Instant) -> io::Result<WaitOutcome> {
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(WaitOutcome::Exited(status));
            }
            if Instant::now() >= deadline {
                return Ok(WaitOutcome::DeadlineExpired);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// Requests group/job termination and reaps the process leader.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error if the tree cannot be killed or
    /// reaped. An already-exited group is still reaped successfully.
    pub fn terminate(&mut self) -> io::Result<(ExitStatus, TerminationReport)> {
        let child = self
            .child
            .take()
            .ok_or_else(|| io::Error::other("process tree was already reaped"))?;
        let cleanup = self
            .cleanup
            .take()
            .ok_or_else(|| io::Error::other("process cleanup admission was already consumed"))?;
        terminate_group_child(child, cleanup)
    }

    /// Force-terminates the process tree without blocking the caller past `deadline`.
    ///
    /// A kill/reap operation that does not finish in time remains owned by a bounded
    /// cleanup worker; the caller receives a timed-out error instead of blocking in
    /// `GroupChild::wait` or dropping a live group handle.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error from kill/reap, or a timed-out error when
    /// cleanup ownership had to be transferred at the absolute deadline.
    pub fn terminate_until(
        &mut self,
        deadline: Instant,
    ) -> io::Result<(ExitStatus, TerminationReport)> {
        let child = self
            .child
            .take()
            .ok_or_else(|| io::Error::other("process tree was already reaped"))?;
        let cleanup = self
            .cleanup
            .take()
            .ok_or_else(|| io::Error::other("process cleanup admission was already consumed"))?;
        let receipt = RetainedTerminationReceipt::new(&cleanup);
        let (sender, receiver) = mpsc::sync_channel(1);
        termination_executor_sender()?
            .send(TerminationTask {
                child,
                cleanup,
                receipt: receipt.clone(),
                completion: Some(sender),
                probe: TerminationProbe::None,
            })
            .map_err(|_| io::Error::other("process-tree termination executor disconnected"))?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                RetainedTerminationError {
                    receipt,
                    reason: RetainedTerminationReason::NoReserve,
                },
            ));
        }
        match receiver.recv_timeout(remaining) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                RetainedTerminationError {
                    receipt,
                    reason: RetainedTerminationReason::DeadlineExpired,
                },
            )),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::other(
                "process-tree termination receipt disconnected",
            )),
        }
    }

    /// Waits for normal process-group/job leader completion and consumes the guard.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when the process tree cannot be
    /// reaped.
    pub fn wait(mut self) -> io::Result<ExitStatus> {
        let status = self
            .child
            .take()
            .ok_or_else(|| io::Error::other("process tree was already reaped"))?
            .wait();
        self.cleanup.take();
        status
    }
}

fn terminate_group_child(
    mut child: GroupChild,
    cleanup: CleanupLease,
) -> io::Result<(ExitStatus, TerminationReport)> {
    match child.kill() {
        Ok(()) => {}
        Err(error) if process_tree_is_absent(&error) => {}
        Err(error) => return Err(error),
    }
    let status = child.wait()?;
    let cleanup_id = cleanup.id();
    drop(cleanup);
    Ok((
        status,
        TerminationReport {
            cleanup_id,
            forced: true,
            reaped: true,
        },
    ))
}

const CLEANUP_ADMISSION_CAPACITY: usize = 16;

#[derive(Debug)]
struct CleanupAdmissionInner {
    id: u64,
    owners: Mutex<usize>,
    idle: Condvar,
}

/// Cloneable ownership token shared by the child and every I/O cleanup task.
#[derive(Debug)]
pub struct CleanupLease {
    inner: Arc<CleanupAdmissionInner>,
}

impl Clone for CleanupLease {
    fn clone(&self) -> Self {
        *self
            .inner
            .owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl CleanupLease {
    fn acquire() -> io::Result<Self> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let tracker = late_termination_tracker();
        let mut admitted = tracker
            .admitted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *admitted >= CLEANUP_ADMISSION_CAPACITY {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "process cleanup admission capacity is exhausted before child spawn",
            ));
        }
        *admitted += 1;
        Ok(Self {
            inner: Arc::new(CleanupAdmissionInner {
                id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
                owners: Mutex::new(1),
                idle: Condvar::new(),
            }),
        })
    }

    /// Returns the stable lifecycle id.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.inner.id
    }

    /// Returns a non-owning receipt for the complete process and I/O lifecycle.
    #[must_use]
    pub fn receipt(&self) -> CleanupLifecycleReceipt {
        CleanupLifecycleReceipt {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Drop for CleanupLease {
    fn drop(&mut self) {
        let mut owners = self
            .inner
            .owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *owners = owners.saturating_sub(1);
        if *owners != 0 {
            return;
        }
        self.inner.idle.notify_all();
        let tracker = late_termination_tracker();
        let mut admitted = tracker
            .admitted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *admitted = admitted.saturating_sub(1);
        tracker.idle.notify_all();
    }
}

/// Non-owning receipt for all process and I/O owners admitted with one child.
#[derive(Clone, Debug)]
pub struct CleanupLifecycleReceipt {
    inner: Arc<CleanupAdmissionInner>,
}

impl CleanupLifecycleReceipt {
    /// Waits until every cleanup lifecycle admitted in this process is idle.
    pub fn wait_for_all() {
        let tracker = late_termination_tracker();
        let mut admitted = tracker
            .admitted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *admitted != 0 {
            admitted = tracker
                .idle
                .wait(admitted)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    /// Waits until every cleanup lifecycle admitted in this process is idle.
    ///
    /// This is intended for an external owner process that must not exit after
    /// an unwind until all child and I/O ownership has reached a terminal state.
    pub fn wait_for_all_until(deadline: Instant) -> bool {
        let tracker = late_termination_tracker();
        let mut admitted = tracker
            .admitted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *admitted != 0 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let (next, timeout) = tracker
                .idle
                .wait_timeout(admitted, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            admitted = next;
            if timeout.timed_out() && *admitted != 0 {
                return false;
            }
        }
        true
    }

    /// Stable lifecycle id.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.inner.id
    }

    /// Returns whether every process and I/O owner is terminal.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        *self
            .inner
            .owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            == 0
    }

    /// Waits without polling until every admitted owner is terminal or the deadline expires.
    pub fn wait_until(&self, deadline: Instant) -> bool {
        let mut owners = self
            .inner
            .owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *owners != 0 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let (next, timeout) = self
                .inner
                .idle
                .wait_timeout(owners, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            owners = next;
            if timeout.timed_out() && *owners != 0 {
                return false;
            }
        }
        true
    }

    /// Waits until every admitted process and I/O owner is terminal.
    pub fn wait(&self) {
        let mut owners = self
            .inner
            .owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *owners != 0 {
            owners = self
                .inner
                .idle
                .wait(owners)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

/// Terminal state of cleanup retained after its caller's completion deadline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetainedTerminationState {
    /// The cleanup worker still owns kill/reap.
    Owned,
    /// Kill/reap completed successfully.
    Completed(TerminationReport),
    /// Kill/reap completed with this bounded error text.
    Failed(String),
}

/// Receipt for cleanup that remains owned after the caller returns.
#[derive(Clone, Debug)]
pub struct RetainedTerminationReceipt {
    id: u64,
    state: Arc<(Mutex<RetainedTerminationState>, Condvar)>,
    lifecycle: CleanupLifecycleReceipt,
}

impl RetainedTerminationReceipt {
    fn new(cleanup: &CleanupLease) -> Self {
        Self {
            id: cleanup.id(),
            state: Arc::new((Mutex::new(RetainedTerminationState::Owned), Condvar::new())),
            lifecycle: cleanup.receipt(),
        }
    }

    fn finish(&self, result: &io::Result<(ExitStatus, TerminationReport)>) {
        *self
            .state
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = match result {
            Ok((_, report)) => RetainedTerminationState::Completed(*report),
            Err(error) => RetainedTerminationState::Failed(error.to_string()),
        };
        self.state.1.notify_all();
    }

    /// Returns the stable cleanup id.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Returns the current retained-cleanup state.
    #[must_use]
    pub fn state(&self) -> RetainedTerminationState {
        self.state
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Waits for both kill/reap and every process/I/O lease to become terminal.
    #[must_use]
    pub fn wait_until(&self, deadline: Instant) -> RetainedTerminationSnapshot {
        let mut state = self
            .state
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while matches!(*state, RetainedTerminationState::Owned) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let (next, timeout) = self
                .state
                .1
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
            if timeout.timed_out() && matches!(*state, RetainedTerminationState::Owned) {
                break;
            }
        }
        let terminal_state = state.clone();
        drop(state);
        let lifecycle_idle = self.lifecycle.wait_until(deadline);
        RetainedTerminationSnapshot {
            state: terminal_state,
            lifecycle_idle,
        }
    }

    /// Waits until kill/reap and every admitted I/O owner are terminal.
    #[must_use]
    pub fn wait(&self) -> RetainedTerminationSnapshot {
        let mut state = self
            .state
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while matches!(*state, RetainedTerminationState::Owned) {
            state = self
                .state
                .1
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        let terminal_state = state.clone();
        drop(state);
        self.lifecycle.wait();
        RetainedTerminationSnapshot {
            state: terminal_state,
            lifecycle_idle: true,
        }
    }
}

/// Deadline-bounded snapshot of retained process and I/O cleanup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedTerminationSnapshot {
    /// Kill/reap state at the observation deadline.
    pub state: RetainedTerminationState,
    /// Whether all process/stdin/stdout/stderr ownership became idle.
    pub lifecycle_idle: bool,
}

#[derive(Debug)]
struct RetainedTerminationError {
    receipt: RetainedTerminationReceipt,
    reason: RetainedTerminationReason,
}

#[derive(Debug)]
enum RetainedTerminationReason {
    NoReserve,
    DeadlineExpired,
}

impl std::fmt::Display for RetainedTerminationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.reason {
            RetainedTerminationReason::NoReserve => write!(
                formatter,
                "execution exhausted the process-tree cleanup reserve; cleanup receipt {} remains owned",
                self.receipt.id()
            ),
            RetainedTerminationReason::DeadlineExpired => write!(
                formatter,
                "process-tree kill/reap exceeded its absolute deadline; cleanup receipt {} remains owned",
                self.receipt.id()
            ),
        }
    }
}

impl std::error::Error for RetainedTerminationError {}

/// Extracts a typed retained-cleanup receipt from a termination timeout.
#[must_use]
pub fn retained_termination_receipt(error: &io::Error) -> Option<RetainedTerminationReceipt> {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<RetainedTerminationError>())
        .map(|source| source.receipt.clone())
}

struct LateTerminationTracker {
    admitted: Mutex<usize>,
    idle: Condvar,
}

fn late_termination_tracker() -> &'static LateTerminationTracker {
    static TRACKER: OnceLock<LateTerminationTracker> = OnceLock::new();
    TRACKER.get_or_init(|| LateTerminationTracker {
        admitted: Mutex::new(0),
        idle: Condvar::new(),
    })
}

struct TerminationTask {
    child: GroupChild,
    cleanup: CleanupLease,
    receipt: RetainedTerminationReceipt,
    completion: Option<mpsc::SyncSender<io::Result<(ExitStatus, TerminationReport)>>>,
    probe: TerminationProbe,
}

enum TerminationProbe {
    None,
    #[cfg(unix)]
    Wait(mpsc::Receiver<()>),
    #[cfg(unix)]
    PanicAfterCleanup,
}

impl TerminationProbe {
    fn prepare(self) -> io::Result<bool> {
        match self {
            Self::None => Ok(false),
            #[cfg(unix)]
            Self::Wait(gate) => gate
                .recv()
                .map(|()| false)
                .map_err(|_| io::Error::other("process-tree cleanup probe gate disconnected")),
            #[cfg(unix)]
            Self::PanicAfterCleanup => Ok(true),
        }
    }
}

fn termination_executor_sender() -> io::Result<mpsc::Sender<TerminationTask>> {
    const WORKERS: usize = 4;
    static EXECUTOR: OnceLock<Result<mpsc::Sender<TerminationTask>, String>> = OnceLock::new();
    match EXECUTOR.get_or_init(|| {
        let (sender, receiver) = mpsc::channel::<TerminationTask>();
        let receiver = Arc::new(Mutex::new(receiver));
        for index in 0..WORKERS {
            let receiver = Arc::clone(&receiver);
            std::thread::Builder::new()
                .name(format!("hell-process-tree-reaper-{index}"))
                .spawn(move || {
                    loop {
                        let task = {
                            let receiver = receiver
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            receiver.recv()
                        };
                        let Ok(task) = task else {
                            break;
                        };
                        let TerminationTask {
                            child,
                            cleanup,
                            receipt,
                            completion,
                            probe,
                        } = task;
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            let panic_after_cleanup = probe.prepare()?;
                            let result = terminate_group_child(child, cleanup);
                            assert!(
                                !panic_after_cleanup,
                                "injected process-tree cleanup worker panic"
                            );
                            result
                        }))
                        .unwrap_or_else(|_| {
                            Err(io::Error::other("process-tree kill/reap worker panicked"))
                        });
                        receipt.finish(&result);
                        if let Some(completion) = completion {
                            let _ = completion.send(result);
                        }
                    }
                })
                .map_err(|error| format!("cannot start process-tree cleanup executor: {error}"))?;
        }
        Ok(sender)
    }) {
        Ok(sender) => Ok(sender.clone()),
        Err(error) => Err(io::Error::other(error.clone())),
    }
}

/// Verifies that an already-expired kill/reap deadline transfers ownership and
/// reaches a receipt-backed idle state without blocking the caller.
///
/// # Errors
///
/// Returns an error if deadline enforcement or retained cleanup completion drifts.
#[cfg(unix)]
#[doc(hidden)]
pub fn verify_termination_deadline_for_integration() -> Result<(), String> {
    let mut command = Command::new("/bin/sleep");
    command.arg("60");
    let mut child = SupervisedChild::spawn(&mut command)
        .map_err(|error| format!("cannot spawn termination deadline fixture: {error}"))?;
    let started = Instant::now();
    let error = child
        .terminate_until(started)
        .expect_err("expired termination deadline must transfer cleanup ownership");
    if error.kind() != io::ErrorKind::TimedOut || started.elapsed() >= Duration::from_secs(1) {
        return Err("expired kill/reap did not return its bounded typed error".to_owned());
    }
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(5))
        .ok_or_else(|| "termination receipt deadline overflowed".to_owned())?;
    let receipt = retained_termination_receipt(&error)
        .ok_or_else(|| "expired kill/reap lost its typed receipt".to_owned())?;
    let snapshot = receipt.wait_until(deadline);
    if !matches!(
        snapshot.state,
        RetainedTerminationState::Completed(TerminationReport {
            forced: true,
            reaped: true,
            ..
        })
    ) || !snapshot.lifecycle_idle
    {
        return Err("retained kill/reap receipt did not become terminal and idle".to_owned());
    }
    let tracker = late_termination_tracker();
    let mut admitted = tracker
        .admitted
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    while *admitted != 0 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("retained kill/reap did not reach its idle receipt".to_owned());
        }
        let (next, timeout) = tracker
            .idle
            .wait_timeout(admitted, remaining)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        admitted = next;
        if timeout.timed_out() && *admitted != 0 {
            return Err("retained kill/reap exceeded its receipt deadline".to_owned());
        }
    }
    drop(admitted);
    verify_termination_transition_probes(deadline)
}

#[cfg(unix)]
fn verify_termination_transition_probes(deadline: Instant) -> Result<(), String> {
    let mut gated_command = Command::new("/bin/sleep");
    gated_command.arg("60");
    let mut gated = SupervisedChild::spawn(&mut gated_command)
        .map_err(|error| format!("cannot spawn gated termination fixture: {error}"))?;
    let child = gated
        .child
        .take()
        .ok_or_else(|| "gated termination fixture lost its child".to_owned())?;
    let cleanup = gated
        .cleanup
        .take()
        .ok_or_else(|| "gated termination fixture lost its cleanup lease".to_owned())?;
    let receipt = RetainedTerminationReceipt::new(&cleanup);
    let (release, gate) = mpsc::sync_channel(1);
    termination_executor_sender()
        .map_err(|error| format!("cannot acquire gated cleanup executor: {error}"))?
        .send(TerminationTask {
            child,
            cleanup,
            receipt: receipt.clone(),
            completion: None,
            probe: TerminationProbe::Wait(gate),
        })
        .map_err(|_| "cannot submit gated cleanup fixture".to_owned())?;
    if receipt.state() != RetainedTerminationState::Owned {
        return Err("gated cleanup receipt did not retain its owned transition".to_owned());
    }
    release
        .send(())
        .map_err(|_| "cannot release gated cleanup fixture".to_owned())?;
    let snapshot = receipt.wait_until(deadline);
    if !matches!(snapshot.state, RetainedTerminationState::Completed(_)) || !snapshot.lifecycle_idle
    {
        return Err("gated cleanup receipt did not become terminal and idle".to_owned());
    }
    verify_termination_panic_receipt(deadline)
}

#[cfg(unix)]
fn verify_termination_panic_receipt(deadline: Instant) -> Result<(), String> {
    let mut panic_command = Command::new("/usr/bin/true");
    let mut panic_child = SupervisedChild::spawn(&mut panic_command)
        .map_err(|error| format!("cannot spawn cleanup panic fixture: {error}"))?;
    let child = panic_child
        .child
        .take()
        .ok_or_else(|| "cleanup panic fixture lost its child".to_owned())?;
    let cleanup = panic_child
        .cleanup
        .take()
        .ok_or_else(|| "cleanup panic fixture lost its cleanup lease".to_owned())?;
    let receipt = RetainedTerminationReceipt::new(&cleanup);
    termination_executor_sender()
        .map_err(|error| format!("cannot acquire cleanup panic executor: {error}"))?
        .send(TerminationTask {
            child,
            cleanup,
            receipt: receipt.clone(),
            completion: None,
            probe: TerminationProbe::PanicAfterCleanup,
        })
        .map_err(|_| "cannot submit cleanup panic fixture".to_owned())?;
    let snapshot = receipt.wait_until(deadline);
    if !matches!(snapshot.state, RetainedTerminationState::Failed(_)) || !snapshot.lifecycle_idle {
        return Err("cleanup worker panic lost its terminal failed receipt".to_owned());
    }
    Ok(())
}

fn process_tree_is_absent(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::InvalidInput | io::ErrorKind::NotFound
    ) {
        return true;
    }
    #[cfg(unix)]
    {
        const ESRCH: i32 = 3;
        error.raw_os_error() == Some(ESRCH)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

impl Drop for SupervisedChild {
    fn drop(&mut self) {
        if let (Some(child), Some(cleanup)) = (self.child.take(), self.cleanup.take()) {
            let receipt = RetainedTerminationReceipt::new(&cleanup);
            termination_executor_sender()
                .and_then(|sender| {
                    sender
                        .send(TerminationTask {
                            child,
                            cleanup,
                            receipt,
                            completion: None,
                            probe: TerminationProbe::None,
                        })
                        .map_err(|_| {
                            io::Error::other("process-tree termination executor disconnected")
                        })
                })
                .unwrap_or_else(|error| panic!("cannot transfer dropped process tree: {error}"));
        }
    }
}
