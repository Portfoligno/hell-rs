//! Direct lifecycle ownership for a trusted supervision frontend.
//!
//! Unlike [`crate::SupervisedChild`], this owner deliberately creates no
//! process-group or Windows Job boundary around the child. The external
//! provider owns candidate-tree containment; this type owns only frontend
//! kill, reap, and standard-stream lifecycle.

use std::io;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus};
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc};
use std::time::{Duration, Instant};

use crate::{CleanupLease, WaitOutcome};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrontendTerminationReport {
    pub cleanup_id: u64,
    pub kill_requested: bool,
    pub reaped: bool,
}

#[derive(Debug)]
pub struct FrontendChild {
    child: Option<Child>,
    cleanup: Option<CleanupLease>,
}

impl FrontendChild {
    /// Spawns a directly owned frontend without a new process-tree boundary.
    ///
    /// # Errors
    ///
    /// Returns an error if cleanup admission, worker startup, or spawn fails.
    pub fn spawn(command: &mut Command) -> io::Result<Self> {
        let _ = termination_executor_sender()?;
        let cleanup = CleanupLease::acquire()?;
        command.spawn().map(|child| Self {
            child: Some(child),
            cleanup: Some(cleanup),
        })
    }

    #[must_use]
    pub fn id(&self) -> u32 {
        self.child.as_ref().map_or(0, Child::id)
    }

    /// Clones the lifecycle lease for one associated I/O worker.
    ///
    /// # Errors
    ///
    /// Returns an error after cleanup ownership was consumed.
    pub fn cleanup_lease(&self) -> io::Result<CleanupLease> {
        self.cleanup
            .clone()
            .ok_or_else(|| io::Error::other("frontend cleanup admission was already consumed"))
    }

    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.as_mut()?.stdin.take()
    }

    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.as_mut()?.stdout.take()
    }

    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.as_mut()?.stderr.take()
    }

    /// Polls the direct frontend status.
    ///
    /// # Errors
    ///
    /// Returns an error after reap or when the status query fails.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child
            .as_mut()
            .ok_or_else(|| io::Error::other("frontend was already reaped"))?
            .try_wait()
    }

    /// Polls until direct frontend exit or the absolute deadline.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating-system status query fails.
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

    /// Reaps a normally exited frontend.
    ///
    /// # Errors
    ///
    /// Returns an error after reap or when the operating-system wait fails.
    pub fn wait(mut self) -> io::Result<ExitStatus> {
        let status = self
            .child
            .take()
            .ok_or_else(|| io::Error::other("frontend was already reaped"))?
            .wait();
        self.cleanup.take();
        status
    }

    /// Kills and reaps only the direct frontend.
    ///
    /// # Errors
    ///
    /// Returns an error when direct kill or reap fails.
    pub fn terminate(&mut self) -> io::Result<(ExitStatus, FrontendTerminationReport)> {
        let child = self.take_child()?;
        let cleanup = self.take_cleanup()?;
        terminate_frontend(child, cleanup)
    }

    /// Transfers direct kill/reap to a retained worker and waits until the deadline.
    ///
    /// # Errors
    ///
    /// Returns a receipt-backed timeout or a direct kill/reap error.
    pub fn terminate_until(
        &mut self,
        deadline: Instant,
    ) -> io::Result<(ExitStatus, FrontendTerminationReport)> {
        let child = self.take_child()?;
        let cleanup = self.take_cleanup()?;
        let receipt = RetainedFrontendTerminationReceipt::new(&cleanup);
        let (completion, receiver) = mpsc::sync_channel(1);
        termination_executor_sender()?
            .send(TerminationTask {
                child,
                cleanup,
                receipt: receipt.clone(),
                completion: Some(completion),
            })
            .map_err(|_| io::Error::other("frontend termination executor disconnected"))?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(retained_timeout(receipt));
        }
        match receiver.recv_timeout(remaining) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(retained_timeout(receipt)),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::other(
                "frontend termination receipt disconnected",
            )),
        }
    }

    fn take_child(&mut self) -> io::Result<Child> {
        self.child
            .take()
            .ok_or_else(|| io::Error::other("frontend was already reaped"))
    }

    fn take_cleanup(&mut self) -> io::Result<CleanupLease> {
        self.cleanup
            .take()
            .ok_or_else(|| io::Error::other("frontend cleanup admission was already consumed"))
    }
}

impl Drop for FrontendChild {
    fn drop(&mut self) {
        let (Some(child), Some(cleanup)) = (self.child.take(), self.cleanup.take()) else {
            return;
        };
        let receipt = RetainedFrontendTerminationReceipt::new(&cleanup);
        if let Ok(sender) = termination_executor_sender() {
            if let Err(error) = sender.send(TerminationTask {
                child,
                cleanup,
                receipt,
                completion: None,
            }) {
                let TerminationTask { child, cleanup, .. } = error.0;
                let _ = terminate_frontend(child, cleanup);
            }
        } else {
            let _ = terminate_frontend(child, cleanup);
        }
    }
}

fn terminate_frontend(
    mut child: Child,
    cleanup: CleanupLease,
) -> io::Result<(ExitStatus, FrontendTerminationReport)> {
    let kill_requested = match child.kill() {
        Ok(()) => true,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::NotFound
            ) =>
        {
            false
        }
        Err(error) => return Err(error),
    };
    let status = child.wait()?;
    let cleanup_id = cleanup.id();
    drop(cleanup);
    Ok((
        status,
        FrontendTerminationReport {
            cleanup_id,
            kill_requested,
            reaped: true,
        },
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetainedFrontendTerminationState {
    Owned,
    Completed(FrontendTerminationReport),
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct RetainedFrontendTerminationReceipt {
    id: u64,
    state: Arc<(Mutex<RetainedFrontendTerminationState>, Condvar)>,
    lifecycle: crate::CleanupLifecycleReceipt,
}

impl RetainedFrontendTerminationReceipt {
    fn new(cleanup: &CleanupLease) -> Self {
        Self {
            id: cleanup.id(),
            state: Arc::new((
                Mutex::new(RetainedFrontendTerminationState::Owned),
                Condvar::new(),
            )),
            lifecycle: cleanup.receipt(),
        }
    }

    fn finish(&self, result: &io::Result<(ExitStatus, FrontendTerminationReport)>) {
        *self
            .state
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = match result {
            Ok((_, report)) => RetainedFrontendTerminationState::Completed(*report),
            Err(error) => RetainedFrontendTerminationState::Failed(error.to_string()),
        };
        self.state.1.notify_all();
    }

    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    #[must_use]
    pub fn wait_until(&self, deadline: Instant) -> RetainedFrontendTerminationSnapshot {
        let mut state = self
            .state
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while matches!(*state, RetainedFrontendTerminationState::Owned) {
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
            if timeout.timed_out() && matches!(*state, RetainedFrontendTerminationState::Owned) {
                break;
            }
        }
        let state = state.clone();
        RetainedFrontendTerminationSnapshot {
            state,
            lifecycle_idle: self.lifecycle.wait_until(deadline),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedFrontendTerminationSnapshot {
    pub state: RetainedFrontendTerminationState,
    pub lifecycle_idle: bool,
}

#[derive(Debug)]
struct RetainedFrontendTerminationError {
    receipt: RetainedFrontendTerminationReceipt,
}

impl std::fmt::Display for RetainedFrontendTerminationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "frontend kill/reap exceeded its absolute deadline; cleanup receipt {} remains owned",
            self.receipt.id()
        )
    }
}

impl std::error::Error for RetainedFrontendTerminationError {}

fn retained_timeout(receipt: RetainedFrontendTerminationReceipt) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        RetainedFrontendTerminationError { receipt },
    )
}

#[must_use]
pub fn retained_frontend_termination_receipt(
    error: &io::Error,
) -> Option<RetainedFrontendTerminationReceipt> {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<RetainedFrontendTerminationError>())
        .map(|source| source.receipt.clone())
}

struct TerminationTask {
    child: Child,
    cleanup: CleanupLease,
    receipt: RetainedFrontendTerminationReceipt,
    completion: Option<mpsc::SyncSender<io::Result<(ExitStatus, FrontendTerminationReport)>>>,
}

fn termination_executor_sender() -> io::Result<mpsc::Sender<TerminationTask>> {
    static EXECUTOR: OnceLock<Result<mpsc::Sender<TerminationTask>, String>> = OnceLock::new();
    match EXECUTOR.get_or_init(|| {
        let (sender, receiver) = mpsc::channel::<TerminationTask>();
        std::thread::Builder::new()
            .name("hell-frontend-reaper".to_owned())
            .spawn(move || {
                while let Ok(task) = receiver.recv() {
                    let result = terminate_frontend(task.child, task.cleanup);
                    task.receipt.finish(&result);
                    if let Some(completion) = task.completion {
                        let _ = completion.send(result);
                    }
                }
            })
            .map_err(|error| format!("cannot start frontend cleanup executor: {error}"))?;
        Ok(sender)
    }) {
        Ok(sender) => Ok(sender.clone()),
        Err(error) => Err(io::Error::other(error.clone())),
    }
}
