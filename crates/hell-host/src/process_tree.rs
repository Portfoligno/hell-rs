//! Safe cross-platform process-group and Windows Job Object supervision.

use std::io;
use std::process::{ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus};
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
}

impl SupervisedChild {
    /// Spawns `command` in a fresh platform process-tree boundary.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when the group/job or child cannot be
    /// created.
    pub fn spawn(command: &mut Command) -> io::Result<Self> {
        command
            .group_spawn()
            .map(|child| Self { child: Some(child) })
    }

    /// Returns the process leader identifier, or zero after reap.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.child.as_ref().map_or(0, GroupChild::id)
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

    /// Polls the whole process tree until it exits or `deadline` is reached.
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

    /// Force-terminates and reaps every process in the group/job.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error if the tree cannot be killed or
    /// reaped. An already-exited group is still reaped successfully.
    pub fn terminate(&mut self) -> io::Result<(ExitStatus, TerminationReport)> {
        let mut child = self
            .child
            .take()
            .ok_or_else(|| io::Error::other("process tree was already reaped"))?;
        match child.kill() {
            Ok(()) => {}
            Err(error) if process_tree_is_absent(&error) => {}
            Err(error) => return Err(error),
        }
        let status = child.wait()?;
        Ok((
            status,
            TerminationReport {
                forced: true,
                reaped: true,
            },
        ))
    }

    /// Waits for normal whole-tree completion and consumes the guard.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when the process tree cannot be
    /// reaped.
    pub fn wait(mut self) -> io::Result<ExitStatus> {
        self.child
            .take()
            .ok_or_else(|| io::Error::other("process tree was already reaped"))?
            .wait()
    }
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
        if let Some(mut child) = self.child.take() {
            if matches!(child.try_wait(), Ok(None)) {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}
