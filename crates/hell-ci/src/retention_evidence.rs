//! Diagnostic-only receipts for trusted work-tree retention attempts.

#[cfg(unix)]
pub mod entry;

#[cfg(unix)]
pub mod tree;

use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::Duration;

use crate::release::manifest::write_atomic_new;

#[derive(Clone, Copy)]
pub enum Attempt {
    Primary,
    CleanupRetry,
}

impl Attempt {
    pub fn directory(self, evidence: &Path) -> PathBuf {
        evidence.join("retention").join(match self {
            Self::Primary => "primary",
            Self::CleanupRetry => "cleanup-retry",
        })
    }
}

pub struct CapturedAdapter<'a> {
    pub status: ExitStatus,
    pub duration: Duration,
    pub timed_out: bool,
    pub stdout: &'a [u8],
    pub stderr: &'a [u8],
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_sha256: hell_testkit::Digest,
    pub stderr_sha256: hell_testkit::Digest,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

impl<'a> From<&'a crate::command::CommandResult> for CapturedAdapter<'a> {
    fn from(result: &'a crate::command::CommandResult) -> Self {
        Self {
            status: result.status,
            duration: result.duration,
            timed_out: result.timed_out,
            stdout: &result.stdout,
            stderr: &result.stderr,
            stdout_bytes: result.stdout_bytes,
            stderr_bytes: result.stderr_bytes,
            stdout_sha256: result.stdout_sha256,
            stderr_sha256: result.stderr_sha256,
            stdout_truncated: result.stdout_truncated,
            stderr_truncated: result.stderr_truncated,
        }
    }
}

fn classification(
    captured: &CapturedAdapter<'_>,
    deadline_expired: bool,
) -> (&'static str, Result<(), String>) {
    if captured.timed_out {
        (
            "capture-timeout",
            Err("Linux MemCordon retention adapter capture timed out".to_owned()),
        )
    } else if !captured.status.success() {
        (
            "unsuccessful-exit",
            Err(format!(
                "Linux MemCordon retention adapter exited unsuccessfully: {}",
                captured.status
            )),
        )
    } else if deadline_expired {
        (
            "deadline-expired",
            Err("Linux MemCordon retention deadline expired after adapter completion".to_owned()),
        )
    } else {
        ("completed", Ok(()))
    }
}

fn json_bytes(value: &serde_json::Value) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn combine(primary: Result<(), String>, failures: Vec<String>) -> Result<(), String> {
    if failures.is_empty() {
        return primary;
    }
    let persistence = format!(
        "retention diagnostic persistence failed: {}",
        failures.join("; ")
    );
    match primary {
        Ok(()) => Err(persistence),
        Err(primary) => Err(format!("{primary}; additionally, {persistence}")),
    }
}

pub fn retain_result(
    root: &Path,
    captured: &CapturedAdapter<'_>,
    deadline_expired: bool,
) -> Result<(), String> {
    let (classification, primary) = classification(captured, deadline_expired);
    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt;
        captured.status.signal()
    };
    #[cfg(not(unix))]
    let signal: Option<i32> = None;
    let receipt = serde_json::json!({"schema_version":1, "classification":classification,
        "capture_available":true, "exit_code":captured.status.code(), "signal":signal,
        "timed_out":captured.timed_out, "deadline_expired":deadline_expired,
        "duration_millis":captured.duration.as_millis(),
        "stdout_bytes":captured.stdout_bytes, "stderr_bytes":captured.stderr_bytes,
        "stdout_retained_bytes":captured.stdout.len(), "stderr_retained_bytes":captured.stderr.len(),
        "stdout_sha256":captured.stdout_sha256.hex(), "stderr_sha256":captured.stderr_sha256.hex(),
        "stdout_truncated":captured.stdout_truncated, "stderr_truncated":captured.stderr_truncated});
    let mut failures = Vec::new();
    for (name, bytes) in [("stdout", captured.stdout), ("stderr", captured.stderr)] {
        if let Err(error) = write_atomic_new(&root.join(name), bytes) {
            failures.push(error);
        }
    }
    match json_bytes(&receipt).and_then(|bytes| write_atomic_new(&root.join("result.json"), &bytes))
    {
        Ok(()) => {}
        Err(error) => failures.push(error),
    }
    combine(primary, failures)
}

pub fn retain_failure(
    root: &Path,
    primary: String,
    elapsed: Duration,
    deadline_expired: bool,
    timed_out: Option<bool>,
) -> String {
    let receipt = serde_json::json!({"schema_version":1, "classification":"retention-failure",
        "duration_millis":elapsed.as_millis(),
        "deadline_expired":deadline_expired, "timed_out":timed_out, "error":primary});
    let failures = json_bytes(&receipt)
        .and_then(|bytes| write_atomic_new(&root.join("failure.json"), &bytes))
        .err()
        .into_iter()
        .collect();
    combine(Err(primary), failures).expect_err("an execution failure remains a failure")
}
