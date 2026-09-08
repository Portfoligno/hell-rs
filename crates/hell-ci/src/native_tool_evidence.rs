//! Failure-only native identity-query diagnostics, never admission evidence.
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::command::CommandResult;
use crate::release::manifest::write_atomic_new;

#[doc(hidden)]
pub use crate::command::{
    CommandResult as NativeToolCommandResult, CommandTerminationResult as NativeToolTermination,
};

const MAX_RETAINED_STREAM_BYTES: usize = 4 * 1024 * 1024;

pub struct NativeToolQuery<'a> {
    pub tool: &'a str,
    pub executable: &'a Path,
    pub executable_sha256: &'a str,
    pub arguments: &'a [&'a str],
    pub directory: &'a Path,
    pub resolution_duration: Duration,
    pub hashing_duration: Duration,
    pub execution_budget: Duration,
    pub collection_remaining: Duration,
    pub started_unix_millis: u128,
}

fn native_path(path: &Path) -> Result<serde_json::Value, String> {
    let value: &OsStr = path.as_os_str();
    #[cfg(unix)]
    let (encoding, units) = {
        use std::os::unix::ffi::OsStrExt as _;
        (
            "unix-bytes",
            value
                .as_bytes()
                .iter()
                .take(32 * 1024 + 1)
                .map(|byte| u32::from(*byte))
                .collect::<Vec<_>>(),
        )
    };
    #[cfg(windows)]
    let (encoding, units) = {
        use std::os::windows::ffi::OsStrExt as _;
        (
            "windows-utf16",
            value
                .encode_wide()
                .take(32 * 1024 + 1)
                .map(u32::from)
                .collect::<Vec<_>>(),
        )
    };
    if units.len() > 32 * 1024 {
        return Err("native tool diagnostic path exceeds bound".to_owned());
    }
    Ok(serde_json::json!({"display":path.to_string_lossy(), "encoding":encoding, "units":units}))
}

fn receipt(
    query: &NativeToolQuery<'_>,
    primary: &str,
    elapsed: Duration,
    result: Option<&CommandResult>,
) -> Result<Vec<u8>, String> {
    if query.tool.len() > 128
        || query.arguments.len() > 32
        || query.arguments.iter().any(|arg| arg.len() > 4096)
    {
        return Err("native tool diagnostic context exceeds bound".to_owned());
    }
    let capture = result.map(|result| {
        #[cfg(unix)]
        let signal = { use std::os::unix::process::ExitStatusExt as _; result.status.signal() };
        #[cfg(not(unix))]
        let signal: Option<i32> = None;
        serde_json::json!({
            "exitCode":result.status.code(), "signal":signal, "status":result.status.to_string(),
            "timedOut":result.timed_out, "forced":result.termination.forced, "reaped":result.termination.reaped,
            "candidateQuiescenceComplete":result.termination.candidate_quiescence_complete,
            "durationMillis":result.duration.as_millis(),
            "stdoutObservedBytes":result.stdout_bytes, "stderrObservedBytes":result.stderr_bytes,
            "stdoutRetainedBytes":result.stdout.len(), "stderrRetainedBytes":result.stderr.len(),
            "stdoutSha256":result.stdout_sha256.hex(), "stderrSha256":result.stderr_sha256.hex(),
            "stdoutRetainedSha256":hell_testkit::sha256_bytes(&result.stdout).hex(),
            "stderrRetainedSha256":hell_testkit::sha256_bytes(&result.stderr).hex(),
            "stdoutTruncated":result.stdout_truncated, "stderrTruncated":result.stderr_truncated,
        })
    });
    let primary: String = primary.chars().take(4096).collect();
    let mut bytes = serde_json::to_vec(&serde_json::json!({
        "schemaVersion":1, "kind":"native-tool-query-failure", "admissionEvidence":false,
        "toolId":query.tool, "executable":native_path(query.executable)?,
        "executableSha256":query.executable_sha256, "arguments":query.arguments,
        "workingDirectory":native_path(query.directory)?, "queryStartedUnixMillis":query.started_unix_millis,
        "resolutionMillis":query.resolution_duration.as_millis(), "hashingMillis":query.hashing_duration.as_millis(),
        "executionBudgetMillis":query.execution_budget.as_millis(),
        "collectionRemainingAtQueryStartMillis":query.collection_remaining.as_millis(),
        "queryElapsedMillis":elapsed.as_millis(), "primary":primary, "capture":capture,
    })).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn reserve(output: &Path) -> Result<PathBuf, String> {
    let output = std::path::absolute(output).map_err(|error| error.to_string())?;
    let parent = output
        .parent()
        .ok_or("native tool diagnostics have no output parent")?;
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|error| error.to_string())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(
                "native tool diagnostic parent is redirected or not a directory".to_owned(),
            );
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err("native tool diagnostic parent is a reparse point".to_owned());
            }
        }
    }
    // Canonicalization may add Windows' extended path prefix without redirecting
    // the directory. Bind the checked parent, rather than comparing path spelling.
    let directory = fs::canonicalize(parent)
        .map_err(|error| error.to_string())?
        .join(
            output
                .file_name()
                .ok_or("native tool diagnostics have no output name")?,
        )
        .with_extension("tool-failure");
    fs::create_dir(&directory)
        .map_err(|error| format!("cannot reserve native tool diagnostic directory: {error}"))?;
    Ok(directory)
}

/// Preserve the query's primary error even if diagnostic persistence also fails.
pub fn retain_failure(
    output: Option<&Path>,
    query: &NativeToolQuery<'_>,
    primary: String,
    elapsed: Duration,
    result: Option<&CommandResult>,
) -> String {
    let Some(output) = output else {
        return primary;
    };
    let directory = match reserve(output) {
        Ok(directory) => directory,
        Err(error) => {
            return format!("{primary}; native tool diagnostic persistence failed: {error}");
        }
    };
    let mut failures = Vec::new();
    if let Some(result) = result {
        // The supervisor has already bounded these original retained streams.
        // Do not apply a second lossy text summary or erase binary output.
        for (name, bytes) in [("stdout", &result.stdout), ("stderr", &result.stderr)] {
            if bytes.len() > MAX_RETAINED_STREAM_BYTES {
                failures.push(format!(
                    "native tool {name} exceeds supervisor capture bound"
                ));
                continue;
            }
            if let Err(error) = write_atomic_new(&directory.join(name), bytes) {
                failures.push(error);
            }
        }
    }
    if let Err(error) = receipt(query, &primary, elapsed, result)
        .and_then(|bytes| write_atomic_new(&directory.join("query.json"), &bytes))
    {
        failures.push(error);
    }
    if failures.is_empty() {
        format!(
            "{primary}; native tool diagnostics: {}",
            directory.display()
        )
    } else {
        format!(
            "{primary}; native tool diagnostic persistence failed: {}",
            failures.join("; ")
        )
    }
}
