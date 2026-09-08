//! Bounded command streams retained independently of candidate output trees.

use std::fs;
use std::path::Path;

use crate::release::manifest::write_atomic;

pub fn forward_nested_capture(
    captured_stdout: &[u8],
    captured_stderr: &[u8],
    mut stdout: impl std::io::Write,
    mut stderr: impl std::io::Write,
) -> std::io::Result<()> {
    let out = stdout.write_all(captured_stdout);
    let err = stderr.write_all(captured_stderr);
    out.and(err)
}
use hell_testkit::{BoundedCapture, SupervisedOutput};

pub fn retain(root: &Path, output: &SupervisedOutput) -> Result<(), String> {
    fs::create_dir_all(root.parent().ok_or("operation streams lack a parent")?)
        .map_err(|error| format!("cannot prepare operation stream parent: {error}"))?;
    fs::create_dir(root)
        .map_err(|error| format!("operation stream reservation is not fresh: {error}"))?;
    let stdout = retain_capture(root, "stdout", &output.stdout)?;
    let stderr = retain_capture(root, "stderr", &output.stderr)?;
    let mut receipt = serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version": 1, "exit_code": output.status.code(),
        "status": output.status.to_string(), "timed_out": output.timed_out,
        "stdout": stdout, "stderr": stderr,
    }))
    .map_err(|error| format!("cannot encode operation stream receipt: {error}"))?;
    receipt.push(b'\n');
    write_atomic(&root.join("capture.json"), &receipt)
}

fn retain_capture(
    root: &Path,
    name: &str,
    capture: &BoundedCapture,
) -> Result<serde_json::Value, String> {
    let directory = root.join(name);
    fs::create_dir(&directory)
        .map_err(|error| format!("cannot reserve operation capture: {error}"))?;
    if let Some(complete) = &capture.complete {
        write_atomic(&directory.join("complete"), complete)?;
    }
    write_atomic(&directory.join("prefix"), &capture.prefix)?;
    write_atomic(&directory.join("suffix"), &capture.suffix)?;
    Ok(serde_json::json!({
        "total_bytes": capture.total_bytes, "sha256": capture.sha256.hex(),
        "truncated": capture.truncated, "complete": capture.complete.is_some(),
        "prefix_bytes": capture.prefix.len(), "suffix_bytes": capture.suffix.len(),
        "prefix_sha256": hell_testkit::sha256_bytes(&capture.prefix).hex(),
        "suffix_sha256": hell_testkit::sha256_bytes(&capture.suffix).hex(),
    }))
}

pub fn failure(operation: &str, output: &SupervisedOutput) -> String {
    let excerpt = if output.stderr.prefix.is_empty() {
        &output.stdout.prefix
    } else {
        &output.stderr.prefix
    };
    let excerpt = String::from_utf8_lossy(&excerpt[..excerpt.len().min(4096)]);
    format!(
        "MemCordon operation {operation} returned {} (timed_out={}): {excerpt}",
        output.status, output.timed_out
    )
}

/// Retains only a typed failure diagnostic, never successful campaign evidence.
/// The caller must first establish candidate quiescence and return ownership.
#[cfg(unix)]
pub fn retain_blocked_fuzz_report(work: &Path, evidence: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    let output = work.join("ci-out");
    let report = output.join("fuzz-smoke.json");
    for directory in [work, output.as_path()] {
        let metadata = match fs::symlink_metadata(directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(format!("cannot inspect fuzz diagnostic directory: {error}")),
        };
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
        {
            return Err("fuzz diagnostic directory lacks retained owner authority".to_owned());
        }
    }
    let before = match fs::symlink_metadata(&report) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("cannot inspect blocked fuzz report: {error}")),
    };
    // This diagnostic contains only two short strings, not campaign captures.
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.nlink() != 1
        || before.uid() != nix::unistd::geteuid().as_raw()
        || before.len() > 1024 * 1024
    {
        return Err("blocked fuzz report lacks bounded regular-file authority".to_owned());
    }
    let bytes = crate::release::manifest::read_regular(&report)?;
    let after = fs::symlink_metadata(&report).map_err(|error| error.to_string())?;
    if before.dev() != after.dev() || before.ino() != after.ino() || before.len() != after.len() {
        return Err("blocked fuzz report changed during retention".to_owned());
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct BlockedDiagnostic {
        schema_version: u32,
        state: String,
        diagnostic_code: String,
        diagnostic_message: String,
    }
    let value: BlockedDiagnostic = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid blocked fuzz report: {error}"))?;
    if value.schema_version != 1
        || value.state != "blocked"
        || value.diagnostic_code.is_empty()
        || value.diagnostic_message.is_empty()
    {
        return Err("fuzz diagnostic differs from the blocked-report schema".to_owned());
    }
    let directory = evidence.join("diagnostics");
    fs::create_dir(&directory)
        .map_err(|error| format!("cannot reserve fuzz diagnostic retention: {error}"))?;
    crate::release::manifest::write_atomic_new(&directory.join("fuzz-smoke.json"), &bytes)
}
