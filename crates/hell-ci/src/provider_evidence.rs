//! Provider command evidence is retained before qualification validation.

use std::path::Path;
use std::process::ExitStatus;

use crate::json::parse_json;
use crate::release::manifest::{write_atomic, write_json};

pub struct Captured {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_overflow: bool,
    pub stderr_overflow: bool,
}

pub fn require_json_success(captured: &Captured, label: &str) -> Result<(), String> {
    require_success(captured, label)?;
    let text = std::str::from_utf8(&captured.stdout)
        .map_err(|_| format!("{label} output is not UTF-8 JSON"))?;
    parse_json(text).map(|_| ())
}

pub fn require_success(captured: &Captured, label: &str) -> Result<(), String> {
    if captured.stdout_overflow || captured.stderr_overflow {
        return Err(format!("{label} exceeded its output bound"));
    }
    if !captured.status.success() {
        let diagnostic = String::from_utf8_lossy(&captured.stderr);
        let diagnostic = if diagnostic.trim().is_empty() {
            "stderr was empty; see retained command stdout and status receipt".into()
        } else {
            diagnostic
        };
        return Err(format!(
            "{label} failed with {}: {diagnostic}",
            captured.status
        ));
    }
    Ok(())
}

pub fn retain_command(prefix: &Path, captured: &Captured) -> Result<(), String> {
    let mut stdout = prefix.as_os_str().to_owned();
    stdout.push(".stdout");
    let mut stderr = prefix.as_os_str().to_owned();
    stderr.push(".stderr");
    write_atomic(Path::new(&stdout), &captured.stdout)?;
    write_atomic(Path::new(&stderr), &captured.stderr)?;
    let mut receipt = prefix.as_os_str().to_owned();
    receipt.push(".json");
    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt;
        captured.status.signal()
    };
    #[cfg(not(unix))]
    let signal: Option<i32> = None;
    write_serde(
        Path::new(&receipt),
        &serde_json::json!({
            "exitCode": captured.status.code(), "signal": signal,
            "stdoutOverflow": captured.stdout_overflow, "stderrOverflow": captured.stderr_overflow,
            "stdoutRetainedBytes": captured.stdout.len(), "stderrRetainedBytes": captured.stderr.len(),
        }),
    )
}

fn write_serde(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("cannot serialize MemCordon receipt: {error}"))?;
    let text = std::str::from_utf8(&bytes).expect("JSON serializer emits UTF-8");
    write_json(path, &parse_json(text)?)?;
    Ok(())
}

pub fn retain_json_command(prefix: &Path, captured: &Captured, label: &str) -> Result<(), String> {
    retain_command(prefix, captured)?;
    require_json_success(captured, label)
}
