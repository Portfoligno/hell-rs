use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::time::Duration;

use hell_memcordon::{
    AcquisitionReceiptV1, NativeArgument, ProviderLifecycleReceiptV1, ProviderLifecycleState,
    project_schema8_report,
};

use crate::json::{JsonValue, parse_json};
use crate::release::manifest::{write_atomic, write_json};

use super::provider::{
    agent_name, cli_name, create_evidence_directories, find_component, number,
    run_provider_frontend, string,
};
use super::task::Task;

const CANARY_BUDGET: Duration = Duration::from_mins(1);
const REPORT_LIMIT: u64 = 8 * 1024 * 1024;

pub(super) fn run(task: &Task) -> Result<String, String> {
    create_evidence_directories(&task.output)?;
    require_qualified_lease(task)?;
    let cli = find_component(&task.runtime_root, cli_name())?;
    let target = find_component(&task.runtime_root, agent_name())?;
    let report_path = task.output.join("raw/provider-adoption-canary.json");
    if report_path.exists() {
        return Err("MemCordon canary report path is not a fresh reservation".to_owned());
    }
    let arguments = vec![
        OsString::from("--sealed"),
        OsString::from("--quiet"),
        OsString::from("--report"),
        report_path.as_os_str().to_owned(),
        OsString::from("+45000ms"),
        OsString::from("--deadline-scope"),
        OsString::from("attempt"),
        OsString::from("--wait-for"),
        OsString::from("command"),
        OsString::from("--command-exit-grace"),
        OsString::from("0ms"),
        OsString::from("--"),
        target.as_os_str().to_owned(),
        OsString::from("--version"),
    ];
    let result = run_provider_frontend(&cli, &arguments, CANARY_BUDGET, 2 * 1024 * 1024)?;
    write_atomic(
        &task.output.join("qualification-artifacts/canary.stdout"),
        &result.stdout,
    )?;
    write_atomic(
        &task.output.join("qualification-artifacts/canary.stderr"),
        &result.stderr,
    )?;
    if !result.status.success() || result.stdout_overflow || result.stderr_overflow {
        return Err(format!(
            "MemCordon provider adoption canary failed with {}",
            result.status
        ));
    }
    let report_metadata = fs::symlink_metadata(&report_path)
        .map_err(|error| format!("MemCordon canary report is missing: {error}"))?;
    if !report_metadata.is_file()
        || report_metadata.file_type().is_symlink()
        || report_metadata.len() > REPORT_LIMIT
    {
        return Err("MemCordon canary report is not one bounded regular file".to_owned());
    }
    let report = fs::read(&report_path)
        .map_err(|error| format!("cannot read MemCordon canary report: {error}"))?;
    let acquisition_bytes = fs::read(task.output.join("acquisition.json"))
        .map_err(|error| format!("cannot read MemCordon acquisition receipt: {error}"))?;
    let acquisition: AcquisitionReceiptV1 = serde_json::from_slice(&acquisition_bytes)
        .map_err(|error| format!("invalid MemCordon acquisition receipt: {error}"))?;
    let expected_target_argv = [
        NativeArgument::from_os_str(target.as_os_str()),
        NativeArgument::from_os_str(std::ffi::OsStr::new("--version")),
    ];
    let projection = project_schema8_report(&report, &acquisition.mechanism, &expected_target_argv)
        .map_err(|error| error.to_string())?;
    let projection_path = task.output.join("normalized/provider-adoption-canary.json");
    write_serde(&projection_path, &projection)?;
    let projection_bytes = fs::read(&projection_path)
        .map_err(|error| format!("cannot read MemCordon canary projection: {error}"))?;
    let receipt = JsonValue::Object(BTreeMap::from([
        (
            "canaries".to_owned(),
            JsonValue::Array(vec![JsonValue::Object(BTreeMap::from([
                ("id".to_owned(), string("provider-adoption")),
                (
                    "reportSha256".to_owned(),
                    string(&hell_testkit::sha256_bytes(&report).hex()),
                ),
                (
                    "projectionSha256".to_owned(),
                    string(&hell_testkit::sha256_bytes(&projection_bytes).hex()),
                ),
                ("stderrBytes".to_owned(), size(result.stderr.len())?),
                (
                    "stderrSha256".to_owned(),
                    string(&hell_testkit::sha256_bytes(&result.stderr).hex()),
                ),
                ("stdoutBytes".to_owned(), size(result.stdout.len())?),
                (
                    "stdoutSha256".to_owned(),
                    string(&hell_testkit::sha256_bytes(&result.stdout).hex()),
                ),
            ]))]),
        ),
        ("operation".to_owned(), string(&task.operation)),
        ("platform".to_owned(), string(Task::platform_id()?)),
        ("schemaVersion".to_owned(), number(1)),
    ]));
    write_json(&task.output.join("canaries.json"), &receipt)?;
    Ok(format!(
        "MemCordon provider adoption canary passed for {}",
        Task::platform_id()?
    ))
}

fn require_qualified_lease(task: &Task) -> Result<(), String> {
    let bytes = fs::read(task.output.join("provider-lease.json"))
        .map_err(|error| format!("cannot read MemCordon provider lease: {error}"))?;
    let lease: ProviderLifecycleReceiptV1 = serde_json::from_slice(&bytes)
        .map_err(|error| format!("MemCordon provider lease is invalid: {error}"))?;
    if lease.state != ProviderLifecycleState::Qualified
        || lease.lease_owner != "job"
        || lease.admission_closed
        || lease.active_operations != 0
    {
        return Err("MemCordon provider lease is not qualified for this operation".to_owned());
    }
    Ok(())
}

fn size(value: usize) -> Result<JsonValue, String> {
    u64::try_from(value)
        .map(number)
        .map_err(|_| "MemCordon canary byte count overflow".to_owned())
}

fn write_serde(path: &std::path::Path, value: &impl serde::Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("cannot serialize MemCordon canary projection: {error}"))?;
    let text = std::str::from_utf8(&bytes).expect("JSON serializer emits UTF-8");
    write_json(path, &parse_json(text)?)?;
    Ok(())
}
