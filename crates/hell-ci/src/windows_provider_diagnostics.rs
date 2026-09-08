//! Bounded, non-authoritative diagnostics. Never consumed for sealed admission.
use serde_json::{Value, json};

const MAX_RECORD_BYTES: usize = 256 * 1024;
#[cfg(windows)]
const MAX_RECORDS: usize = 32;

fn enumeration(value: &Value, choices: &[&str]) -> Result<Value, String> {
    value
        .as_str()
        .filter(|value| choices.contains(value))
        .map(|value| json!(value))
        .ok_or_else(|| "invalid diagnostic enum".to_owned())
}

fn error_projection(value: &Value) -> Result<Value, String> {
    if value.is_null() {
        return Ok(Value::Null);
    }
    let code = value["error_code"]
        .as_str()
        .filter(|code| {
            !code.is_empty()
                && code.len() <= 128
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
        })
        .ok_or_else(|| "invalid diagnostic error code".to_owned())?;
    let native = &value["native_code"];
    if !native.is_null()
        && native
            .as_i64()
            .and_then(|n| i32::try_from(n).ok())
            .is_none()
    {
        return Err("invalid diagnostic native code".to_owned());
    }
    Ok(json!({
        "stage": enumeration(&value["stage"], &["launch-relay", "cleanup-finalize", "receipt-build", "rejection-build", "response-validate", "response-serialize", "record-authenticate", "atomic-store", "live-delivery", "terminal-ack", "outbox-retirement"] )?,
        "error_code": code, "native_code": native,
        "detail": "omitted: provider free-form text is not exported"
    }))
}

/// Project only documented nonsecret diagnostic fields, never arbitrary record content.
pub fn project_record(bytes: &[u8], name: &str) -> Result<Value, String> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err("diagnostic record byte limit exceeded".to_owned());
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "invalid diagnostic JSON".to_owned())?;
    let id = name
        .strip_suffix(".json")
        .filter(|id| {
            !id.is_empty() && id.len() <= 128 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .ok_or_else(|| "invalid diagnostic record filename".to_owned())?;
    if value["attempt_id"].as_str() != Some(id) || value["schema_version"].as_u64() != Some(1) {
        return Err("diagnostic record identity/schema differs".to_owned());
    }
    let mut projected = json!({"attempt_id": id, "state": enumeration(&value["state"], &["boundary-created", "guardian-ready", "target-created-suspended", "authorized", "terminating", "empty"])?});
    for key in ["resume_attempted", "target_released"] {
        projected[key] = json!(
            value[key]
                .as_bool()
                .ok_or_else(|| "invalid diagnostic flag".to_owned())?
        );
    }
    let mut cleanup = json!({});
    for key in [
        "termination_requested",
        "active_processes_zero",
        "guardian_reaped",
        "final_handles_closed",
    ] {
        cleanup[key] = json!(
            value["cleanup_state"][key]
                .as_bool()
                .ok_or_else(|| "invalid diagnostic cleanup flag".to_owned())?
        );
    }
    projected["cleanup_state"] = cleanup;
    projected["terminal_disposition"] = if value["terminal_disposition"].is_null() {
        Value::Null
    } else {
        enumeration(
            &value["terminal_disposition"],
            &["preauthorization-abort", "posttarget"],
        )?
    };
    let status = &value["terminalization"];
    if status["schema_version"].as_u64() != Some(1) {
        return Err("invalid terminalization schema".to_owned());
    }
    let secondary = match status.get("secondary_errors") {
        None => Vec::new(),
        Some(Value::Array(errors)) if errors.len() <= 16 => errors
            .iter()
            .map(error_projection)
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err("diagnostic secondary error limit/type differs".to_owned()),
    };
    projected["terminalization"] = json!({
        "owner": enumeration(&status["owner"], &["launcher-worker", "control-service", "startup-recovery", "guardian-recovery"] )?,
        "checkpoint": enumeration(&status["checkpoint"], &["executing", "cleanup-requested", "cleanup-proof-ready", "rejection-building", "outbox-staging", "outbox-staged", "ack-retiring", "retained-failure"] )?,
        "sequence": status["sequence"].as_u64().ok_or_else(|| "invalid diagnostic sequence".to_owned())?,
        "last_error": error_projection(&status["last_error"] )?, "secondary_errors": secondary
    });
    Ok(projected)
}

#[cfg(windows)]
pub(crate) fn collect() -> Value {
    let result = collect_native();
    match result {
        Ok(records) => {
            json!({"schema_version": 1, "status": "collected", "admissible_evidence": false, "original_service_error_may_be_unavailable": true, "records": records})
        }
        Err(error) => {
            json!({"schema_version": 1, "status": "unavailable", "admissible_evidence": false, "original_service_error_may_be_unavailable": true, "error": error})
        }
    }
}

#[cfg(windows)]
pub fn native_program_data_root() -> Result<std::path::PathBuf, String> {
    let root = known_folders::get_known_folder_path(known_folders::KnownFolder::ProgramData)
        .ok_or_else(|| "native ProgramData lookup failed".to_owned())?;
    if !root.is_absolute() {
        return Err("native ProgramData is not absolute".to_owned());
    }
    Ok(root)
}

#[cfg(windows)]
fn collect_native() -> Result<Vec<Value>, String> {
    use std::fs::{File, OpenOptions};
    use std::io::Read;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Component, Path, PathBuf};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ,
    };

    fn io_error(error: std::io::Error) -> String {
        format!(
            "native diagnostic read failed ({:?}, code {:?})",
            error.kind(),
            error.raw_os_error()
        )
    }
    fn pin(path: &Path, directory: bool) -> Result<File, String> {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(
                FILE_FLAG_OPEN_REPARSE_POINT
                    | if directory {
                        FILE_FLAG_BACKUP_SEMANTICS
                    } else {
                        0
                    },
            )
            .open(path)
            .map_err(io_error)?;
        let metadata = file.metadata().map_err(io_error)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.is_dir() != directory
            || (!directory && !metadata.is_file())
        {
            return Err("diagnostic path is a reparse point or wrong object type".to_owned());
        }
        Ok(file)
    }
    let root = native_program_data_root()?;
    let mut path = PathBuf::new();
    let mut retained = Vec::new();
    for component in root.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => path.push(component.as_os_str()),
            Component::Normal(_) => {
                path.push(component.as_os_str());
                retained.push(pin(&path, true)?);
            }
            _ => return Err("native ProgramData has noncanonical components".to_owned()),
        }
    }
    for component in ["MemCordon", "sealed", "attempts"] {
        path.push(component);
        retained.push(pin(&path, true)?);
    }
    let mut records = Vec::new();
    let mut total_bytes = 0;
    for entry in std::fs::read_dir(&path).map_err(io_error)? {
        if records.len() >= MAX_RECORDS {
            return Err("diagnostic record count limit exceeded".to_owned());
        }
        let entry = entry.map_err(io_error)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "non-Unicode diagnostic filename".to_owned())?;
        let file = pin(&entry.path(), false)?;
        if file.metadata().map_err(io_error)?.len() > MAX_RECORD_BYTES as u64 {
            return Err("diagnostic record byte limit exceeded".to_owned());
        }
        let mut bytes = Vec::new();
        file.take(MAX_RECORD_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        total_bytes += bytes.len();
        if total_bytes > 1024 * 1024 {
            return Err("diagnostic aggregate byte limit exceeded".to_owned());
        }
        records.push(project_record(&bytes, &name)?);
    }
    records.sort_by(|left, right| {
        left["attempt_id"]
            .as_str()
            .cmp(&right["attempt_id"].as_str())
    });
    drop(retained);
    Ok(records)
}
