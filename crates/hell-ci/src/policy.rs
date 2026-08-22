mod release_workflow;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::command::CommandSpec;
use crate::json::JsonValue;

const REPOSITORY_INVENTORY_ENTRY_LIMIT: usize = 100_000;
const REPOSITORY_INVENTORY_PATH_BYTE_LIMIT: usize = 8 * 1024 * 1024;
const REPOSITORY_INVENTORY_DETAIL_LIMIT: usize = 2 * 1024;

thread_local! {
    static REPOSITORY_INVENTORY_EVIDENCE: RefCell<Option<JsonValue>> = const { RefCell::new(None) };
}

pub(crate) fn take_repository_inventory_evidence() -> Option<JsonValue> {
    REPOSITORY_INVENTORY_EVIDENCE.with(|slot| slot.borrow_mut().take())
}

#[derive(Debug)]
pub(crate) struct RepositoryInventoryReceipt {
    root: PathBuf,
    paths: Vec<PathBuf>,
    status: Option<i32>,
    timed_out: bool,
    stdout_truncated: bool,
    stderr_truncated: bool,
    stdout_bytes: u64,
    stderr_bytes: u64,
    stdout_sha256: hell_testkit::Digest,
    stderr_sha256: hell_testkit::Digest,
    cleanup_id: Option<u64>,
    termination_forced: bool,
    termination_reaped: bool,
    #[cfg(windows)]
    candidate_quiescence_complete: bool,
    #[cfg(windows)]
    windows_launch_control: Option<hell_testkit::WindowsLaunchControlReceipt>,
}

pub fn check_repository(root: &Path) -> Result<(), String> {
    let inventory = tracked_files(root)?;
    inventory.validate()?;
    let tracked = inventory.paths;
    let mut failures = Vec::new();
    for path in &tracked {
        check_tracked_file(root, path, &mut failures);
    }
    release_workflow::check(root, &tracked, &mut failures);
    check_dormant_collection_activation(root, &mut failures);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

impl RepositoryInventoryReceipt {
    fn validate(&self) -> Result<(), String> {
        if self.status != Some(0)
            || fs::canonicalize(&self.root).ok().as_deref() != Some(self.root.as_path())
            || self.timed_out
            || self.stdout_truncated
            || self.stderr_truncated
            || self.stderr_bytes != 0
            || self.stdout_bytes < u64::try_from(self.paths.len()).unwrap_or(u64::MAX)
            || self.stdout_sha256 == hell_testkit::Digest::default()
            || self.stderr_sha256 != hell_testkit::sha256_bytes(&[])
            || self.cleanup_id.is_none()
            || !self.termination_forced
            || !self.termination_reaped
        {
            return Err("repository inventory terminal receipt is inconsistent".to_owned());
        }
        #[cfg(windows)]
        if self.windows_launch_control.as_ref().is_none_or(|control| {
            control.validate().is_err()
                || control.state != "completed"
                || control.program.is_none()
                || control.program_bytes.is_none()
                || control.program_sha256.is_none()
                || control.current_directory != self.root
                || control.termination_forced != self.termination_forced
                || control.termination_reaped != self.termination_reaped
                || control.candidate_quiescence_complete != self.candidate_quiescence_complete
        }) {
            return Err("repository inventory Windows launch receipt is incomplete".to_owned());
        }
        Ok(())
    }
}

#[cfg(windows)]
pub(crate) fn verify_repository_inventory_for_integration(root: &Path) -> Result<(), String> {
    let inventory = tracked_files(root)?;
    inventory.validate()?;
    let control = inventory
        .windows_launch_control
        .as_ref()
        .ok_or_else(|| "Windows repository inventory launch receipt is absent".to_owned())?;
    if inventory.paths.is_empty()
        || control.validate().is_err()
        || control.schema_version != 1
        || control.state != "completed"
        || control.phases.len() != 12
        || control.bytes == 0
        || control.sha256 == hell_testkit::Digest::default()
        || control.status_code != Some(0)
        || control.timed_out
        || !control.termination_forced
        || !control.termination_reaped
        || !control.candidate_quiescence_complete
        || control
            .program
            .as_deref()
            .and_then(Path::file_name)
            .is_none_or(|name| {
                !name.eq_ignore_ascii_case(std::ffi::OsStr::new("git.exe"))
                    && !name.eq_ignore_ascii_case(std::ffi::OsStr::new("git"))
            })
        || control.current_directory != root
    {
        return Err("Windows repository inventory launch receipt differs".to_owned());
    }
    let mut corrupted = control.clone();
    corrupted.request_sha256 = hell_testkit::Digest::default();
    if corrupted.validate().is_ok() {
        return Err("corrupted Windows repository launch receipt was accepted".to_owned());
    }
    Ok(())
}

pub(crate) fn normalized_relative_path(value: &str) -> Result<PathBuf, String> {
    if value.is_empty()
        || value.contains('\\')
        || value
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(format!("path is not a normalized relative path: {value:?}"));
    }
    let path = PathBuf::from(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!("path is not a normalized relative path: {value:?}"));
    }
    Ok(path)
}

fn tracked_files(root: &Path) -> Result<RepositoryInventoryReceipt, String> {
    REPOSITORY_INVENTORY_EVIDENCE.with(|slot| slot.replace(None));
    let result = match CommandSpec::new("git", Duration::from_secs(30))
        .git_safe_directory(root)
        .arguments(["ls-files", "-z"])
        .current_directory(root)
        .run()
    {
        Ok(result) => result,
        Err(error) => {
            REPOSITORY_INVENTORY_EVIDENCE.with(|slot| {
                slot.replace(Some(JsonValue::Object(BTreeMap::from([
                    ("detail".to_owned(), JsonValue::String(error.to_string())),
                    (
                        "phase".to_owned(),
                        JsonValue::String(error.phase().as_str().to_owned()),
                    ),
                    ("schemaVersion".to_owned(), JsonValue::Number(2)),
                    (
                        "state".to_owned(),
                        JsonValue::String("unavailable".to_owned()),
                    ),
                ]))))
            });
            return Err(format!("cannot inventory tracked files: {error}"));
        }
    };
    REPOSITORY_INVENTORY_EVIDENCE
        .with(|slot| slot.replace(Some(repository_inventory_evidence(&result))));
    require_repository_inventory_command(&result)?;
    if !result.stdout.is_empty() && !result.stdout.ends_with(&[0]) {
        return Err("git ls-files returned an unterminated repository inventory".to_owned());
    }
    if result.stdout.len() > REPOSITORY_INVENTORY_PATH_BYTE_LIMIT {
        return Err("git ls-files repository inventory exceeds its byte bound".to_owned());
    }
    let mut paths = result
        .stdout
        .split(|byte| *byte == 0)
        .filter(|bytes| !bytes.is_empty())
        .map(|bytes| {
            std::str::from_utf8(bytes)
                .map(PathBuf::from)
                .map_err(|_| "tracked path is not UTF-8".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if paths.len() > REPOSITORY_INVENTORY_ENTRY_LIMIT {
        return Err("git ls-files repository inventory exceeds its entry bound".to_owned());
    }
    let mut unique = std::collections::BTreeSet::new();
    for path in &paths {
        let text = path
            .to_str()
            .ok_or_else(|| "tracked path is not UTF-8".to_owned())?;
        normalized_relative_path(text)?;
        if !unique.insert(path.clone()) {
            return Err("git ls-files repository inventory contains a duplicate path".to_owned());
        }
    }
    paths.retain(|path| root.join(path).exists());
    let release_workflow = PathBuf::from(".github/workflows/release.yml");
    if root.join(&release_workflow).is_file() && !paths.contains(&release_workflow) {
        paths.push(release_workflow);
    }
    paths.sort();
    Ok(RepositoryInventoryReceipt {
        root: root.to_path_buf(),
        paths,
        status: result.status.code(),
        timed_out: result.timed_out,
        stdout_truncated: result.stdout_truncated,
        stderr_truncated: result.stderr_truncated,
        stdout_bytes: result.stdout_bytes,
        stderr_bytes: result.stderr_bytes,
        stdout_sha256: result.stdout_sha256,
        stderr_sha256: result.stderr_sha256,
        cleanup_id: result.cleanup_id,
        termination_forced: result.termination_forced,
        termination_reaped: result.termination_reaped,
        #[cfg(windows)]
        candidate_quiescence_complete: result.candidate_quiescence_complete,
        #[cfg(windows)]
        windows_launch_control: result.windows_launch_control,
    })
}

fn repository_inventory_evidence(result: &crate::command::CommandResult) -> JsonValue {
    let bounded = |bytes: &[u8]| {
        let rendered = String::from_utf8_lossy(bytes);
        let boundary = (0..=rendered.len().min(REPOSITORY_INVENTORY_DETAIL_LIMIT))
            .rev()
            .find(|boundary| rendered.is_char_boundary(*boundary))
            .unwrap_or_default();
        JsonValue::String(rendered[..boundary].to_owned())
    };
    let evidence = BTreeMap::from([
        ("schemaVersion".to_owned(), JsonValue::Number(2)),
        (
            "durationMillis".to_owned(),
            JsonValue::Number(u64::try_from(result.duration.as_millis()).unwrap_or(u64::MAX)),
        ),
        (
            "state".to_owned(),
            JsonValue::String(
                if result.status.success()
                    && !result.timed_out
                    && !result.stdout_truncated
                    && !result.stderr_truncated
                    && result.stderr.is_empty()
                {
                    "completed"
                } else {
                    "failed"
                }
                .to_owned(),
            ),
        ),
        (
            "statusCode".to_owned(),
            result
                .status
                .code()
                .and_then(|code| u64::try_from(code).ok())
                .map_or(JsonValue::Null, JsonValue::Number),
        ),
        ("timedOut".to_owned(), JsonValue::Bool(result.timed_out)),
        (
            "cleanupId".to_owned(),
            result.cleanup_id.map_or(JsonValue::Null, JsonValue::Number),
        ),
        (
            "terminationForced".to_owned(),
            JsonValue::Bool(result.termination_forced),
        ),
        (
            "terminationReaped".to_owned(),
            JsonValue::Bool(result.termination_reaped),
        ),
        (
            "candidateQuiescenceComplete".to_owned(),
            JsonValue::Bool(result.candidate_quiescence_complete),
        ),
        (
            "stdoutBytes".to_owned(),
            JsonValue::Number(result.stdout_bytes),
        ),
        (
            "stderrBytes".to_owned(),
            JsonValue::Number(result.stderr_bytes),
        ),
        (
            "stdoutSha256".to_owned(),
            JsonValue::String(result.stdout_sha256.hex()),
        ),
        (
            "stderrSha256".to_owned(),
            JsonValue::String(result.stderr_sha256.hex()),
        ),
        (
            "stdoutTruncated".to_owned(),
            JsonValue::Bool(result.stdout_truncated),
        ),
        (
            "stderrTruncated".to_owned(),
            JsonValue::Bool(result.stderr_truncated),
        ),
        ("stdoutDetail".to_owned(), bounded(&result.stdout)),
        ("stderrDetail".to_owned(), bounded(&result.stderr)),
    ]);
    #[cfg(windows)]
    let evidence = {
        let mut evidence = evidence;
        evidence.insert(
            "launchControl".to_owned(),
            result
                .windows_launch_control
                .as_ref()
                .map_or(JsonValue::Null, |control| {
                    JsonValue::Object(BTreeMap::from([
                        ("bytes".to_owned(), JsonValue::Number(control.bytes)),
                        (
                            "candidateQuiescenceComplete".to_owned(),
                            JsonValue::Bool(control.candidate_quiescence_complete),
                        ),
                        (
                            "currentDirectory".to_owned(),
                            JsonValue::String(control.current_directory.display().to_string()),
                        ),
                        (
                            "program".to_owned(),
                            control.program.as_ref().map_or(JsonValue::Null, |path| {
                                JsonValue::String(path.display().to_string())
                            }),
                        ),
                        (
                            "programBytes".to_owned(),
                            control
                                .program_bytes
                                .map_or(JsonValue::Null, JsonValue::Number),
                        ),
                        (
                            "programSha256".to_owned(),
                            control
                                .program_sha256
                                .map_or(JsonValue::Null, |digest| JsonValue::String(digest.hex())),
                        ),
                        (
                            "phases".to_owned(),
                            JsonValue::Array(
                                control
                                    .phases
                                    .iter()
                                    .map(|phase| JsonValue::String((*phase).to_owned()))
                                    .collect(),
                            ),
                        ),
                        (
                            "requestSha256".to_owned(),
                            JsonValue::String(control.request_sha256.hex()),
                        ),
                        (
                            "schemaVersion".to_owned(),
                            JsonValue::Number(control.schema_version),
                        ),
                        ("sha256".to_owned(), JsonValue::String(control.sha256.hex())),
                        (
                            "state".to_owned(),
                            JsonValue::String(control.state.to_owned()),
                        ),
                        (
                            "statusCode".to_owned(),
                            control
                                .status_code
                                .and_then(|code| u64::try_from(code).ok())
                                .map_or(JsonValue::Null, JsonValue::Number),
                        ),
                        ("timedOut".to_owned(), JsonValue::Bool(control.timed_out)),
                        (
                            "terminationForced".to_owned(),
                            JsonValue::Bool(control.termination_forced),
                        ),
                        (
                            "terminationReaped".to_owned(),
                            JsonValue::Bool(control.termination_reaped),
                        ),
                    ]))
                }),
        );
        evidence
    };
    JsonValue::Object(evidence)
}

fn require_repository_inventory_command(
    result: &crate::command::CommandResult,
) -> Result<(), String> {
    #[cfg(windows)]
    let control_failed = result
        .windows_launch_control
        .as_ref()
        .is_none_or(|receipt| receipt.validate().is_err() || receipt.state != "completed");
    #[cfg(not(windows))]
    let control_failed = false;
    if !result.status.success()
        || result.timed_out
        || result.stdout_truncated
        || result.stderr_truncated
        || !result.stderr.is_empty()
        || control_failed
    {
        Err(repository_inventory_failure_detail(result))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
pub(crate) fn verify_repository_inventory_target_stderr_for_integration(
    result: &crate::command::CommandResult,
) -> Result<(), String> {
    let control = result
        .windows_launch_control
        .as_ref()
        .ok_or_else(|| "Windows target-stderr launch receipt is absent".to_owned())?;
    control
        .validate()
        .map_err(|error| format!("Windows target-stderr launch receipt differs: {error}"))?;
    if control.state != "completed" || result.stderr.is_empty() {
        return Err("Windows target-stderr fixture did not reach its intended boundary".to_owned());
    }
    let failure = require_repository_inventory_command(result)
        .expect_err("target stderr must reject repository inventory");
    if !failure.contains("stderrBytes=")
        || !failure.contains("stderrSha256=")
        || !failure.contains("inventory-target-stderr")
    {
        return Err("Windows target-stderr failure evidence is incomplete".to_owned());
    }
    Ok(())
}

fn repository_inventory_failure_detail(result: &crate::command::CommandResult) -> String {
    let bounded = |bytes: &[u8]| {
        let rendered = String::from_utf8_lossy(bytes);
        let boundary = (0..=rendered.len().min(REPOSITORY_INVENTORY_DETAIL_LIMIT))
            .rev()
            .find(|boundary| rendered.is_char_boundary(*boundary))
            .unwrap_or_default();
        let mut detail = rendered[..boundary].to_owned();
        if boundary < rendered.len() {
            detail.push_str("<TRUNCATED>");
        }
        detail
    };
    #[cfg(windows)]
    let control = result.windows_launch_control.as_ref().map_or_else(
        || "unavailable".to_owned(),
        |receipt| {
            format!(
                "{}:{}:{}:{}",
                receipt.schema_version,
                receipt.state,
                receipt.request_sha256.hex(),
                receipt.sha256.hex()
            )
        },
    );
    #[cfg(not(windows))]
    let control = "not-applicable".to_owned();
    format!(
        "git ls-files failed while inventorying repository policy: status={:?}, timedOut={}, stdoutBytes={}, stderrBytes={}, stdoutSha256={}, stderrSha256={}, stdoutTruncated={}, stderrTruncated={}, launchControl={control:?}, stdout={:?}, stderr={:?}",
        result.status.code(),
        result.timed_out,
        result.stdout_bytes,
        result.stderr_bytes,
        result.stdout_sha256.hex(),
        result.stderr_sha256.hex(),
        result.stdout_truncated,
        result.stderr_truncated,
        bounded(&result.stdout),
        bounded(&result.stderr),
    )
}

fn check_tracked_file(root: &Path, relative: &Path, failures: &mut Vec<String>) {
    let path = root.join(relative);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) => {
            failures.push(format!("cannot inspect {}: {error}", relative.display()));
            return;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        failures.push(format!(
            "tracked path must be a regular file: {}",
            relative.display()
        ));
        return;
    }
    if matches!(
        relative.extension().and_then(|value| value.to_str()),
        Some("sh" | "bash")
    ) {
        failures.push(format!("shell script is forbidden: {}", relative.display()));
    }
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            failures.push(format!("cannot read {}: {error}", relative.display()));
            return;
        }
    };
    if !bytes.is_empty() && textual(relative, &bytes) && !bytes.ends_with(b"\n") {
        failures.push(format!(
            "tracked text file lacks a trailing newline: {}",
            relative.display()
        ));
    }
}

fn textual(path: &Path, bytes: &[u8]) -> bool {
    let extension = path.extension().and_then(|value| value.to_str());
    matches!(
        extension,
        Some(
            "md" | "rs"
                | "toml"
                | "yml"
                | "yaml"
                | "json"
                | "txt"
                | "hell"
                | "hs"
                | "cabal"
                | "lock"
                | "tsv"
                | "csv"
        )
    ) || std::str::from_utf8(bytes)
        .is_ok_and(|text| text.starts_with("#!") || text.lines().all(|line| !line.contains('\0')))
}

fn check_dormant_collection_activation(root: &Path, failures: &mut Vec<String>) {
    let manifest = root.join("compat/collection-activation.toml");
    let provenance = root.join("compat/collection-activation-provenance.json");
    let claims = root.join("compat/collection-activation-claims.json");
    let result = (|| {
        let manifest_bytes = fs::read(&manifest)
            .map_err(|error| format!("cannot read {}: {error}", manifest.display()))?;
        let provenance_bytes = fs::read(&provenance)
            .map_err(|error| format!("cannot read {}: {error}", provenance.display()))?;
        let claims_bytes = fs::read(&claims)
            .map_err(|error| format!("cannot read {}: {error}", claims.display()))?;
        let active = hell_testkit::verify_collection_activation_state(
            &manifest_bytes,
            &provenance_bytes,
            &claims_bytes,
        )?;
        if active {
            return Err(
                "collection activation is active but its retired authority implementation is unavailable"
                    .to_owned(),
            );
        }
        Ok(())
    })();
    if let Err(error) = result {
        failures.push(error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dormant_activation_is_bound_and_fail_closed() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut failures = Vec::new();
        check_dormant_collection_activation(&root, &mut failures);
        assert!(failures.is_empty(), "{failures:?}");
    }

    #[test]
    fn shell_extensions_and_missing_newline_are_rejected() {
        assert!(matches!(
            Path::new("tool.sh").extension().and_then(|v| v.to_str()),
            Some("sh")
        ));
        assert!(textual(Path::new("source.rs"), b"fn main() {}"));
    }
}
