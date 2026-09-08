#[cfg(any(target_os = "linux", windows))]
use std::fs;
#[cfg(any(target_os = "linux", windows))]
use std::path::Path;
#[cfg(any(target_os = "linux", windows))]
use std::time::{Duration, Instant};

#[cfg(any(target_os = "linux", windows))]
use hell_memcordon::{
    CandidateBoundaryPolicy, OperationLedgerEntryV1, SealedTerminal,
    WindowsCandidateIdentityReceiptV1,
};

#[cfg(any(target_os = "linux", windows))]
use crate::command::NativeProcessSpec;
#[cfg(any(target_os = "linux", windows))]
use crate::json::parse_json;
#[cfg(any(target_os = "linux", windows))]
use crate::release::manifest::{write_atomic, write_json};

#[cfg(any(target_os = "linux", windows))]
use super::provider::create_evidence_directories;
use super::task::Task;

#[cfg(any(target_os = "linux", windows))]
const CLEANUP_RESERVE: Duration = Duration::from_secs(20);
#[cfg(any(target_os = "linux", windows))]
const COMPLETION_RESERVE: Duration = Duration::from_secs(30);
#[cfg(any(target_os = "linux", windows))]
const AUTHORITY_CLEANUP_RESERVE: Duration = Duration::from_mins(30);

pub(super) fn run(task: &Task) -> Result<String, String> {
    #[cfg(windows)]
    return run_windows(task);
    #[cfg(target_os = "linux")]
    return run_linux(task);
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = task;
        Err("MemCordon execution is supported only on Linux and Windows".to_owned())
    }
}

#[cfg(target_os = "linux")]
fn run_linux(task: &Task) -> Result<String, String> {
    create_evidence_directories(&task.output)?;
    let qualified = super::qualified_policy(&task.policy_path, &task.operation)?;
    let repository = fs::canonicalize(".")
        .map_err(|error| format!("cannot canonicalize operation directory: {error}"))?;
    let work_root = repository.join("target").join(format!(
        "memcordon-work-{}-{}",
        std::process::id(),
        task.operation
    ));
    fs::create_dir(&work_root)
        .map_err(|error| format!("cannot reserve Linux operation work root: {error}"))?;
    let budget = operation_budget(&task.operation)?;
    let started = Instant::now();
    let execution_deadline = started
        .checked_add(budget)
        .ok_or_else(|| "MemCordon operation deadline overflowed".to_owned())?;
    let completion_deadline = execution_deadline
        .checked_add(COMPLETION_RESERVE)
        .ok_or_else(|| "MemCordon completion deadline overflowed".to_owned())?;
    let authority_cleanup_deadline = completion_deadline
        .checked_add(AUTHORITY_CLEANUP_RESERVE)
        .ok_or_else(|| "Linux authority cleanup deadline overflowed".to_owned())?;
    let mut authority = crate::release::platform::LinuxMemcordonLaunchAuthority::acquire_until(
        &repository,
        &work_root,
        &task.operation,
        execution_deadline,
        authority_cleanup_deadline,
    )?;
    let executable = authority.executable().to_path_buf();
    let candidate_repository = authority.repository_root().to_path_buf();
    let candidate_work_root = authority.work_root().to_path_buf();
    let primary = (|| {
        authority.preflight_until(execution_deadline, &task.output)?;
        let mut command = NativeProcessSpec::new(executable)
            .argument("__memcordon-operation-child")
            .argument(&task.operation)
            .argument(&candidate_repository)
            .argument(authority.work_root())
            .current_directory(&candidate_repository)
            .construct()?;
        authority.attach_memcordon(
            hell_testkit::BoundProgramInvocation::new(qualified.runtime.clone(), qualified.runtime)
                .map_err(|error| format!("cannot bind qualified MemCordon CLI: {error}"))?,
            qualified.report_directory,
            qualified.mechanism,
            hell_memcordon::SealedAdmission::new(1),
            CLEANUP_RESERVE,
        )?;
        let bound = authority.configure_command(&mut command)?;
        let output = hell_testkit::run_memcordon_candidate_command_with_deadlines(
            &mut command,
            &[],
            execution_deadline,
            completion_deadline,
            &bound,
            authority.launch_policy()?,
            None,
        )
        .map_err(|error| format!("MemCordon operation execution failed: {error}"))?;
        crate::operation_evidence::retain(
            &task.output.join("streams").join(&task.operation),
            &output,
        )?;
        persist_operation(task, &output, CandidateBoundaryPolicy::SealedLinux, None)?;
        if !output.status.success() || output.timed_out {
            return Err(crate::operation_evidence::failure(&task.operation, &output));
        }
        Ok(format!(
            "executed {} as one authenticated MemCordon root",
            task.operation
        ))
    })();
    let retention = authority
        .retain_work_root_until(authority_cleanup_deadline, &task.output)
        .and_then(|()| {
            if primary.is_err() && task.operation == "fuzz" {
                crate::operation_evidence::retain_blocked_fuzz_report(
                    &candidate_work_root,
                    &task.output,
                )?;
            }
            retain_candidate_outputs(&task.operation, &candidate_work_root, &repository)
        });
    let authority_cleanup = authority.close_until(authority_cleanup_deadline, &task.output);
    let work_root_cleanup = fs::remove_dir_all(&work_root)
        .map_err(|error| format!("cannot remove retained Linux work root: {error}"));
    let cleanup = match (authority_cleanup, work_root_cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(authority), Ok(())) => Err(authority),
        (Ok(()), Err(work_root)) => Err(work_root),
        (Err(authority), Err(work_root)) => Err(format!(
            "{authority}; additionally, retained work-root cleanup failed: {work_root}"
        )),
    };
    compose_authority_result("Linux", primary, retention, cleanup)
}

#[cfg(windows)]
fn run_windows(task: &Task) -> Result<String, String> {
    create_evidence_directories(&task.output)?;
    let qualified = super::qualified_policy(&task.policy_path, &task.operation)?;
    let executable = fs::canonicalize(
        std::env::current_exe().map_err(|error| format!("cannot locate hell-ci: {error}"))?,
    )
    .map_err(|error| format!("cannot canonicalize hell-ci: {error}"))?;
    let bound = hell_testkit::BoundProgramInvocation::new(executable.clone(), executable.clone())
        .map_err(|error| format!("cannot bind MemCordon operation driver: {error}"))?;
    let repository = fs::canonicalize(".")
        .map_err(|error| format!("cannot canonicalize operation directory: {error}"))?;
    let target = fs::canonicalize(repository.join("target"))
        .map_err(|error| format!("cannot canonicalize operation target: {error}"))?;
    let output_root = repository.join("ci-out");
    fs::create_dir_all(&output_root)
        .map_err(|error| format!("cannot create candidate output root: {error}"))?;
    let output_root = fs::canonicalize(&output_root)
        .map_err(|error| format!("cannot canonicalize candidate output root: {error}"))?;
    let budget = operation_budget(&task.operation)?;
    let started = Instant::now();
    let execution_deadline = started
        .checked_add(budget)
        .ok_or_else(|| "MemCordon operation deadline overflowed".to_owned())?;
    let completion_deadline = execution_deadline
        .checked_add(COMPLETION_RESERVE)
        .ok_or_else(|| "MemCordon completion deadline overflowed".to_owned())?;
    let authority_cleanup_deadline = completion_deadline
        .checked_add(AUTHORITY_CLEANUP_RESERVE)
        .ok_or_else(|| "Windows authority cleanup deadline overflowed".to_owned())?;
    let mut authority =
        crate::release::platform::NightlyWindowsLaunchAuthority::acquire_until_with_writable_roots(
            &repository,
            &target,
            std::slice::from_ref(&output_root),
            execution_deadline,
            authority_cleanup_deadline,
        )?;
    let primary = (|| {
        authority.attach_memcordon(
            hell_testkit::BoundProgramInvocation::new(qualified.runtime.clone(), qualified.runtime)
                .map_err(|error| format!("cannot bind qualified MemCordon CLI: {error}"))?,
            qualified.report_directory,
            qualified.mechanism,
            hell_memcordon::SealedAdmission::windows_default(),
            CLEANUP_RESERVE,
        )?;
        let policy = authority.launch_policy()?;
        let mut command = NativeProcessSpec::new(executable)
            .argument("__memcordon-operation-child")
            .argument(&task.operation)
            .current_directory(&repository)
            .construct()?;
        let output = hell_testkit::run_memcordon_candidate_command_with_deadlines(
            &mut command,
            &[],
            execution_deadline,
            completion_deadline,
            &bound,
            policy,
            None,
        )
        .map_err(|error| format!("MemCordon operation execution failed: {error}"))?;
        crate::operation_evidence::retain(
            &task.output.join("streams").join(&task.operation),
            &output,
        )?;
        let identity = policy
            .windows_memcordon_identity_receipt(&task.operation, &output)
            .map_err(|error| format!("cannot retain Windows identity receipt: {error}"))?;
        persist_operation(
            task,
            &output,
            CandidateBoundaryPolicy::SealedWindows,
            Some(&identity),
        )?;
        if !output.status.success() || output.timed_out {
            return Err(crate::operation_evidence::failure(&task.operation, &output));
        }
        Ok(format!(
            "executed {} as one authenticated MemCordon root",
            task.operation
        ))
    })();
    let cleanup = authority.close_until(authority_cleanup_deadline);
    compose_authority_result("Windows", primary, Ok(()), cleanup)
}

pub fn compose_authority_result(
    platform: &str,
    primary: Result<String, String>,
    retention: Result<(), String>,
    cleanup: Result<(), String>,
) -> Result<String, String> {
    let mut failures = Vec::new();
    let message = match primary {
        Ok(message) => Some(message),
        Err(error) => {
            failures.push(error);
            None
        }
    };
    if let Err(error) = retention {
        failures.push(format!(
            "{platform} candidate output retention failed: {error}"
        ));
    }
    if let Err(error) = cleanup {
        failures.push(format!(
            "{platform} launch authority cleanup failed: {error}"
        ));
    }
    if failures.is_empty() {
        Ok(message.expect("successful authority execution has a message"))
    } else {
        Err(failures.join("; additionally, "))
    }
}

#[cfg(target_os = "linux")]
fn retain_candidate_outputs(
    operation: &str,
    work_root: &Path,
    repository: &Path,
) -> Result<(), String> {
    let source_root = work_root.join("ci-out");
    let source_metadata = match fs::symlink_metadata(&source_root) {
        Ok(metadata) => metadata,
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && matches!(operation, "regression-corpus" | "regression-subject") =>
        {
            return Ok(());
        }
        Err(error) => return Err(format!("cannot inspect candidate output root: {error}")),
    };
    if !source_metadata.is_dir() || source_metadata.file_type().is_symlink() {
        return Err("candidate output root is not one direct directory".to_owned());
    }
    let (required, allowed): (&[&str], &[&str]) = match operation {
        "nightly" => (&["nightly-linux.json"], &["nightly-linux.json", "failures"]),
        "mutation" => (&["mutation"], &["mutation"]),
        "fuzz" => (
            &["fuzz-smoke.json", "fuzz-corpora", "fuzz-artifacts"],
            &["fuzz-smoke.json", "fuzz-corpora", "fuzz-artifacts"],
        ),
        "regression-corpus" | "regression-subject" => (&[], &[]),
        _ => return Err(format!("unsupported retained operation {operation}")),
    };
    let observed = fs::read_dir(&source_root)
        .map_err(|error| format!("cannot enumerate candidate output root: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("cannot inspect candidate output root: {error}"))?
                .file_name()
                .into_string()
                .map_err(|_| "candidate output name is not UTF-8".to_owned())
        })
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    if required.iter().any(|name| !observed.contains(*name))
        || observed
            .iter()
            .any(|name| !allowed.contains(&name.as_str()))
    {
        return Err(format!(
            "candidate output inventory differs for {operation}: {}",
            observed.into_iter().collect::<Vec<_>>().join(",")
        ));
    }
    validate_candidate_output_shape(operation, &source_root, repository)?;
    let destination_root = repository.join("ci-out");
    fs::create_dir_all(&destination_root)
        .map_err(|error| format!("cannot create trusted output root: {error}"))?;
    for name in allowed {
        if source_root.join(name).exists() && destination_root.join(name).exists() {
            return Err(format!(
                "trusted candidate output already exists: {}",
                destination_root.join(name).display()
            ));
        }
    }
    let mut directories = Vec::new();
    let mut files = Vec::new();
    let mut pending = vec![source_root.clone()];
    while let Some(directory) = pending.pop() {
        let mut entries = fs::read_dir(&directory)
            .map_err(|error| format!("cannot enumerate candidate outputs: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot inspect candidate output: {error}"))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let source = entry.path();
            let relative = source
                .strip_prefix(&source_root)
                .map_err(|_| "candidate output escaped its retained root".to_owned())?;
            if relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
            {
                return Err("candidate output path is not normalized".to_owned());
            }
            let destination = destination_root.join(relative);
            let kind = entry
                .file_type()
                .map_err(|error| format!("cannot classify candidate output: {error}"))?;
            if kind.is_symlink() {
                return Err("candidate output contains a symbolic link".to_owned());
            }
            if kind.is_dir() {
                directories.push(destination);
                pending.push(source);
            } else if kind.is_file() {
                if destination.exists() {
                    return Err(format!(
                        "trusted candidate output already exists: {}",
                        destination.display()
                    ));
                }
                files.push((source, destination));
            } else {
                return Err("candidate output contains a special file".to_owned());
            }
        }
    }
    directories.sort_by_key(|path| path.components().count());
    for directory in directories {
        fs::create_dir(&directory)
            .map_err(|error| format!("cannot create trusted output directory: {error}"))?;
    }
    files.sort_by(|left, right| left.1.cmp(&right.1));
    for (source, destination) in files {
        fs::copy(&source, &destination)
            .map_err(|error| format!("cannot retain candidate output: {error}"))?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_candidate_output_shape(
    operation: &str,
    source_root: &Path,
    repository: &Path,
) -> Result<(), String> {
    match operation {
        "nightly" => {
            require_output_kind(&source_root.join("nightly-linux.json"), false)?;
            let failures = source_root.join("failures");
            if failures.exists() {
                require_output_kind(&failures, true)?;
                require_flat_regular_files(&failures)?;
            }
        }
        "mutation" => {
            let mutation = source_root.join("mutation");
            require_output_kind(&mutation, true)?;
            require_exact_directory_entries(&mutation, &["assurance.json"], false)?;
        }
        "fuzz" => {
            require_output_kind(&source_root.join("fuzz-smoke.json"), false)?;
            let expected = crate::fuzz::checked_target_ids(
                &repository.join("ci/fuzz-targets.toml"),
                repository,
            )?;
            for name in ["fuzz-corpora", "fuzz-artifacts"] {
                let root = source_root.join(name);
                require_output_kind(&root, true)?;
                let observed = direct_directory_names(&root)?;
                if observed != expected {
                    return Err(format!("candidate {name} target inventory differs"));
                }
                for target in &expected {
                    require_flat_regular_files(&root.join(target))?;
                }
            }
        }
        "regression-corpus" | "regression-subject" => {}
        _ => return Err(format!("unsupported retained operation {operation}")),
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_output_kind(path: &Path, directory: bool) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "cannot inspect candidate output {}: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink()
        || metadata.is_dir() != directory
        || metadata.is_file() == directory
    {
        return Err(format!(
            "candidate output has the wrong type: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_exact_directory_entries(
    path: &Path,
    expected: &[&str],
    directories: bool,
) -> Result<(), String> {
    let observed = fs::read_dir(path)
        .map_err(|error| {
            format!(
                "cannot enumerate candidate output {}: {error}",
                path.display()
            )
        })?
        .map(|entry| {
            let entry =
                entry.map_err(|error| format!("cannot inspect candidate output: {error}"))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "candidate output name is not UTF-8".to_owned())?;
            require_output_kind(&entry.path(), directories)?;
            Ok(name)
        })
        .collect::<Result<std::collections::BTreeSet<_>, String>>()?;
    let expected = expected.iter().map(|name| (*name).to_owned()).collect();
    if observed != expected {
        return Err(format!(
            "candidate output inventory differs under {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn direct_directory_names(path: &Path) -> Result<std::collections::BTreeSet<String>, String> {
    fs::read_dir(path)
        .map_err(|error| {
            format!(
                "cannot enumerate candidate output {}: {error}",
                path.display()
            )
        })?
        .map(|entry| {
            let entry =
                entry.map_err(|error| format!("cannot inspect candidate output: {error}"))?;
            require_output_kind(&entry.path(), true)?;
            entry
                .file_name()
                .into_string()
                .map_err(|_| "candidate output name is not UTF-8".to_owned())
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn require_flat_regular_files(path: &Path) -> Result<(), String> {
    fs::read_dir(path)
        .map_err(|error| {
            format!(
                "cannot enumerate candidate output {}: {error}",
                path.display()
            )
        })?
        .try_for_each(|entry| {
            let entry =
                entry.map_err(|error| format!("cannot inspect candidate output: {error}"))?;
            require_output_kind(&entry.path(), false)
        })
}

#[cfg(any(target_os = "linux", windows))]
fn persist_operation(
    task: &Task,
    output: &hell_testkit::SupervisedOutput,
    boundary: CandidateBoundaryPolicy,
    identity: Option<&WindowsCandidateIdentityReceiptV1>,
) -> Result<(), String> {
    let reserved_raw = output
        .memcordon_report_path
        .as_deref()
        .ok_or_else(|| "MemCordon operation lacks a raw report path".to_owned())?;
    let raw_digest = output
        .memcordon_report_sha256
        .ok_or_else(|| "MemCordon operation lacks a raw report digest".to_owned())?
        .hex();
    let projection = output
        .memcordon_projection
        .as_ref()
        .ok_or_else(|| "MemCordon operation lacks a normalized projection".to_owned())?;
    let raw_relative = format!("raw/{}.json", task.operation);
    let raw_path = task.output.join(&raw_relative);
    if raw_path.exists() || task.output.join("operations.json").exists() {
        return Err("MemCordon operation evidence reservation is not fresh".to_owned());
    }
    fs::rename(reserved_raw, &raw_path)
        .map_err(|error| format!("cannot retain MemCordon raw report: {error}"))?;
    let normalized_relative = format!("normalized/{}.json", task.operation);
    let normalized_path = task.output.join(&normalized_relative);
    write_serde(&normalized_path, projection)?;
    let normalized = fs::read(&normalized_path)
        .map_err(|error| format!("cannot read MemCordon projection: {error}"))?;
    let (identity_adapter_path, identity_adapter_digest) = if let Some(identity) = identity {
        identity.validate().map_err(|error| error.to_string())?;
        let relative = format!("adapters/{}.json", task.operation);
        let path = task.output.join(&relative);
        write_serde(&path, identity)?;
        let bytes = fs::read(&path)
            .map_err(|error| format!("cannot read Windows identity receipt: {error}"))?;
        (
            Some(relative),
            Some(hell_testkit::sha256_bytes(&bytes).hex()),
        )
    } else {
        (None, None)
    };
    let request = serde_json::to_vec(&projection.target_argv)
        .map_err(|error| format!("cannot encode MemCordon request binding: {error}"))?;
    let terminal = match &projection.terminal {
        hell_memcordon::Schema8TerminalV1::InnerDeadline => SealedTerminal::InnerDeadline,
        hell_memcordon::Schema8TerminalV1::CandidateExit { .. }
        | hell_memcordon::Schema8TerminalV1::CandidateSignal { .. } => {
            SealedTerminal::OrdinaryResult
        }
    };
    let entry = OperationLedgerEntryV1 {
        operation_id: task.operation.clone(),
        boundary,
        request_digest: hell_testkit::sha256_bytes(&request).hex(),
        raw_report_path: Some(raw_relative),
        raw_report_digest: Some(raw_digest),
        normalized_report_path: Some(normalized_relative),
        normalized_report_digest: Some(hell_testkit::sha256_bytes(&normalized).hex()),
        identity_adapter_path,
        identity_adapter_digest,
        terminal,
    };
    let ledger =
        hell_memcordon::operation_ledger_json(&[entry]).map_err(|error| error.to_string())?;
    write_atomic(&task.output.join("operations.json"), &ledger)
}

#[cfg(any(target_os = "linux", windows))]
fn operation_budget(operation: &str) -> Result<Duration, String> {
    match operation {
        "nightly" => Ok(Duration::from_mins(110)),
        "mutation" | "fuzz" => Ok(Duration::from_mins(80)),
        "regression-corpus" | "regression-subject" => Ok(Duration::from_mins(25)),
        _ => Err(format!(
            "MemCordon standalone execution does not support {operation}"
        )),
    }
}

#[cfg(any(target_os = "linux", windows))]
fn write_serde(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("cannot serialize MemCordon projection: {error}"))?;
    let text = std::str::from_utf8(&bytes).expect("JSON serializer emits UTF-8");
    write_json(path, &parse_json(text)?).map(|_| ())
}
