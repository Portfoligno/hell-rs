use std::ffi::OsString;
use std::path::PathBuf;

use hell_memcordon::{AcquisitionReceiptV1, ProviderLifecycleReceiptV1, ProviderLifecycleState};

mod acquire;
mod canary;
mod collector;
mod execute;
mod finalize;
mod prerequisite;
mod provider;
mod task;

pub use collector::ExecutionCollector;
pub use execute::compose_authority_result;
pub use finalize::validate_execution_group_binding;
pub(crate) use finalize::{verify_archived_finalized_evidence, verify_finalized_evidence};

pub(crate) fn find_component_for_integration(
    root: &std::path::Path,
    name: &str,
) -> Result<PathBuf, String> {
    provider::find_component(root, name)
}

pub(crate) fn finalize_platform_report_for_integration(
    output: &std::path::Path,
    finalization: &hell_memcordon::FinalizationReceiptV1,
    finalization_bytes: &[u8],
    inventory_bytes: &[u8],
) -> Result<(), String> {
    finalize::finalize_platform_report(output, finalization, finalization_bytes, inventory_bytes)
}

pub(crate) struct QualifiedPolicy {
    pub(crate) evidence_root: PathBuf,
    pub(crate) runtime: PathBuf,
    pub(crate) report_directory: PathBuf,
    pub(crate) mechanism: String,
}

struct Options {
    action: Action,
    task: PathBuf,
    operation: String,
    candidate_commit: Option<String>,
    workflow_commit: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Acquire,
    Prepare,
    Canary,
    Execute,
    Cleanup,
    Finalize,
}

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments.first().and_then(|value| value.to_str()) == Some("memcordon")
}

pub(crate) fn run(arguments: &[OsString]) -> Result<String, String> {
    let options = parse(arguments)?;
    let task = task::Task::load(&options.task, &options.operation)?;
    match options.action {
        Action::Acquire => acquire::run(&task),
        Action::Prepare => provider::prepare(&task),
        Action::Canary => canary::run(&task),
        Action::Execute => execute::run(&task),
        Action::Cleanup => provider::cleanup(&task),
        Action::Finalize => finalize::run(
            &task,
            options.candidate_commit.as_deref(),
            options.workflow_commit.as_deref(),
        ),
    }
}

pub(crate) fn fuzz_archive_member_policy(bytes: &[u8]) -> Result<(), String> {
    acquire::fuzz_archive_member_policy(bytes)
}

pub(crate) fn qualified_policy(
    task_path: &std::path::Path,
    operation: &str,
) -> Result<QualifiedPolicy, String> {
    let task = task::Task::load(task_path, operation)?;
    let acquisition_bytes = std::fs::read(task.output.join("acquisition.json"))
        .map_err(|error| format!("cannot read MemCordon acquisition receipt: {error}"))?;
    let acquisition: AcquisitionReceiptV1 = serde_json::from_slice(&acquisition_bytes)
        .map_err(|error| format!("invalid MemCordon acquisition receipt: {error}"))?;
    let provider_bytes = std::fs::read(task.output.join("provider-lease.json"))
        .map_err(|error| format!("cannot read MemCordon provider lease: {error}"))?;
    let provider: ProviderLifecycleReceiptV1 = serde_json::from_slice(&provider_bytes)
        .map_err(|error| format!("invalid MemCordon provider lease: {error}"))?;
    if provider.state != ProviderLifecycleState::Qualified
        || provider.lease_owner != "job"
        || provider.admission_closed
        || provider.active_operations != 0
        || provider.runtime_lock_digest != acquisition.runtime_lock_digest
    {
        return Err("MemCordon provider is not qualified for sealed admission".to_owned());
    }
    let runtime = provider::find_component(&task.runtime_root, provider::cli_name())?;
    let runtime = std::fs::canonicalize(&runtime)
        .map_err(|error| format!("cannot canonicalize qualified MemCordon CLI: {error}"))?;
    let runtime_sha256 = hell_testkit::sha256_file(&runtime)
        .map_err(|error| format!("cannot hash qualified MemCordon CLI: {error}"))?
        .hex();
    if !acquisition.components.iter().any(|component| {
        std::path::Path::new(&component.path)
            .file_name()
            .is_some_and(|name| {
                if cfg!(windows) {
                    name.to_str()
                        .is_some_and(|name| name.eq_ignore_ascii_case(provider::cli_name()))
                } else {
                    name == provider::cli_name()
                }
            })
            && component.sha256 == runtime_sha256
    }) {
        return Err("qualified MemCordon CLI differs from acquisition evidence".to_owned());
    }
    Ok(QualifiedPolicy {
        evidence_root: prerequisite::validate(&task, &acquisition, &provider)?,
        runtime,
        report_directory: std::fs::canonicalize(task.output.join("raw"))
            .map_err(|error| format!("cannot canonicalize MemCordon report directory: {error}"))?,
        mechanism: acquisition.mechanism,
    })
}

fn parse(arguments: &[OsString]) -> Result<Options, String> {
    if arguments.len() != 6 && arguments.len() != 10 {
        return Err(
            "memcordon requires ACTION --task PATH --operation OPERATION and finalize may additionally bind both commits"
                .to_owned(),
        );
    }
    let action = match arguments.get(1).and_then(|value| value.to_str()) {
        Some("acquire") => Action::Acquire,
        Some("prepare") => Action::Prepare,
        Some("canary") => Action::Canary,
        Some("execute") => Action::Execute,
        Some("cleanup") => Action::Cleanup,
        Some("finalize") => Action::Finalize,
        _ => return Err("unknown MemCordon action".to_owned()),
    };
    let mut task = None;
    let mut operation = None;
    let mut candidate_commit = None;
    let mut workflow_commit = None;
    for pair in arguments[2..].chunks_exact(2) {
        let flag = pair[0]
            .to_str()
            .ok_or_else(|| "MemCordon option name must be UTF-8".to_owned())?;
        match flag {
            "--task" if task.is_none() => task = Some(PathBuf::from(&pair[1])),
            "--operation" if operation.is_none() => {
                operation = Some(
                    pair[1]
                        .to_str()
                        .ok_or_else(|| "MemCordon operation must be UTF-8".to_owned())?
                        .to_owned(),
                );
            }
            "--candidate-commit" if candidate_commit.is_none() => {
                candidate_commit = Some(parse_commit(&pair[1], flag)?);
            }
            "--workflow-commit" if workflow_commit.is_none() => {
                workflow_commit = Some(parse_commit(&pair[1], flag)?);
            }
            "--task" | "--operation" | "--candidate-commit" | "--workflow-commit" => {
                return Err(format!(
                    "MemCordon option {flag} was provided more than once"
                ));
            }
            _ => return Err(format!("unknown MemCordon option {flag}")),
        }
    }
    if action != Action::Finalize && (candidate_commit.is_some() || workflow_commit.is_some()) {
        return Err("commit bindings are accepted only by MemCordon finalize".to_owned());
    }
    if candidate_commit.is_some() != workflow_commit.is_some() {
        return Err("MemCordon finalization requires both commit bindings".to_owned());
    }
    Ok(Options {
        action,
        task: task.ok_or_else(|| "--task is required".to_owned())?,
        operation: operation.ok_or_else(|| "--operation is required".to_owned())?,
        candidate_commit,
        workflow_commit,
    })
}

fn parse_commit(value: &std::ffi::OsStr, flag: &str) -> Result<String, String> {
    let value = value
        .to_str()
        .ok_or_else(|| format!("{flag} must be UTF-8"))?;
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{flag} must be one lowercase 40-hex commit"));
    }
    Ok(value.to_owned())
}
