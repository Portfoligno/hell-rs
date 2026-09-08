use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hell_memcordon::{
    AcquisitionReceiptV1, PROVIDER_CLEANUP_RECEIPT_SCHEMA_V1, PROVIDER_RECEIPT_SCHEMA_V1,
    ProviderCleanupReceiptV1, ProviderLeaseStateMachine, ProviderLifecycleReceiptV1,
    ProviderLifecycleState,
};

use crate::command::CommandSpec;
use crate::json::{JsonValue, parse_json};
use crate::provider_evidence::{
    Captured, require_json_success, require_success, retain_command, retain_json_command,
};
use crate::release::manifest::{write_atomic, write_json};

use super::task::Task;

const ADMIN_OUTPUT_LIMIT: usize = 2 * 1024 * 1024;
const ADMIN_TIMEOUT: Duration = Duration::from_mins(3);

struct ProviderPreparation {
    acquisition: AcquisitionReceiptV1,
    agent_sha256: String,
    package_inspection_digest: String,
    provider_lease_id: String,
    lifecycle: ProviderLeaseStateMachine,
}

pub(super) fn prepare(task: &Task) -> Result<String, String> {
    create_evidence_directories(&task.output)?;
    let agent = find_component(&task.runtime_root, agent_name())?;
    let cli = find_component(&task.runtime_root, cli_name())?;
    let mut preparation = prepare_installation(task, &agent)?;
    let (package_verification_digest, qualification_digest) =
        install_and_qualify(task, &agent, &cli)?;
    preparation
        .lifecycle
        .transition(ProviderLifecycleState::Qualified)
        .map_err(|error| error.to_string())?;
    if !preparation.lifecycle.admits_sealed_roots() {
        return Err("qualified provider lifecycle did not open sealed admission".to_owned());
    }

    let qualified = ProviderLifecycleReceiptV1 {
        schema_version: PROVIDER_RECEIPT_SCHEMA_V1,
        provider_lease_id: preparation.provider_lease_id,
        lease_owner: "job".to_owned(),
        runtime_lock_digest: preparation.acquisition.runtime_lock_digest,
        agent_sha256: preparation.agent_sha256,
        package_inspection_digest: Some(preparation.package_inspection_digest),
        package_verification_digest: Some(package_verification_digest),
        qualification_digest: Some(qualification_digest),
        state: preparation.lifecycle.state(),
        admission_closed: false,
        active_operations: 0,
        cleanup_succeeded: false,
        failure: None,
    };
    write_serde(&task.output.join("provider-lease.json"), &qualified)?;
    Ok(format!(
        "installed and qualified MemCordon for {}",
        Task::platform_id()?
    ))
}

fn prepare_installation(task: &Task, agent: &Path) -> Result<ProviderPreparation, String> {
    let mut lifecycle = ProviderLeaseStateMachine::default();
    lifecycle
        .transition(ProviderLifecycleState::Acquired)
        .map_err(|error| error.to_string())?;

    let inspect = run_bounded(
        agent,
        [
            OsStr::new("package"),
            OsStr::new("inspect"),
            OsStr::new("--json"),
        ],
        ADMIN_TIMEOUT,
        ADMIN_OUTPUT_LIMIT,
    )?;
    require_json_success(&inspect, "package inspect")?;
    write_atomic(&task.output.join("package-inspect.json"), &inspect.stdout)?;
    lifecycle
        .transition(ProviderLifecycleState::PackageInspected)
        .map_err(|error| error.to_string())?;

    let preexisting = run_bounded(
        agent,
        [
            OsStr::new("package"),
            OsStr::new("verify"),
            OsStr::new("--json"),
        ],
        Duration::from_secs(45),
        ADMIN_OUTPUT_LIMIT,
    )?;
    retain_command(
        &task
            .output
            .join("qualification-artifacts/pre-install-package-verify"),
        &preexisting,
    )?;
    if preexisting.status.success() {
        return Err(
            "an existing MemCordon installation is present; refusing to replace it".to_owned(),
        );
    }
    require_expected_verification_failure(&preexisting, "pre-install package verification")?;
    prove_native_absence(task, "pre-install-footprint")?;
    lifecycle
        .transition(ProviderLifecycleState::Installing)
        .map_err(|error| error.to_string())?;

    let acquisition = read_acquisition(task)?;
    let package_inspection_digest = hell_testkit::sha256_bytes(&inspect.stdout).hex();
    let agent_sha256 = hell_testkit::sha256_file(agent)
        .map_err(|error| format!("cannot hash MemCordon agent: {error}"))?
        .hex();
    let provider_lease_id = lease_id(task, &acquisition);
    let lease = ProviderLifecycleReceiptV1 {
        schema_version: PROVIDER_RECEIPT_SCHEMA_V1,
        provider_lease_id: provider_lease_id.clone(),
        lease_owner: "job".to_owned(),
        runtime_lock_digest: acquisition.runtime_lock_digest.clone(),
        agent_sha256: agent_sha256.clone(),
        package_inspection_digest: Some(package_inspection_digest.clone()),
        package_verification_digest: None,
        qualification_digest: None,
        state: lifecycle.state(),
        admission_closed: true,
        active_operations: 0,
        cleanup_succeeded: false,
        failure: None,
    };
    write_serde(&task.output.join("provider-lease.json"), &lease)?;

    Ok(ProviderPreparation {
        acquisition,
        agent_sha256,
        package_inspection_digest,
        provider_lease_id,
        lifecycle,
    })
}

fn install_and_qualify(task: &Task, agent: &Path, cli: &Path) -> Result<(String, String), String> {
    let mut install_arguments = vec![
        OsString::from("package"),
        OsString::from("install"),
        OsString::from("--ephemeral-ci"),
    ];
    if cfg!(windows) {
        install_arguments.push(OsString::from("--qualification-artifact-directory"));
        install_arguments.push(task.output.join("qualification-artifacts").into_os_string());
    }
    let install = run_elevated_agent(agent, &install_arguments, ADMIN_TIMEOUT)?;
    retain_command(
        &task.output.join("qualification-artifacts/package-install"),
        &install,
    )?;
    require_success(&install, "package install")?;

    let verify = run_provider_frontend(
        agent,
        [
            OsStr::new("package"),
            OsStr::new("verify"),
            OsStr::new("--json"),
        ],
        ADMIN_TIMEOUT,
        ADMIN_OUTPUT_LIMIT,
    )?;
    retain_json_command(
        &task.output.join("qualification-artifacts/package-verify"),
        &verify,
        "package verify",
    )?;
    write_atomic(&task.output.join("package-verify.json"), &verify.stdout)?;

    let doctor = run_provider_frontend(
        cli,
        [
            OsStr::new("doctor"),
            OsStr::new("--require"),
            OsStr::new("sealed"),
            OsStr::new("--json"),
        ],
        ADMIN_TIMEOUT,
        ADMIN_OUTPUT_LIMIT,
    )?;
    retain_json_command(
        &task.output.join("qualification-artifacts/doctor"),
        &doctor,
        "doctor --require sealed",
    )?;
    write_atomic(&task.output.join("doctor.json"), &doctor.stdout)?;
    Ok((
        hell_testkit::sha256_bytes(&verify.stdout).hex(),
        hell_testkit::sha256_bytes(&doctor.stdout).hex(),
    ))
}

pub(super) fn cleanup(task: &Task) -> Result<String, String> {
    create_evidence_directories(&task.output)?;
    let lease_path = task.output.join("provider-lease.json");
    if !lease_path.exists() {
        let acquisition = read_acquisition(task)?;
        let receipt = crate::provider_presence::unowned_cleanup_receipt(
            lease_id(task, &acquisition),
            task.operation.clone(),
            acquisition.platform,
            prove_native_absence(task, "unowned-cleanup-footprint"),
        );
        receipt.validate().map_err(|error| error.to_string())?;
        write_serde(&task.output.join("provider-cleanup.json"), &receipt)?;
        return receipt.failure.map_or_else(
            || {
                Ok(
                    "MemCordon provider was not installed by this task; native footprint is absent"
                        .to_owned(),
                )
            },
            Err,
        );
    }
    let lease_bytes =
        fs::read(&lease_path).map_err(|error| format!("cannot read provider lease: {error}"))?;
    let lease: ProviderLifecycleReceiptV1 = serde_json::from_slice(&lease_bytes)
        .map_err(|error| format!("provider lease is invalid: {error}"))?;
    let acquisition = read_acquisition(task)?;
    if lease.lease_owner != "job"
        || lease.provider_lease_id != lease_id(task, &acquisition)
        || !matches!(
            lease.state,
            ProviderLifecycleState::Installing
                | ProviderLifecycleState::Qualified
                | ProviderLifecycleState::Running
                | ProviderLifecycleState::Draining
        )
    {
        return Err("provider lease is not owned by this exact task".to_owned());
    }
    let agent = find_component(&task.runtime_root, agent_name())?;
    #[cfg(windows)]
    if let Err(error) = write_serde(
        &task
            .output
            .join("qualification-artifacts/windows-attempt-diagnostics.json"),
        &crate::windows_provider_diagnostics::collect(),
    ) {
        // Diagnostic collection is separate from provider retirement authority.
        // Never leave the installed provider behind because evidence could not be written.
        eprintln!("cannot retain Windows provider diagnostics before cleanup: {error}");
    }
    let uninstall = run_elevated_agent(
        &agent,
        &[
            OsString::from("package"),
            OsString::from("uninstall"),
            OsString::from("--ephemeral-ci"),
        ],
        ADMIN_TIMEOUT,
    )?;
    retain_command(
        &task
            .output
            .join("qualification-artifacts/package-uninstall"),
        &uninstall,
    )?;
    let mut failure = None;
    if let Err(error) = require_success(&uninstall, "package uninstall") {
        failure = Some(error);
    } else {
        let verify = run_bounded(
            &agent,
            [
                OsStr::new("package"),
                OsStr::new("verify"),
                OsStr::new("--json"),
            ],
            Duration::from_secs(45),
            ADMIN_OUTPUT_LIMIT,
        )?;
        retain_command(
            &task.output.join("qualification-artifacts/package-absence"),
            &verify,
        )?;
        if verify.status.success() {
            failure = Some("MemCordon package remains installed after uninstall".to_owned());
        } else if let Err(error) =
            require_expected_verification_failure(&verify, "post-uninstall package verification")
        {
            failure = Some(error);
        } else if let Err(error) = prove_native_absence(task, "post-uninstall-footprint") {
            failure = Some(error);
        }
    }
    let receipt = ProviderCleanupReceiptV1 {
        schema_version: PROVIDER_CLEANUP_RECEIPT_SCHEMA_V1,
        provider_lease_id: lease.provider_lease_id,
        operation_id: task.operation.clone(),
        platform: acquisition.platform,
        attempted: true,
        final_state: if failure.is_none() {
            ProviderLifecycleState::Removed
        } else {
            ProviderLifecycleState::FailedDirty
        },
        installed_footprint_absent: failure.is_none(),
        active_operations: lease.active_operations,
        failure: failure.clone(),
    };
    receipt.validate().map_err(|error| error.to_string())?;
    write_serde(&task.output.join("provider-cleanup.json"), &receipt)?;
    failure.map_or_else(
        || Ok("retired and removed MemCordon provider".to_owned()),
        Err,
    )
}

pub(super) fn find_component(root: &Path, name: &str) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect runtime root: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("MemCordon runtime root is not a real directory".to_owned());
    }
    let root =
        fs::canonicalize(root).map_err(|error| format!("cannot bind runtime root: {error}"))?;
    let mut pending = vec![root.clone()];
    let mut found = Vec::new();
    let mut observed = 0_usize;
    while let Some(directory) = pending.pop() {
        let metadata = fs::symlink_metadata(&directory)
            .map_err(|error| format!("cannot inspect runtime directory: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("MemCordon runtime directory was redirected".to_owned());
        }
        let entries = fs::read_dir(&directory)
            .map_err(|error| format!("cannot enumerate {}: {error}", directory.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("cannot read runtime entry: {error}"))?;
            observed = observed.saturating_add(1);
            if observed > 256 {
                return Err("MemCordon runtime has more than 256 entries".to_owned());
            }
            let kind = entry
                .file_type()
                .map_err(|error| format!("cannot inspect runtime entry: {error}"))?;
            if kind.is_symlink() {
                return Err("MemCordon runtime contains a symbolic link".to_owned());
            }
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() && component_name_matches(&entry.file_name(), name) {
                found.push(entry.path());
            }
        }
    }
    match found.as_slice() {
        [path] => {
            let metadata = fs::symlink_metadata(path)
                .map_err(|error| format!("cannot inspect runtime component: {error}"))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("MemCordon runtime component is not a regular file".to_owned());
            }
            let canonical = fs::canonicalize(path)
                .map_err(|error| format!("cannot bind runtime component: {error}"))?;
            if !canonical.is_absolute() || !canonical.starts_with(&root) || canonical != *path {
                return Err("MemCordon runtime component escaped or redirected its root".to_owned());
            }
            Ok(canonical)
        }
        [] => Err(format!("MemCordon runtime component {name} is missing")),
        _ => Err(format!("MemCordon runtime component {name} is ambiguous")),
    }
}

fn component_name_matches(observed: &OsStr, expected: &str) -> bool {
    if cfg!(windows) {
        observed
            .to_str()
            .is_some_and(|value| value.eq_ignore_ascii_case(expected))
    } else {
        observed == OsStr::new(expected)
    }
}

pub(super) fn run_bounded<I, S>(
    program: &Path,
    arguments: I,
    timeout: Duration,
    limit: usize,
) -> Result<Captured, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    // Provider administration and runtime qualification are trusted host work;
    // candidate operations use the sealed platform authority in execute.rs.
    let mut output = CommandSpec::new(program, timeout)
        .arguments(
            arguments
                .into_iter()
                .map(|argument| argument.as_ref().to_os_string()),
        )
        .release_candidate_environment()
        .run_trusted_host_captured()
        .map_err(|error| format!("cannot supervise {}: {error}", program.display()))?;
    if output.timed_out {
        return Err(format!(
            "{} exceeded its bounded deadline ({})",
            program.display(),
            output.status
        ));
    }
    let stdout_overflow =
        output.stdout_truncated || u128::from(output.stdout_bytes) > limit as u128;
    let stderr_overflow =
        output.stderr_truncated || u128::from(output.stderr_bytes) > limit as u128;
    output.stdout.truncate(limit);
    output.stderr.truncate(limit);
    Ok(Captured {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
        stdout_overflow,
        stderr_overflow,
    })
}

pub(super) fn run_provider_frontend<I, S>(
    program: &Path,
    arguments: I,
    timeout: Duration,
    limit: usize,
) -> Result<Captured, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let arguments = arguments
        .into_iter()
        .map(|argument| argument.as_ref().to_os_string())
        .collect::<Vec<_>>();
    #[cfg(target_os = "linux")]
    {
        let program = fs::canonicalize(program)
            .map_err(|error| format!("cannot bind provider frontend: {error}"))?;
        let (program, arguments) =
            hell_testkit::provider_frontend::authorized_linux_frontend(&program, &arguments)
                .map_err(|error| format!("cannot authorize non-root provider frontend: {error}"))?;
        run_bounded(&program, &arguments, timeout, limit)
    }
    #[cfg(not(target_os = "linux"))]
    run_bounded(program, &arguments, timeout, limit)
}

fn run_elevated_agent(
    agent: &Path,
    arguments: &[OsString],
    timeout: Duration,
) -> Result<Captured, String> {
    #[cfg(target_os = "linux")]
    {
        let mut elevated = vec![
            OsString::from("--non-interactive"),
            OsString::from("--"),
            agent.as_os_str().to_owned(),
        ];
        elevated.extend_from_slice(arguments);
        run_bounded(
            Path::new("/usr/bin/sudo"),
            &elevated,
            timeout,
            ADMIN_OUTPUT_LIMIT,
        )
    }
    #[cfg(windows)]
    {
        run_bounded(agent, arguments, timeout, ADMIN_OUTPUT_LIMIT)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (agent, arguments, timeout);
        Err("MemCordon package mutation is unavailable on this platform".to_owned())
    }
}

fn require_expected_verification_failure(captured: &Captured, label: &str) -> Result<(), String> {
    crate::provider_presence::verify_failure_protocol(
        cfg!(target_os = "linux"),
        captured.status.code(),
        &captured.stdout,
        &captured.stderr,
        captured.stdout_overflow || captured.stderr_overflow,
    )
    .map_err(|error| format!("{label}: {error}"))
}

fn prove_native_absence(task: &Task, evidence_name: &str) -> Result<(), String> {
    let mut observations = Vec::new();
    let inspection = inspect_native_footprint(task, evidence_name, &mut observations);
    let result = inspection.and_then(|()| crate::provider_presence::require_absent(&observations));
    write_serde(
        &task.output.join(evidence_name).with_extension("json"),
        &serde_json::json!({
            "schemaVersion": 1,
            "contract": "memcordon-0.5.2-rc.23",
            "observations": observations,
            "absent": result.is_ok(),
            "failure": result.as_ref().err(),
        }),
    )?;
    result
}

#[cfg(target_os = "linux")]
fn inspect_native_footprint(
    task: &Task,
    evidence_name: &str,
    observations: &mut Vec<crate::provider_presence::Observation>,
) -> Result<(), String> {
    use crate::provider_presence::{LINUX_PATHS, LINUX_UNITS, Observation, Presence, observe_path};
    observations.extend(LINUX_PATHS.iter().map(|path| observe_path(Path::new(path))));
    for unit in LINUX_UNITS {
        let captured = run_bounded(
            Path::new("/usr/bin/systemctl"),
            [
                "show",
                "--all",
                "--no-pager",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=FragmentPath",
                "--property=UnitFileState",
                "--",
                unit,
            ],
            Duration::from_secs(15),
            ADMIN_OUTPUT_LIMIT,
        )?;
        retain_command(
            &task
                .output
                .join("qualification-artifacts")
                .join(evidence_name)
                .join(unit),
            &captured,
        )?;
        let state = require_success(&captured, "systemd footprint inspection")
            .and_then(|()| crate::provider_presence::systemd_unit_absent(&captured.stdout));
        observations.push(Observation {
            authority: (*unit).to_owned(),
            presence: if state.is_ok() {
                Presence::Absent
            } else {
                Presence::Unreadable
            },
            detail: state.err(),
        });
    }
    Ok(())
}

#[cfg(windows)]
fn inspect_native_footprint(
    task: &Task,
    evidence_name: &str,
    observations: &mut Vec<crate::provider_presence::Observation>,
) -> Result<(), String> {
    use crate::process_environment::{ProcessEnvironment, StandardVariable};
    use crate::provider_presence::{
        Observation, Presence, WINDOWS_PIPES, WINDOWS_SERVICES, observe_path,
    };
    let environment = ProcessEnvironment::from_process();
    let program_files = PathBuf::from(
        environment.required_singleton_value(StandardVariable::ProgramFiles, "ProgramFiles")?,
    );
    let program_data = PathBuf::from(
        environment.required_singleton_value(StandardVariable::ProgramData, "ProgramData")?,
    );
    let system_root = PathBuf::from(
        environment.required_singleton_value(StandardVariable::SystemRoot, "SystemRoot")?,
    );
    if [&program_files, &program_data, &system_root]
        .iter()
        .any(|path| !path.is_absolute())
    {
        return Err("Windows provider authority roots must be absolute".to_owned());
    }
    let state_parent = program_data.join("MemCordon");
    let state = state_parent.join("sealed");
    for path in [
        program_files.join("MemCordon"),
        state_parent,
        state.join("package").join("scm-launcher-connect-ace-owned"),
        state.join("guardian-slots"),
        state,
    ] {
        observations.push(observe_path(&path));
    }
    let sc = system_root.join("System32").join("sc.exe");
    for service in WINDOWS_SERVICES {
        let captured = run_bounded(
            &sc,
            ["query", service],
            Duration::from_secs(15),
            ADMIN_OUTPUT_LIMIT,
        )?;
        retain_command(
            &task
                .output
                .join("qualification-artifacts")
                .join(evidence_name)
                .join(service),
            &captured,
        )?;
        observations.push(Observation {
            authority: (*service).to_owned(),
            presence: if captured.status.code() == Some(1060)
                && !captured.stdout_overflow
                && !captured.stderr_overflow
            {
                Presence::Absent
            } else if captured.status.success() {
                Presence::Present
            } else {
                Presence::Unreadable
            },
            detail: Some(captured.status.to_string()),
        });
    }
    let pipes = fs::read_dir(r"\\.\pipe\")
        .map_err(|error| format!("cannot enumerate native pipe authority: {error}"))?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot inspect native pipe authority: {error}"))?;
    for pipe in WINDOWS_PIPES {
        let present = pipes
            .iter()
            .any(|name| name.to_string_lossy().eq_ignore_ascii_case(pipe));
        observations.push(Observation {
            authority: (*pipe).to_owned(),
            presence: if present {
                Presence::Present
            } else {
                Presence::Absent
            },
            detail: None,
        });
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", windows)))]
fn inspect_native_footprint(
    _task: &Task,
    _evidence_name: &str,
    _observations: &mut Vec<crate::provider_presence::Observation>,
) -> Result<(), String> {
    Err("native sealed provider footprint inspection is unsupported on this platform".to_owned())
}

fn read_acquisition(task: &Task) -> Result<AcquisitionReceiptV1, String> {
    let bytes = fs::read(task.output.join("acquisition.json"))
        .map_err(|error| format!("cannot read MemCordon acquisition receipt: {error}"))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("MemCordon acquisition receipt is invalid: {error}"))
}

pub(super) fn lease_id(task: &Task, acquisition: &AcquisitionReceiptV1) -> String {
    let binding = format!(
        "{}\0{}\0{}",
        task.operation,
        Task::platform_id().unwrap_or("unsupported"),
        acquisition.runtime_lock_digest
    );
    hell_testkit::sha256_bytes(binding.as_bytes()).hex()
}

fn write_serde(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("cannot serialize MemCordon receipt: {error}"))?;
    let text = std::str::from_utf8(&bytes).expect("JSON serializer emits UTF-8");
    write_json(path, &parse_json(text)?)?;
    Ok(())
}

pub(super) fn create_evidence_directories(root: &Path) -> Result<(), String> {
    fs::create_dir_all(root)
        .map_err(|error| format!("cannot create MemCordon evidence root: {error}"))?;
    for relative in [
        "raw",
        "normalized",
        "adapters",
        "frontend",
        "qualification-artifacts",
    ] {
        let directory = root.join(relative);
        fs::create_dir_all(&directory)
            .map_err(|error| format!("cannot create MemCordon evidence directory: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("cannot protect MemCordon evidence directory: {error}"))?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("cannot protect MemCordon evidence root: {error}"))?;
    }
    Ok(())
}

pub(super) const fn agent_name() -> &'static str {
    if cfg!(windows) {
        "memcordon-sealed-agent.exe"
    } else {
        "memcordon-sealed-agent"
    }
}

pub(super) const fn cli_name() -> &'static str {
    if cfg!(windows) {
        "memcordon.exe"
    } else {
        "memcordon"
    }
}

pub(super) fn string(value: &str) -> JsonValue {
    JsonValue::String(value.to_owned())
}

pub(super) const fn number(value: u64) -> JsonValue {
    JsonValue::Number(value)
}
