use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use hell_memcordon::{
    AcquisitionReceiptV1, PROVIDER_CLEANUP_RECEIPT_SCHEMA_V1, PROVIDER_RECEIPT_SCHEMA_V1,
    ProviderCleanupReceiptV1, ProviderLeaseStateMachine, ProviderLifecycleReceiptV1,
    ProviderLifecycleState,
};

use crate::json::{JsonValue, parse_json};
use crate::release::manifest::{write_atomic, write_json};

use super::task::Task;

const ADMIN_OUTPUT_LIMIT: usize = 2 * 1024 * 1024;
const ADMIN_TIMEOUT: Duration = Duration::from_mins(3);

pub(super) struct Captured {
    pub(super) status: ExitStatus,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
    pub(super) stdout_overflow: bool,
    pub(super) stderr_overflow: bool,
}

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
    require_documented_absence(&preexisting, "pre-install package verification")?;
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

    let verify = run_bounded(
        agent,
        [
            OsStr::new("package"),
            OsStr::new("verify"),
            OsStr::new("--json"),
        ],
        ADMIN_TIMEOUT,
        ADMIN_OUTPUT_LIMIT,
    )?;
    require_json_success(&verify, "package verify")?;
    write_atomic(&task.output.join("package-verify.json"), &verify.stdout)?;

    let doctor = run_bounded(
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
    require_json_success(&doctor, "doctor --require sealed")?;
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
        let receipt = ProviderCleanupReceiptV1 {
            schema_version: PROVIDER_CLEANUP_RECEIPT_SCHEMA_V1,
            provider_lease_id: lease_id(task, &acquisition),
            operation_id: task.operation.clone(),
            platform: acquisition.platform,
            attempted: false,
            final_state: ProviderLifecycleState::Absent,
            installed_footprint_absent: true,
            active_operations: 0,
            failure: None,
        };
        receipt.validate().map_err(|error| error.to_string())?;
        write_serde(&task.output.join("provider-cleanup.json"), &receipt)?;
        return Ok("MemCordon provider was not installed by this task".to_owned());
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
            require_documented_absence(&verify, "post-uninstall package verification")
        {
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
    let mut pending = vec![root.to_path_buf()];
    let mut found = Vec::new();
    let mut observed = 0_usize;
    while let Some(directory) = pending.pop() {
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
        [path] => Ok(path.clone()),
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
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot spawn {}: {error}", program.display()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "stdout pipe is missing".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "stderr pipe is missing".to_owned())?;
    let stdout_reader = thread::spawn(move || read_bounded(stdout, limit));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, limit));
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            Ok(None) => {
                let _ = child.kill();
                let status = child
                    .wait()
                    .map_err(|error| format!("cannot reap timed-out process: {error}"))?;
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(format!(
                    "{} exceeded its bounded deadline ({status})",
                    program.display()
                ));
            }
            Err(error) => return Err(format!("cannot wait for {}: {error}", program.display())),
        }
    };
    let (stdout, stdout_overflow) = stdout_reader
        .join()
        .map_err(|_| "stdout reader panicked".to_owned())??;
    let (stderr, stderr_overflow) = stderr_reader
        .join()
        .map_err(|_| "stderr reader panicked".to_owned())??;
    Ok(Captured {
        status,
        stdout,
        stderr,
        stdout_overflow,
        stderr_overflow,
    })
}

fn read_bounded(mut reader: impl Read, limit: usize) -> Result<(Vec<u8>, bool), String> {
    let mut retained = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    let mut overflow = false;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("cannot drain command output: {error}"))?;
        if read == 0 {
            break;
        }
        let available = limit.saturating_sub(retained.len());
        let keep = available.min(read);
        retained.extend_from_slice(&buffer[..keep]);
        overflow |= keep != read;
    }
    Ok((retained, overflow))
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

fn require_json_success(captured: &Captured, label: &str) -> Result<(), String> {
    require_success(captured, label)?;
    let text = std::str::from_utf8(&captured.stdout)
        .map_err(|_| format!("{label} output is not UTF-8 JSON"))?;
    parse_json(text).map(|_| ())
}

fn require_success(captured: &Captured, label: &str) -> Result<(), String> {
    if captured.stdout_overflow || captured.stderr_overflow {
        return Err(format!("{label} exceeded its output bound"));
    }
    if !captured.status.success() {
        let diagnostic = String::from_utf8_lossy(&captured.stderr);
        return Err(format!(
            "{label} failed with {}: {diagnostic}",
            captured.status
        ));
    }
    Ok(())
}

fn require_documented_absence(captured: &Captured, label: &str) -> Result<(), String> {
    if captured.stdout_overflow || captured.stderr_overflow {
        return Err(format!("{label} exceeded its output bound"));
    }
    if captured.status.success() {
        return Err(format!("{label} reported an installed package"));
    }
    let stdout = std::str::from_utf8(&captured.stdout)
        .map_err(|_| format!("{label} stdout is not UTF-8"))?;
    let stderr = std::str::from_utf8(&captured.stderr)
        .map_err(|_| format!("{label} stderr is not UTF-8"))?;
    let diagnostic = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    if !diagnostic.contains("not installed") && !diagnostic.contains("not-installed") {
        return Err(format!(
            "{label} failed without the documented missing-package result"
        ));
    }
    Ok(())
}

fn retain_command(prefix: &Path, captured: &Captured) -> Result<(), String> {
    let mut stdout = prefix.as_os_str().to_owned();
    stdout.push(".stdout");
    let mut stderr = prefix.as_os_str().to_owned();
    stderr.push(".stderr");
    write_atomic(Path::new(&stdout), &captured.stdout)?;
    write_atomic(Path::new(&stderr), &captured.stderr)
}

fn read_acquisition(task: &Task) -> Result<AcquisitionReceiptV1, String> {
    let bytes = fs::read(task.output.join("acquisition.json"))
        .map_err(|error| format!("cannot read MemCordon acquisition receipt: {error}"))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("MemCordon acquisition receipt is invalid: {error}"))
}

fn lease_id(task: &Task, acquisition: &AcquisitionReceiptV1) -> String {
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
