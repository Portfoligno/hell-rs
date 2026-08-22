use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io::{Read as _, Write as IoWrite};
#[cfg(windows)]
use std::io::{Seek as _, SeekFrom};
#[cfg(unix)]
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
#[cfg(windows)]
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
#[cfg(unix)]
use std::os::fd::AsRawFd as _;
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
#[cfg(windows)]
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::sync::{OnceLock, mpsc};
use std::time::{Duration, Instant};

use hell_testkit::{
    DifferentialBatchTiming, DifferentialCase, DifferentialMismatch, DifferentialReport,
    DifferentialTiming, Digest, ExecutableIdentity, ExecutableInvocationAuthority, ExecutableRole,
    GeneratedCase, MismatchKind, SupervisedOutputStream, SupervisedProgressObserver,
    bind_process_helper_directory, committed_differential_cases,
    differential_batch_with_identities, differential_batch_with_invocations,
    differential_inventory_sha256, differential_worker_limit, generated_typed_cases,
    representative_differential_sample, sha256_bytes, sha256_file, verify_executable,
};

use crate::command::{CommandSpec, NativeProcessSpec, NativeStdio, release_candidate_target};
use crate::compatibility;
use crate::identity::require_git_sha;
use crate::json::{JsonValue, canonical_json_bytes};
#[cfg(windows)]
use crate::process_environment::{ProcessEnvironment, StandardVariable};
use crate::report::{ActivePhaseAttribution, Report};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureKind {
    Policy,
    Child,
    Fixture,
}

const WORKSPACE_TEST_TIMEOUT: Duration = Duration::from_mins(90);
const NIGHTLY_WORKSPACE_TEST_TIMEOUT: Duration = Duration::from_hours(1);
const NIGHTLY_CORE_DATA_TEST_TIMEOUT: Duration = Duration::from_mins(30);
#[cfg(target_os = "macos")]
const NIGHTLY_MACOS_BROAD_WORKSPACE_TIMEOUT: Duration = Duration::from_mins(40);
#[cfg(target_os = "macos")]
const NIGHTLY_MACOS_STAGED_NATIVE_TOOLCHAIN_TIMEOUT: Duration = Duration::from_mins(20);
const NIGHTLY_COMMAND_CLEANUP_RESERVE: Duration = Duration::from_mins(5);
const NIGHTLY_REPORT_RESERVE: Duration = Duration::from_mins(1);
#[cfg(any(unix, windows))]
const NIGHTLY_SUPERVISOR_START_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(any(unix, windows))]
const NIGHTLY_SUPERVISOR_START_CLEANUP_RESERVE: Duration = Duration::from_secs(5);
#[cfg(any(unix, windows))]
const NIGHTLY_SUPERVISOR_PROTOCOL_MAGIC: &[u8] = b"hell-nightly-supervisor-v1\0";
#[cfg(any(unix, windows))]
const NIGHTLY_SUPERVISOR_ELAPSED_NONE: u64 = u64::MAX;
const NIGHTLY_SUPERVISOR_ELAPSED_MAX_MILLIS: u64 = u64::MAX - 1;
#[cfg(unix)]
const NIGHTLY_SUPERVISOR_REQUEST_LIMIT: usize = 32 * 1024;
#[cfg(unix)]
const NIGHTLY_SUPERVISOR_EXIT_WAITER_CAPACITY: u64 = 4;
#[cfg(unix)]
static NIGHTLY_SUPERVISOR_EXIT_WAITERS: AtomicU64 = AtomicU64::new(0);
#[cfg(any(unix, windows))]
const NIGHTLY_SUPERVISOR_TERMINAL_LIMIT: usize = 32 * 1024;
#[cfg(any(unix, windows))]
const NIGHTLY_SUPERVISOR_TERMINAL_MESSAGE: u8 = 5;
#[cfg(any(unix, windows))]
const NIGHTLY_SUPERVISOR_PROGRESS_FRAME_CAPACITY: u64 = 32;
#[cfg(any(unix, windows))]
const NIGHTLY_SUPERVISOR_PROGRESS_LIMIT: usize = 2048;
const TERMINAL_PERSISTENCE_RESERVE: Duration = Duration::from_secs(15);
const REPORT_WRITE_RESERVE: Duration = Duration::from_secs(15);
const NIGHTLY_CORE_DATA_TEST: &str =
    "core_data_obligations_round_trip_through_the_production_bundle_gate";
const NIGHTLY_CORE_DATA_TEST_TARGET: &str = "core_data_production_bundle";
#[cfg(windows)]
const WINDOWS_PARALLEL_WORKSPACE_TEST_TIMEOUT: Duration = Duration::from_mins(40);
#[cfg(windows)]
const WINDOWS_HELL_TESTKIT_DIAGNOSTIC_TIMEOUT: Duration = Duration::from_mins(5);
const PORTABILITY_SUITE_TIMEOUT: Duration = Duration::from_mins(40);
const PORTABILITY_CLEANUP_RESERVE: Duration = Duration::from_mins(5);
const PORTABILITY_PROGRESS_INTERVAL: Duration = Duration::from_secs(30);
const PORTABILITY_PROGRESS_DRAIN_INTERVAL: Duration = Duration::from_millis(100);
const PORTABILITY_PROGRESS_QUEUE_CAPACITY: usize = 64;
const PORTABILITY_ATTRIBUTION_LINE_LIMIT: usize = 16 * 1024;
const PORTABILITY_ATTRIBUTION_FIELD_LIMIT: usize = 256;
#[cfg(target_os = "macos")]
static PORTABILITY_PARTITION_SEQUENCE: AtomicU64 = AtomicU64::new(0);
#[cfg(target_os = "macos")]
const MACOS_STAGED_NATIVE_TOOLCHAIN_CASE: &str =
    "staged_native_toolchain_accepts_real_ghc_without_inner_launcher_aliases";

#[derive(Default)]
struct PortabilityChildProgress {
    suite: &'static str,
    stdout_observed: u64,
    stderr_observed: u64,
    stdout_relayed: usize,
    stderr_relayed: usize,
    stdout_line: Vec<u8>,
    stderr_line: Vec<u8>,
    stdout_line_truncated: bool,
    stderr_line_truncated: bool,
    sequence: u64,
    target: Option<String>,
    case: Option<String>,
    case_state: Option<PortabilityCaseState>,
    subphase: Option<String>,
    observed_started: Option<Instant>,
    last_transition_elapsed: Option<Duration>,
    failed_case: Option<CausalFailedCase>,
    case_line_truncated: bool,
}

#[derive(Clone)]
struct CausalFailedCase {
    sequence: u64,
    transition_elapsed: Option<Duration>,
    target: Option<String>,
    case: String,
    stream: String,
}

#[derive(Clone, Copy)]
enum PortabilityCaseState {
    Active,
    StillRunning,
    Completed,
    Passed,
    Ignored,
    Failed,
    TimedOutCleaned,
    LaunchFailed,
    Panicked,
    Retained,
    ReceiptDisconnected,
}

impl PortabilityCaseState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::StillRunning => "still-running",
            Self::Completed => "completed",
            Self::Passed => "passed",
            Self::Ignored => "ignored",
            Self::Failed => "failed",
            Self::TimedOutCleaned => "timed-out-cleaned",
            Self::LaunchFailed => "launch-failed",
            Self::Panicked => "panicked",
            Self::Retained => "retained",
            Self::ReceiptDisconnected => "receipt-disconnected",
        }
    }
}

enum PortabilityAttributionEvent {
    Target(String),
    Case(String, PortabilityCaseState),
    Subphase(String),
}

enum PortabilityWorkerOutcome<T> {
    Complete(T),
    CompletionDeadlineExpired,
    ReceiptDisconnected,
    Panicked,
}

type AttributedCommandResult =
    Result<crate::command::CommandResult, crate::command::CommandRunError>;
type AttributedCommandOutcome = PortabilityWorkerOutcome<AttributedCommandResult>;

enum AttributedWorkerTerminal {
    Complete(Result<crate::command::CommandResult, crate::command::CommandRunError>),
    Panicked,
}

struct AttributedWorkerTask {
    spec: CommandSpec,
    execution_deadline: Instant,
    child_completion_deadline: Instant,
    progress: SupervisedProgressObserver,
    terminal: mpsc::SyncSender<AttributedWorkerTerminal>,
    receipt: AttributedWorkerReceipt,
    permit: PortabilityWorkerPermit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AttributedWorkerState {
    Owned,
    Completed,
    Panicked,
    Rejected,
}

#[derive(Clone)]
struct AttributedWorkerReceipt {
    id: u64,
    state: Arc<(Mutex<AttributedWorkerState>, Condvar)>,
}

impl AttributedWorkerReceipt {
    fn new(id: u64) -> Self {
        Self {
            id,
            state: Arc::new((Mutex::new(AttributedWorkerState::Owned), Condvar::new())),
        }
    }

    fn finish(&self, state: AttributedWorkerState) {
        *self
            .state
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = state;
        self.state.1.notify_all();
    }

    fn wait_until(&self, deadline: Instant) -> AttributedWorkerState {
        let mut state = self
            .state
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *state == AttributedWorkerState::Owned {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let (next, timeout) = self
                .state
                .1
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
            if timeout.timed_out() && *state == AttributedWorkerState::Owned {
                break;
            }
        }
        *state
    }
}

fn attributed_worker_sender() -> Result<mpsc::Sender<AttributedWorkerTask>, String> {
    const WORKERS: usize = 4;
    static EXECUTOR: OnceLock<Result<mpsc::Sender<AttributedWorkerTask>, String>> = OnceLock::new();
    match EXECUTOR.get_or_init(|| {
        let (sender, receiver) = mpsc::channel::<AttributedWorkerTask>();
        let receiver = Arc::new(Mutex::new(receiver));
        for index in 0..WORKERS {
            let receiver = Arc::clone(&receiver);
            std::thread::Builder::new()
                .name(format!("hell-attributed-command-{index}"))
                .spawn(move || {
                    loop {
                        let task = {
                            let receiver = receiver
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            receiver.recv()
                        };
                        let Ok(task) = task else {
                            break;
                        };
                        let AttributedWorkerTask {
                            spec,
                            execution_deadline,
                            child_completion_deadline,
                            progress,
                            terminal: terminal_sender,
                            receipt,
                            permit,
                        } = task;
                        let _permit = permit;
                        let outcome =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                spec.run_until(
                                    execution_deadline,
                                    child_completion_deadline,
                                    progress,
                                )
                            }));
                        if let Ok(result) = outcome {
                            let _ =
                                terminal_sender.send(AttributedWorkerTerminal::Complete(result));
                            receipt.finish(AttributedWorkerState::Completed);
                        } else {
                            let _ = terminal_sender.send(AttributedWorkerTerminal::Panicked);
                            receipt.finish(AttributedWorkerState::Panicked);
                        }
                    }
                })
                .map_err(|error| format!("cannot start attributed command executor: {error}"))?;
        }
        Ok(sender)
    }) {
        Ok(sender) => Ok(sender.clone()),
        Err(error) => Err(error.clone()),
    }
}

#[cfg(target_os = "macos")]
struct MacosStagedWorkerTask {
    operation: Box<dyn FnOnce() -> Result<(), String> + Send>,
    terminal: mpsc::SyncSender<Result<(), String>>,
    receipt: AttributedWorkerReceipt,
    permit: PortabilityWorkerPermit,
}

#[cfg(target_os = "macos")]
fn macos_staged_worker_sender() -> Result<mpsc::Sender<MacosStagedWorkerTask>, String> {
    const WORKERS: usize = 2;
    static EXECUTOR: OnceLock<Result<mpsc::Sender<MacosStagedWorkerTask>, String>> =
        OnceLock::new();
    match EXECUTOR.get_or_init(|| {
        let (sender, receiver) = mpsc::channel::<MacosStagedWorkerTask>();
        let receiver = Arc::new(Mutex::new(receiver));
        for index in 0..WORKERS {
            let receiver = Arc::clone(&receiver);
            std::thread::Builder::new()
                .name(format!("hell-macos-staged-worker-{index}"))
                .spawn(move || {
                    loop {
                        let task = {
                            let receiver = receiver
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            receiver.recv()
                        };
                        let Ok(task) = task else {
                            break;
                        };
                        let MacosStagedWorkerTask {
                            operation,
                            terminal,
                            receipt,
                            permit,
                        } = task;
                        let _permit = permit;
                        let outcome =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
                        if let Ok(result) = outcome {
                            receipt.finish(AttributedWorkerState::Completed);
                            let _ = terminal.send(result);
                        } else {
                            receipt.finish(AttributedWorkerState::Panicked);
                            drop(terminal);
                        }
                    }
                })
                .map_err(|error| format!("cannot start macOS staged worker executor: {error}"))?;
        }
        Ok(sender)
    }) {
        Ok(sender) => Ok(sender.clone()),
        Err(error) => Err(error.clone()),
    }
}

#[derive(Clone, Copy)]
struct SupervisionEnvelope {
    execution: Instant,
    child_completion_deadline: Instant,
    report_completion_deadline: Instant,
}

#[derive(Clone, Copy)]
struct AttributedRunContext<'a> {
    name: &'a str,
    suite: &'static str,
    suite_started: Instant,
    envelope: SupervisionEnvelope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExternalSupervisorPlan {
    NightlyWorkspace,
    #[cfg(target_os = "macos")]
    MacosStagedNativeToolchain,
    NightlyCoreData,
    #[cfg(windows)]
    WindowsAuthorityProbe,
    #[cfg(windows)]
    WindowsCoreAuthorityProbe,
}

impl ExternalSupervisorPlan {
    #[cfg(windows)]
    fn combined_followup(self) -> Option<Self> {
        match self {
            Self::NightlyWorkspace => Some(Self::NightlyCoreData),
            Self::WindowsAuthorityProbe => Some(Self::WindowsCoreAuthorityProbe),
            Self::NightlyCoreData | Self::WindowsCoreAuthorityProbe => None,
        }
    }

    #[cfg(any(unix, windows))]
    fn code(self) -> u8 {
        match self {
            Self::NightlyWorkspace => 1,
            Self::NightlyCoreData => 2,
            #[cfg(target_os = "macos")]
            Self::MacosStagedNativeToolchain => 5,
            #[cfg(windows)]
            Self::WindowsAuthorityProbe => 3,
            #[cfg(windows)]
            Self::WindowsCoreAuthorityProbe => 4,
        }
    }

    #[cfg(any(unix, windows))]
    fn from_code(code: u8) -> Result<Self, String> {
        match code {
            1 => Ok(Self::NightlyWorkspace),
            2 => Ok(Self::NightlyCoreData),
            #[cfg(target_os = "macos")]
            5 => Ok(Self::MacosStagedNativeToolchain),
            #[cfg(windows)]
            3 => Ok(Self::WindowsAuthorityProbe),
            #[cfg(windows)]
            4 => Ok(Self::WindowsCoreAuthorityProbe),
            _ => Err("nightly supervisor request has an unknown plan".to_owned()),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::NightlyWorkspace => "nightly-workspace-tests",
            #[cfg(target_os = "macos")]
            Self::MacosStagedNativeToolchain => "nightly-macos-staged-native-toolchain",
            Self::NightlyCoreData => "nightly-core-data-bundle-test",
            #[cfg(windows)]
            Self::WindowsAuthorityProbe => "nightly-windows-authority-probe",
            #[cfg(windows)]
            Self::WindowsCoreAuthorityProbe => "nightly-windows-core-authority-probe",
        }
    }

    fn total(self) -> Duration {
        match self {
            Self::NightlyWorkspace => nightly_workspace_command_timeout(),
            #[cfg(target_os = "macos")]
            Self::MacosStagedNativeToolchain => NIGHTLY_MACOS_STAGED_NATIVE_TOOLCHAIN_TIMEOUT,
            Self::NightlyCoreData => NIGHTLY_CORE_DATA_TEST_TIMEOUT,
            #[cfg(windows)]
            Self::WindowsAuthorityProbe => Duration::from_mins(10),
            #[cfg(windows)]
            Self::WindowsCoreAuthorityProbe => Duration::from_mins(10),
        }
    }

    fn seed(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::NightlyWorkspace => (
                "workspace-all-targets",
                "nightly-workspace-tests",
                "prelaunch",
            ),
            #[cfg(target_os = "macos")]
            Self::MacosStagedNativeToolchain => (
                "release_environment",
                MACOS_STAGED_NATIVE_TOOLCHAIN_CASE,
                "prelaunch",
            ),
            Self::NightlyCoreData => (
                NIGHTLY_CORE_DATA_TEST_TARGET,
                NIGHTLY_CORE_DATA_TEST,
                "prelaunch",
            ),
            #[cfg(windows)]
            Self::WindowsAuthorityProbe => (
                "windows-staged-cargo",
                "nightly-windows-authority-probe",
                "prelaunch",
            ),
            #[cfg(windows)]
            Self::WindowsCoreAuthorityProbe => (
                "windows-staged-core",
                "nightly-windows-core-authority-probe",
                "prelaunch",
            ),
        }
    }

    fn command(self, root: &Path, timeout: Duration) -> CommandSpec {
        let command = match self {
            Self::NightlyWorkspace => {
                CommandSpec::cargo(timeout).arguments(nightly_workspace_test_arguments())
            }
            #[cfg(target_os = "macos")]
            Self::MacosStagedNativeToolchain => CommandSpec::cargo(timeout)
                .arguments(nightly_macos_staged_native_toolchain_arguments()),
            Self::NightlyCoreData => CommandSpec::cargo(timeout).arguments([
                "test",
                "--package",
                "hell-testkit",
                "--test",
                NIGHTLY_CORE_DATA_TEST_TARGET,
                "--all-features",
                "--locked",
                NIGHTLY_CORE_DATA_TEST,
                "--",
                "--exact",
                "--nocapture",
            ]),
            #[cfg(windows)]
            Self::WindowsAuthorityProbe => CommandSpec::cargo(timeout).arguments([
                "check",
                "--package",
                "hell-builtins",
                "--lib",
                "--locked",
            ]),
            #[cfg(windows)]
            Self::WindowsCoreAuthorityProbe => CommandSpec::cargo(timeout).arguments([
                "check",
                "--package",
                "hell-digest",
                "--lib",
                "--locked",
            ]),
        };
        command.current_directory(root)
    }
}

#[cfg(target_os = "macos")]
fn nightly_workspace_command_timeout() -> Duration {
    NIGHTLY_MACOS_BROAD_WORKSPACE_TIMEOUT
}

#[cfg(not(target_os = "macos"))]
fn nightly_workspace_command_timeout() -> Duration {
    NIGHTLY_WORKSPACE_TEST_TIMEOUT
}

#[cfg(target_os = "macos")]
fn nightly_workspace_test_arguments() -> Vec<&'static str> {
    vec![
        "test",
        "--workspace",
        "--all-targets",
        "--all-features",
        "--locked",
        "--",
        "--skip",
        NIGHTLY_CORE_DATA_TEST,
        "--skip",
        MACOS_STAGED_NATIVE_TOOLCHAIN_CASE,
    ]
}

#[cfg(target_os = "macos")]
fn nightly_macos_staged_native_toolchain_arguments() -> Vec<&'static str> {
    vec![
        "test",
        "--package",
        "hell-ci",
        "--test",
        "release_environment",
        "--all-features",
        "--locked",
        MACOS_STAGED_NATIVE_TOOLCHAIN_CASE,
        "--",
        "--exact",
        "--nocapture",
    ]
}

#[cfg(not(target_os = "macos"))]
fn nightly_workspace_test_arguments() -> Vec<&'static str> {
    vec![
        "test",
        "--workspace",
        "--all-targets",
        "--all-features",
        "--locked",
        "--",
        "--skip",
        NIGHTLY_CORE_DATA_TEST,
    ]
}

#[cfg(windows)]
fn windows_write_restricted_supervisor_command(
    spec: CommandSpec,
    writable_target: &Path,
    imported: Option<&ImportedWindowsNightlyAuthority>,
    deadline: Instant,
) -> Result<CommandSpec, String> {
    if Instant::now() >= deadline {
        return Err("Windows restricted payload deadline expired before construction".to_owned());
    }
    let directory =
        spec.current_directory
            .clone()
            .unwrap_or(std::env::current_dir().map_err(|error| {
                format!("cannot resolve Windows nightly payload directory: {error}")
            })?);
    let directory = fs::canonicalize(&directory).map_err(|error| {
        format!("cannot canonicalize Windows nightly payload directory: {error}")
    })?;
    let program = PathBuf::from(&spec.program);
    let is_cargo = program
        .file_stem()
        .is_some_and(|name| name.eq_ignore_ascii_case("cargo"));
    let canonical_program = if is_cargo {
        let imported = imported.ok_or_else(|| {
            "Windows Nightly Cargo has no imported staged toolchain authority".to_owned()
        })?;
        imported.revalidate_until(deadline)?;
        let staged_cargo = imported
            .staged_cargo
            .clone()
            .ok_or_else(|| "Windows authority manifest has no staged Cargo".to_owned())?;
        if imported.staged_rustc.is_none() {
            return Err("Windows authority manifest has no staged rustc".to_owned());
        }
        staged_cargo
    } else {
        fs::canonicalize(&program)
            .map_err(|error| format!("cannot canonicalize Windows nightly payload: {error}"))?
    };
    let target_arguments = std::iter::once(canonical_program.into_os_string())
        .chain(spec.arguments.iter().cloned())
        .collect::<Vec<_>>();
    let mut environment: Vec<(std::ffi::OsString, std::ffi::OsString)> = if spec.clear_environment {
        Vec::new()
    } else {
        ProcessEnvironment::from_process().release_child_entries()
    };
    for (name, value) in spec.environment {
        if let Some(index) = environment
            .iter()
            .position(|(existing, _)| existing.eq_ignore_ascii_case(&name))
        {
            environment[index] = (name, value);
        } else {
            environment.push((name, value));
        }
    }
    if let Some(imported) = imported {
        let staged_bin = imported
            .staged_rustc
            .as_deref()
            .and_then(Path::parent)
            .ok_or_else(|| "imported Windows rustc has no staged bin".to_owned())?;
        let environment = ProcessEnvironment::from_process();
        let system_root = environment
            .value(StandardVariable::SystemRoot)
            .map(PathBuf::from)
            .ok_or_else(|| "Windows SystemRoot is unavailable".to_owned())?;
        let restricted_path = std::env::join_paths([
            staged_bin.to_path_buf(),
            system_root.join("System32"),
            system_root,
        ])
        .map_err(|error| format!("cannot construct staged Windows PATH: {error}"))?;
        if let Some((_, value)) = environment
            .iter_mut()
            .find(|(name, _)| name.eq_ignore_ascii_case("PATH"))
        {
            *value = restricted_path;
        } else {
            environment.push(("PATH".into(), restricted_path));
        }
    }
    let current_exe = fs::canonicalize(
        std::env::current_exe()
            .map_err(|error| format!("cannot locate Windows nightly supervisor: {error}"))?,
    )
    .map_err(|error| format!("cannot canonicalize Windows nightly supervisor: {error}"))?;
    let adapter = current_exe
        .parent()
        .ok_or_else(|| "Windows nightly supervisor has no executable parent".to_owned())?
        .join("hell-test-helper.exe");
    let adapter = fs::canonicalize(&adapter)
        .map_err(|error| format!("cannot canonicalize Windows restricted adapter: {error}"))?;
    let (adapter_guard, adapter_receipt) = windows_bind_path(&adapter, false)?;
    let adapter_sha256 = hell_testkit::sha256_retained_windows_file_until(&adapter_guard, deadline)
        .map_err(|error| format!("cannot hash retained Windows restricted adapter: {error}"))?;
    if Instant::now() >= deadline
        || windows_file_receipt(&adapter_guard)? != adapter_receipt
        || windows_bind_path(&adapter, false)?.1 != adapter_receipt
    {
        return Err("Windows restricted adapter changed during request construction".to_owned());
    }
    let mut request = vec![adapter.as_os_str().to_owned()];
    request.push(adapter_sha256.hex().into());
    request.extend(
        hell_testkit::windows_nightly_child_request_fields_for_integration(
            &directory,
            environment,
            &target_arguments,
            writable_target,
        )
        .map_err(|error| format!("cannot encode Windows restricted payload policy: {error}"))?,
    );
    let encoded = hell_testkit::encode_windows_argv(&request)
        .map_err(|error| format!("cannot encode Windows restricted payload request: {error}"))?;
    if Instant::now() >= deadline || windows_file_receipt(&adapter_guard)? != adapter_receipt {
        return Err("Windows restricted payload deadline expired before launch".to_owned());
    }
    Ok(CommandSpec::trusted_absolute(current_exe, spec.timeout)?
        .arguments(["__nightly-write-restricted-child".into(), encoded])
        .current_directory(directory))
}

#[cfg(windows)]
pub(crate) fn run_windows_supervisor_icacls(
    root: &Path,
    arguments: &[&str],
    deadline: Instant,
) -> Result<(), String> {
    let environment = ProcessEnvironment::from_process();
    let system_root = environment
        .value(StandardVariable::SystemRoot)
        .ok_or_else(|| "standard Windows SystemRoot is unavailable".to_owned())?;
    let system32 = fs::canonicalize(PathBuf::from(system_root).join("System32"))
        .map_err(|error| format!("cannot canonicalize Windows System32: {error}"))?;
    let icacls = fs::canonicalize(system32.join("icacls.exe"))
        .map_err(|error| format!("cannot canonicalize Windows icacls.exe: {error}"))?;
    if icacls.parent() != Some(system32.as_path())
        || !fs::symlink_metadata(&icacls)
            .map_err(|error| format!("cannot inspect Windows icacls.exe: {error}"))?
            .is_file()
    {
        return Err("Windows icacls.exe is not one canonical System32 file".to_owned());
    }
    let now = Instant::now();
    let remaining = deadline.saturating_duration_since(now);
    if remaining.is_zero() {
        return Err("Windows supervisor DACL deadline expired".to_owned());
    }
    let execution_deadline = now
        .checked_add(remaining / 2)
        .ok_or_else(|| "Windows supervisor DACL execution deadline overflowed".to_owned())?;
    let (discard_progress, _discard_receiver) = SupervisedProgressObserver::bounded(1);
    let result = CommandSpec::trusted_absolute(icacls, remaining)?
        .argument(root.as_os_str())
        .arguments(arguments.iter().copied())
        .run_until(execution_deadline, deadline, discard_progress)
        .map_err(|error| format!("Windows supervisor DACL command failed: {error}"))?;
    if !result.status.success() || result.timed_out {
        return Err(format!(
            "Windows supervisor DACL command rejected policy: status={:?} timedOut={} stderr={}",
            result.status.code(),
            result.timed_out,
            String::from_utf8_lossy(&result.stderr)
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn protect_windows_supervisor_session(root: &Path, deadline: Instant) -> Result<(), String> {
    run_windows_supervisor_icacls(root, &["/reset", "/T", "/C"], deadline)?;
    run_windows_supervisor_icacls(root, &["/setowner", "*S-1-5-32-544", "/T", "/C"], deadline)?;
    run_windows_supervisor_icacls(
        root,
        &[
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-32-544:(OI)(CI)(F)",
            "*S-1-5-18:(OI)(CI)(F)",
            "*S-1-5-11:(OI)(CI)(RX)",
            "*S-1-5-12:(OI)(CI)(RX)",
            "/T",
            "/C",
        ],
        deadline,
    )
}

#[cfg(windows)]
fn protect_windows_supervisor_receipt(path: &Path, deadline: Instant) -> Result<(), String> {
    run_windows_supervisor_icacls(path, &["/reset"], deadline)?;
    run_windows_supervisor_icacls(path, &["/setowner", "*S-1-5-32-544"], deadline)?;
    run_windows_supervisor_icacls(
        path,
        &[
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-32-544:(F)",
            "*S-1-5-18:(F)",
            "*S-1-5-11:(R)",
            "*S-1-5-12:(R)",
        ],
        deadline,
    )
}

#[cfg(windows)]
fn reset_windows_supervisor_session(root: &Path, deadline: Instant) -> Result<(), String> {
    run_windows_supervisor_icacls(root, &["/reset", "/T", "/C"], deadline)
}

#[cfg(not(any(unix, windows)))]
fn run_direct_nightly_command(
    root: &Path,
    report: &mut Report,
    plan: ExternalSupervisorPlan,
    suite_started: Instant,
    outer_deadline: Instant,
) -> Result<(), FailureKind> {
    let started = Instant::now();
    let envelope = SupervisionEnvelope::within(
        started,
        plan.total(),
        NIGHTLY_COMMAND_CLEANUP_RESERVE,
        NIGHTLY_REPORT_RESERVE,
        outer_deadline,
    )
    .map_err(|error| {
        report.check("nightly-deadline", Duration::ZERO, Err(error));
        FailureKind::Policy
    })?;
    let seed = plan.seed();
    run_attributed_command(
        report,
        AttributedRunContext {
            name: plan.name(),
            suite: "nightly",
            suite_started,
            envelope,
        },
        Some(seed),
        |timeout| plan.command(root, timeout),
    )
}

#[cfg(unix)]
struct ExternalSupervisorRequest {
    plan: ExternalSupervisorPlan,
    root: PathBuf,
    root_device: u64,
    root_inode: u64,
    root_uid: u32,
    root_mode: u32,
    nonce: Digest,
    session_device: u64,
    session_inode: u64,
    session_uid: u32,
    terminal_observer: Option<SocketAddrV4>,
    launch_gate: Option<SocketAddrV4>,
    fixture_command: bool,
    fixture_control: ExternalSupervisorFixtureControl,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExternalSupervisorFixtureControl {
    Normal = 0,
    CloseBeforeTerminal = 1,
    FailBeforeTerminal = 2,
}

#[cfg(unix)]
impl ExternalSupervisorFixtureControl {
    fn from_byte(value: u8) -> Result<Self, String> {
        match value {
            0 => Ok(Self::Normal),
            1 => Ok(Self::CloseBeforeTerminal),
            2 => Ok(Self::FailBeforeTerminal),
            _ => Err("nightly supervisor fixture control is invalid".to_owned()),
        }
    }
}

#[cfg(any(unix, windows))]
struct ExternalSupervisorTerminal {
    execution: ExternalSupervisorExecutionState,
    exit_code: Option<i32>,
    stdout_bytes: u64,
    stdout_sha256: Digest,
    stderr_bytes: u64,
    stderr_sha256: Digest,
    capture: ExternalSupervisorCaptureState,
    cleanup: ExternalSupervisorCleanupState,
    cleanup_id: Option<u64>,
    candidate_quiescence_complete: bool,
    cleanup_state: String,
    cleanup_error: Option<String>,
    cleanup_failures: Vec<String>,
    detail: String,
    attribution: ActivePhaseAttribution,
    failed_case: Option<CausalFailedCase>,
    failed_case_unavailable: Option<String>,
    dropped_chunks: u64,
    dropped_bytes: u64,
}

#[cfg(any(unix, windows))]
struct ExternalSupervisorExecutionState {
    success: bool,
    timed_out: bool,
}

#[cfg(any(unix, windows))]
struct ExternalSupervisorCaptureState {
    stdout_truncated: bool,
    stderr_truncated: bool,
    available: bool,
}

#[cfg(any(unix, windows))]
struct ExternalSupervisorCleanupState {
    terminal: bool,
    termination_requested: bool,
    leader_reaped: bool,
}

#[cfg(unix)]
struct ExternalSupervisorStarted {
    exit: ExternalSupervisorExitReceipt,
    control_input: std::process::ChildStdin,
    control_output: std::process::ChildStdout,
    session: NightlyFixtureRoot,
    request_sha256: Digest,
    nonce: Digest,
    envelope: SupervisionEnvelope,
    launch_ownership_uncertain: Option<String>,
}

#[cfg(unix)]
struct ExternalSupervisorStartPolicy {
    total: Duration,
    cleanup_reserve: Duration,
    report_reserve: Duration,
    terminal_observer: Option<SocketAddrV4>,
    launch_gate: Option<SocketAddrV4>,
    fixture_command: bool,
    fixture_control: ExternalSupervisorFixtureControl,
    session_parent: PathBuf,
}

#[cfg(unix)]
impl ExternalSupervisorStarted {
    fn pid(&self) -> u32 {
        self.exit.pid
    }
}

#[cfg(unix)]
struct ExternalSupervisorExitWaiter {
    child: mpsc::SyncSender<std::process::Child>,
    terminal: mpsc::Receiver<Result<std::process::ExitStatus, String>>,
}

#[cfg(unix)]
struct ExternalSupervisorExitPermit;

#[cfg(unix)]
impl ExternalSupervisorExitPermit {
    fn acquire() -> Result<Self, String> {
        let mut observed = NIGHTLY_SUPERVISOR_EXIT_WAITERS.load(Ordering::Acquire);
        loop {
            if observed >= NIGHTLY_SUPERVISOR_EXIT_WAITER_CAPACITY {
                return Err("nightly supervisor exit waiter capacity is exhausted".to_owned());
            }
            match NIGHTLY_SUPERVISOR_EXIT_WAITERS.compare_exchange_weak(
                observed,
                observed.saturating_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(Self),
                Err(actual) => observed = actual,
            }
        }
    }
}

#[cfg(unix)]
impl Drop for ExternalSupervisorExitPermit {
    fn drop(&mut self) {
        NIGHTLY_SUPERVISOR_EXIT_WAITERS.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(unix)]
struct ExternalSupervisorExitReceipt {
    pid: u32,
    terminal: mpsc::Receiver<Result<std::process::ExitStatus, String>>,
}

#[cfg(unix)]
enum ExternalSupervisorExitState {
    Exited(std::process::ExitStatus),
    DeadlineExpired,
    Failed(String),
}

#[cfg(unix)]
impl ExternalSupervisorExitWaiter {
    fn prepare() -> Result<Self, String> {
        let permit = ExternalSupervisorExitPermit::acquire()?;
        let (child, child_receiver) = mpsc::sync_channel::<std::process::Child>(1);
        let (terminal_sender, terminal) = mpsc::sync_channel(1);
        let waiter = std::thread::Builder::new()
            .name("hell-nightly-supervisor-exit".to_owned())
            .spawn(move || {
                let Ok(mut child) = child_receiver.recv() else {
                    return;
                };
                let result = child
                    .wait()
                    .map_err(|error| format!("cannot reap nightly supervisor: {error}"));
                drop(terminal_sender.send(result));
                drop(permit);
            })
            .map_err(|error| format!("cannot start nightly supervisor exit waiter: {error}"))?;
        drop(waiter);
        Ok(Self { child, terminal })
    }

    fn transfer(
        self,
        child: std::process::Child,
    ) -> Result<ExternalSupervisorExitReceipt, (String, std::process::Child)> {
        let pid = child.id();
        self.child.send(child).map_err(|error| {
            (
                "nightly supervisor exit waiter disconnected before ownership transfer".to_owned(),
                error.0,
            )
        })?;
        Ok(ExternalSupervisorExitReceipt {
            pid,
            terminal: self.terminal,
        })
    }
}

#[cfg(unix)]
impl ExternalSupervisorExitReceipt {
    fn wait_until(&self, deadline: Instant) -> ExternalSupervisorExitState {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return match self.terminal.try_recv() {
                Ok(Ok(status)) => ExternalSupervisorExitState::Exited(status),
                Ok(Err(error)) => ExternalSupervisorExitState::Failed(error),
                Err(mpsc::TryRecvError::Empty) => ExternalSupervisorExitState::DeadlineExpired,
                Err(mpsc::TryRecvError::Disconnected) => ExternalSupervisorExitState::Failed(
                    "nightly supervisor exit waiter disconnected without a receipt".to_owned(),
                ),
            };
        }
        match self.terminal.recv_timeout(remaining) {
            Ok(Ok(status)) => ExternalSupervisorExitState::Exited(status),
            Ok(Err(error)) => ExternalSupervisorExitState::Failed(error),
            Err(mpsc::RecvTimeoutError::Timeout) => ExternalSupervisorExitState::DeadlineExpired,
            Err(mpsc::RecvTimeoutError::Disconnected) => ExternalSupervisorExitState::Failed(
                "nightly supervisor exit waiter disconnected without a receipt".to_owned(),
            ),
        }
    }
}

#[cfg(any(unix, windows))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExternalSupervisorMessage {
    Ready = 1,
    Go = 2,
    Started = 3,
    Budget = 4,
    Terminal = 5,
    Progress = 6,
}

#[cfg(any(unix, windows))]
impl ExternalSupervisorMessage {
    fn from_byte(value: u8) -> Result<Self, String> {
        match value {
            1 => Ok(Self::Ready),
            2 => Ok(Self::Go),
            3 => Ok(Self::Started),
            4 => Ok(Self::Budget),
            5 => Ok(Self::Terminal),
            6 => Ok(Self::Progress),
            _ => Err("nightly supervisor sent an unknown message".to_owned()),
        }
    }
}

impl SupervisionEnvelope {
    fn within(
        started: Instant,
        total: Duration,
        cleanup_reserve: Duration,
        report_reserve: Duration,
        outer_deadline: Instant,
    ) -> Result<Self, String> {
        if cleanup_reserve.is_zero() || cleanup_reserve >= total {
            return Err(
                "supervised cleanup reserve must be nonzero and smaller than its total envelope"
                    .to_owned(),
            );
        }
        if report_reserve.is_zero() || report_reserve >= cleanup_reserve {
            return Err(
                "supervised report reserve must be nonzero and smaller than its cleanup reserve"
                    .to_owned(),
            );
        }
        let report_completion_deadline = started
            .checked_add(total)
            .ok_or_else(|| "supervised completion deadline overflowed".to_owned())?
            .min(outer_deadline);
        let execution_deadline = report_completion_deadline
            .checked_sub(cleanup_reserve)
            .ok_or_else(|| "supervised execution deadline underflowed".to_owned())?;
        let child_completion_deadline = report_completion_deadline
            .checked_sub(report_reserve)
            .ok_or_else(|| "supervised child completion deadline underflowed".to_owned())?;
        if execution_deadline <= started
            || execution_deadline >= child_completion_deadline
            || child_completion_deadline >= report_completion_deadline
        {
            return Err(
                "supervised execution/completion envelope has no cleanup reserve".to_owned(),
            );
        }
        Ok(Self {
            execution: execution_deadline,
            child_completion_deadline,
            report_completion_deadline,
        })
    }
}

fn terminal_receipt_deadline(
    child_completion_deadline: Instant,
    report_completion_deadline: Instant,
) -> Instant {
    report_completion_deadline
        .checked_sub(TERMINAL_PERSISTENCE_RESERVE.saturating_mul(2))
        .unwrap_or(child_completion_deadline)
        .max(child_completion_deadline)
        .min(report_completion_deadline)
}

fn cleanup_observation_deadline(
    terminal_deadline: Instant,
    report_completion_deadline: Instant,
) -> Instant {
    report_completion_deadline
        .checked_sub(REPORT_WRITE_RESERVE)
        .unwrap_or(terminal_deadline)
        .max(terminal_deadline)
        .min(report_completion_deadline)
}

struct PortabilityWorkerPermit {
    id: u64,
}

struct PortabilityWorkerTracker {
    active: Mutex<usize>,
    idle: Condvar,
}

#[cfg(any(unix, windows))]
struct ExternalSupervisorAcceptTask {
    listener: TcpListener,
    result: mpsc::SyncSender<std::io::Result<TcpStream>>,
}

#[cfg(any(unix, windows))]
fn external_supervisor_accept_sender()
-> Result<&'static mpsc::SyncSender<ExternalSupervisorAcceptTask>, String> {
    static SENDER: OnceLock<Result<mpsc::SyncSender<ExternalSupervisorAcceptTask>, String>> =
        OnceLock::new();
    match SENDER.get_or_init(|| {
        let (sender, receiver) = mpsc::sync_channel::<ExternalSupervisorAcceptTask>(2);
        let receiver = Arc::new(Mutex::new(receiver));
        for index in 0..2 {
            let receiver = Arc::clone(&receiver);
            std::thread::Builder::new()
                .name(format!("hell-nightly-supervisor-accept-{index}"))
                .spawn(move || {
                    loop {
                        let task = receiver
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .recv();
                        let Ok(task) = task else {
                            break;
                        };
                        let result = task.listener.accept().map(|(stream, _)| stream);
                        let _ = task.result.send(result);
                    }
                })
                .map_err(|error| {
                    format!("cannot start nightly supervisor accept executor: {error}")
                })?;
        }
        Ok(sender)
    }) {
        Ok(sender) => Ok(sender),
        Err(error) => Err(error.clone()),
    }
}

#[cfg(any(unix, windows))]
fn submit_external_supervisor_accept(
    listener: TcpListener,
) -> Result<mpsc::Receiver<std::io::Result<TcpStream>>, String> {
    let (result, receiver) = mpsc::sync_channel(1);
    external_supervisor_accept_sender()?
        .try_send(ExternalSupervisorAcceptTask { listener, result })
        .map_err(|error| format!("nightly supervisor accept capacity is unavailable: {error}"))?;
    Ok(receiver)
}

impl PortabilityWorkerPermit {
    fn acquire() -> Result<Self, String> {
        const CAPACITY: usize = 4;
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);

        let mut active = portability_worker_tracker()
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *active >= CAPACITY {
            return Err("portability retained-worker capacity is exhausted".to_owned());
        }
        *active += 1;
        Ok(Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        })
    }
}

impl Drop for PortabilityWorkerPermit {
    fn drop(&mut self) {
        let tracker = portability_worker_tracker();
        let mut active = tracker
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *active = active.saturating_sub(1);
        tracker.idle.notify_all();
    }
}

fn portability_worker_tracker() -> &'static PortabilityWorkerTracker {
    static TRACKER: OnceLock<PortabilityWorkerTracker> = OnceLock::new();
    TRACKER.get_or_init(|| PortabilityWorkerTracker {
        active: Mutex::new(0),
        idle: Condvar::new(),
    })
}

impl PortabilityChildProgress {
    fn seeded(suite: &'static str, target: &str, case: &str, subphase: &str) -> Self {
        Self {
            suite,
            sequence: 1,
            target: Some(sanitize_portability_attribution(target)),
            case: Some(sanitize_portability_attribution(case)),
            case_state: Some(PortabilityCaseState::Active),
            subphase: Some(sanitize_portability_attribution(subphase)),
            observed_started: Some(Instant::now()),
            last_transition_elapsed: Some(Duration::ZERO),
            ..Self::default()
        }
    }

    fn suite(&self) -> &'static str {
        if self.suite.is_empty() {
            "portability"
        } else {
            self.suite
        }
    }

    fn observe(&mut self, phase: &str, stream: SupervisedOutputStream, bytes: &[u8]) {
        let observed = match stream {
            SupervisedOutputStream::Stdout => &mut self.stdout_observed,
            SupervisedOutputStream::Stderr => &mut self.stderr_observed,
        };
        *observed = observed.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        for byte in bytes {
            if *byte == b'\n' {
                let line = match stream {
                    SupervisedOutputStream::Stdout => std::mem::take(&mut self.stdout_line),
                    SupervisedOutputStream::Stderr => std::mem::take(&mut self.stderr_line),
                };
                let truncated = match stream {
                    SupervisedOutputStream::Stdout => {
                        std::mem::take(&mut self.stdout_line_truncated)
                    }
                    SupervisedOutputStream::Stderr => {
                        std::mem::take(&mut self.stderr_line_truncated)
                    }
                };
                if truncated {
                    self.case_line_truncated = true;
                } else if let Some(event) = parse_portability_child_attribution(&line) {
                    self.record_observed_attribution(phase, stream, event);
                }
            } else {
                let line = match stream {
                    SupervisedOutputStream::Stdout => &mut self.stdout_line,
                    SupervisedOutputStream::Stderr => &mut self.stderr_line,
                };
                if line.len() < PORTABILITY_ATTRIBUTION_LINE_LIMIT {
                    line.push(*byte);
                } else {
                    match stream {
                        SupervisedOutputStream::Stdout => self.stdout_line_truncated = true,
                        SupervisedOutputStream::Stderr => self.stderr_line_truncated = true,
                    }
                }
            }
        }
    }

    fn record_observed_attribution(
        &mut self,
        phase: &str,
        stream: SupervisedOutputStream,
        event: PortabilityAttributionEvent,
    ) {
        let failed = matches!(
            &event,
            PortabilityAttributionEvent::Case(_, PortabilityCaseState::Failed)
        );
        self.record_attribution(phase, event);
        if failed {
            let attribution = self.attribution();
            self.failed_case = attribution.case.map(|case| CausalFailedCase {
                sequence: attribution.sequence,
                transition_elapsed: attribution.transition_elapsed,
                target: attribution.target,
                case,
                stream: match stream {
                    SupervisedOutputStream::Stdout => "stdout",
                    SupervisedOutputStream::Stderr => "stderr",
                }
                .to_owned(),
            });
        }
    }

    fn record_attribution(&mut self, phase: &str, event: PortabilityAttributionEvent) {
        let started = *self.observed_started.get_or_insert_with(Instant::now);
        self.sequence = self.sequence.saturating_add(1);
        self.last_transition_elapsed =
            Some(canonical_external_supervisor_elapsed(started.elapsed()));
        match event {
            PortabilityAttributionEvent::Target(target) => {
                self.target = Some(target);
                self.case = None;
                self.case_state = None;
                self.subphase = None;
            }
            PortabilityAttributionEvent::Case(case, state) => {
                self.case = Some(case);
                self.case_state = Some(state);
            }
            PortabilityAttributionEvent::Subphase(subphase) => {
                self.subphase = Some(subphase);
            }
        }
        let snapshot = self.attribution();
        let mut stderr = std::io::stderr().lock();
        let _ = write!(
            stderr,
            "hell-ci-progress suite={} phase={phase} event=child-output sequence={}",
            self.suite(),
            snapshot.sequence
        );
        if let Some(target) = snapshot.target {
            let _ = write!(stderr, " target={target}");
        }
        if let Some(case) = snapshot.case {
            let _ = write!(stderr, " case={case}");
        }
        if let Some(state) = snapshot.case_state {
            let _ = write!(stderr, " caseState={state}");
        }
        if let Some(subphase) = snapshot.subphase {
            let _ = write!(stderr, " subphase={subphase}");
        }
        let _ = writeln!(stderr);
        let _ = stderr.flush();
    }

    fn record_terminal(&mut self, phase: &str, state: PortabilityCaseState) {
        let case = self.case.clone().unwrap_or_else(|| phase.to_owned());
        self.record_attribution(phase, PortabilityAttributionEvent::Case(case, state));
        self.subphase = Some("terminal".to_owned());
    }

    fn retain_partial_line_evidence(&self, report: &mut Report, phase: &str) {
        report.evidence(
            format!("{}-partial-output", self.suite()),
            JsonValue::Object(BTreeMap::from([
                ("phase".to_owned(), JsonValue::String(phase.to_owned())),
                (
                    "stdoutPartial".to_owned(),
                    JsonValue::String(sanitize_portability_attribution(&String::from_utf8_lossy(
                        &self.stdout_line,
                    ))),
                ),
                (
                    "stderrPartial".to_owned(),
                    JsonValue::String(sanitize_portability_attribution(&String::from_utf8_lossy(
                        &self.stderr_line,
                    ))),
                ),
                (
                    "stdoutPartialTruncated".to_owned(),
                    JsonValue::Bool(self.stdout_line_truncated),
                ),
                (
                    "stderrPartialTruncated".to_owned(),
                    JsonValue::Bool(self.stderr_line_truncated),
                ),
            ])),
        );
    }

    fn attribution(&self) -> ActivePhaseAttribution {
        ActivePhaseAttribution {
            sequence: self.sequence,
            transition_elapsed: self.last_transition_elapsed,
            target: self.target.clone(),
            case: self.case.clone(),
            case_state: self.case_state.map(|state| state.as_str().to_owned()),
            subphase: self.subphase.clone(),
        }
    }

    fn apply_external_attribution(
        &mut self,
        attribution: ActivePhaseAttribution,
    ) -> Result<(), String> {
        if attribution.sequence < self.sequence {
            return Err("nightly supervisor progress sequence moved backward".to_owned());
        }
        self.sequence = attribution.sequence;
        self.last_transition_elapsed = attribution
            .transition_elapsed
            .map(canonical_external_supervisor_elapsed);
        self.target = attribution.target;
        self.case = attribution.case;
        self.case_state = match attribution.case_state.as_deref() {
            None => None,
            Some("active") => Some(PortabilityCaseState::Active),
            Some("still-running") => Some(PortabilityCaseState::StillRunning),
            Some("completed") => Some(PortabilityCaseState::Completed),
            Some("passed") => Some(PortabilityCaseState::Passed),
            Some("ignored") => Some(PortabilityCaseState::Ignored),
            Some("failed") => Some(PortabilityCaseState::Failed),
            Some("timed-out-cleaned") => Some(PortabilityCaseState::TimedOutCleaned),
            Some("launch-failed") => Some(PortabilityCaseState::LaunchFailed),
            Some("panicked") => Some(PortabilityCaseState::Panicked),
            Some("retained") => Some(PortabilityCaseState::Retained),
            Some("receipt-disconnected") => Some(PortabilityCaseState::ReceiptDisconnected),
            Some(_) => return Err("nightly supervisor progress case state is unknown".to_owned()),
        };
        self.subphase = attribution.subphase;
        Ok(())
    }

    fn emit_summary(&self, phase: &str, loss: hell_testkit::SupervisedProgressLoss) {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "{}", self.summary(phase, loss));
        let _ = stderr.flush();
    }

    fn summary(&self, phase: &str, loss: hell_testkit::SupervisedProgressLoss) -> String {
        format!(
            "hell-ci-progress suite={} phase={phase} event=child-relay-summary stdoutObservedBytes={} stdoutRelayedBytes={} stderrObservedBytes={} stderrRelayedBytes={} droppedChunks={} droppedBytes={}",
            self.suite(),
            self.stdout_observed,
            self.stdout_relayed,
            self.stderr_observed,
            self.stderr_relayed,
            loss.chunks,
            loss.bytes,
        )
    }
}

fn parse_portability_child_attribution(bytes: &[u8]) -> Option<PortabilityAttributionEvent> {
    let line = String::from_utf8_lossy(bytes);
    let trimmed = line.trim();
    trimmed
        .strip_prefix("hell-progress-target=")
        .map(|target| PortabilityAttributionEvent::Target(sanitize_portability_attribution(target)))
        .or_else(|| {
            trimmed.strip_prefix("hell-progress-case=").map(|case| {
                PortabilityAttributionEvent::Case(
                    sanitize_portability_attribution(case),
                    PortabilityCaseState::Active,
                )
            })
        })
        .or_else(|| {
            trimmed
                .strip_prefix("hell-progress-subphase=")
                .map(|subphase| {
                    PortabilityAttributionEvent::Subphase(sanitize_portability_attribution(
                        subphase,
                    ))
                })
        })
        .or_else(|| {
            trimmed.strip_prefix("Running ").map(|target| {
                PortabilityAttributionEvent::Target(sanitize_portability_attribution(target))
            })
        })
        .or_else(|| {
            trimmed.strip_prefix("test ").and_then(|case| {
                case.split_once(" has been running for over ")
                    .map(|(name, _)| {
                        PortabilityAttributionEvent::Case(
                            sanitize_portability_attribution(name),
                            PortabilityCaseState::StillRunning,
                        )
                    })
                    .or_else(|| {
                        case.split_once(" ... ").and_then(|(name, outcome)| {
                            let state = if outcome == "ok" {
                                Some(PortabilityCaseState::Passed)
                            } else if outcome == "FAILED" {
                                Some(PortabilityCaseState::Failed)
                            } else if outcome == "ignored" || outcome.starts_with("ignored, ") {
                                Some(PortabilityCaseState::Ignored)
                            } else {
                                None
                            }?;
                            Some(PortabilityAttributionEvent::Case(
                                sanitize_portability_attribution(name),
                                state,
                            ))
                        })
                    })
            })
        })
}

fn sanitize_portability_attribution(value: &str) -> String {
    let sanitized = value
        .chars()
        .take(PORTABILITY_ATTRIBUTION_FIELD_LIMIT)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':' | '/')
            {
                character
            } else {
                '?'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "unknown".to_owned()
    } else {
        sanitized
    }
}

/// Verifies the exact subordinate portability deadline policy.
///
/// # Errors
///
/// Returns an error if child work can consume the suite cleanup/report reserve.
#[doc(hidden)]
pub fn verify_portability_timeout_policy_for_integration() -> Result<(), String> {
    verify_portability_partition_policy()?;
    verify_portability_checkpoint_lifecycle()?;
    verify_portability_attribution_contract()?;
    verify_portability_worker_capacity()
}

fn verify_portability_partition_policy() -> Result<(), String> {
    if PORTABILITY_SUITE_TIMEOUT != Duration::from_mins(40)
        || PORTABILITY_CLEANUP_RESERVE != Duration::from_mins(5)
        || PORTABILITY_PROGRESS_INTERVAL != Duration::from_secs(30)
        || PORTABILITY_SUITE_TIMEOUT.checked_sub(PORTABILITY_CLEANUP_RESERVE)
            != Some(Duration::from_mins(35))
        || PORTABILITY_PROGRESS_INTERVAL >= PORTABILITY_CLEANUP_RESERVE
    {
        return Err("portability deadline policy no longer preserves its exact reserve".to_owned());
    }
    let workspace_arguments = portable_workspace_test_arguments();
    #[cfg(target_os = "macos")]
    if !workspace_arguments.ends_with(&["--", "--skip", MACOS_STAGED_NATIVE_TOOLCHAIN_CASE])
        || workspace_arguments
            .iter()
            .filter(|argument| **argument == MACOS_STAGED_NATIVE_TOOLCHAIN_CASE)
            .count()
            != 1
    {
        return Err(
            "macOS staged-toolchain partition does not exclude its exact broad test once"
                .to_owned(),
        );
    }
    #[cfg(not(target_os = "macos"))]
    if workspace_arguments.contains(&"--skip") {
        return Err("non-macOS portability coverage unexpectedly excludes a test".to_owned());
    }
    #[cfg(target_os = "macos")]
    verify_macos_staged_native_partition_for_integration()?;
    Ok(())
}

fn verify_portability_checkpoint_lifecycle() -> Result<(), String> {
    let checkpoint = std::env::temp_dir().join(format!(
        "hell-portability-timeout-policy-{}.json",
        std::process::id()
    ));
    if checkpoint.exists() {
        return Err("portability checkpoint fixture already exists".to_owned());
    }
    let mut report = Report::new("portability-timeout-policy-verifier");
    report
        .attach_checkpoint(checkpoint.clone())
        .and_then(|()| {
            report.checkpoint_phase_attribution(
                "portable-workspace-tests",
                Duration::from_secs(1),
                Duration::from_secs(35 * 60 - 1),
                ActivePhaseAttribution {
                    sequence: 3,
                    transition_elapsed: Some(Duration::from_millis(750)),
                    target: Some("release_environment".to_owned()),
                    case: Some("staged_native_toolchain".to_owned()),
                    case_state: Some("still-running".to_owned()),
                    subphase: Some("provenance-postflight".to_owned()),
                },
            )
        })
        .map_err(|error| format!("cannot write running portability checkpoint: {error}"))?;
    let running = fs::read_to_string(&checkpoint)
        .map_err(|error| format!("cannot read running portability checkpoint: {error}"))?;
    if !running.contains("\"lifecycle\": \"running\"")
        || !running.contains("\"passed\": false")
        || !running.contains("\"name\": \"portable-workspace-tests\"")
        || !running.contains("\"sequence\": 3")
        || !running.contains("\"transitionElapsedMillis\": 750")
        || !running.contains("\"caseState\": \"still-running\"")
        || !running.contains("\"subphase\": \"provenance-postflight\"")
    {
        return Err("running portability checkpoint omits exact lifecycle evidence".to_owned());
    }
    #[cfg(target_os = "macos")]
    {
        let now = Instant::now();
        let deadline = now
            .checked_add(Duration::from_mins(1))
            .ok_or_else(|| "macOS partition checkpoint deadline overflowed".to_owned())?;
        checkpoint_macos_staged_native_transition(
            &mut report,
            now,
            deadline,
            4,
            Some(Duration::from_secs(2)),
            Some("provenance-postflight"),
        )?;
        let partition = fs::read_to_string(&checkpoint)
            .map_err(|error| format!("cannot read macOS partition checkpoint: {error}"))?;
        if !partition.contains("\"name\": \"macos-staged-native-toolchain\"")
            || !partition.contains(MACOS_STAGED_NATIVE_TOOLCHAIN_CASE)
            || !partition.contains("\"sequence\": 4")
            || !partition.contains("\"transitionElapsedMillis\": 2000")
            || !partition.contains("\"subphase\": \"provenance-postflight\"")
        {
            return Err(
                "macOS staged-toolchain transition is absent from the durable checkpoint"
                    .to_owned(),
            );
        }
    }
    report.complete();
    report
        .write(&checkpoint)
        .map_err(|error| format!("cannot write terminal portability checkpoint: {error}"))?;
    let terminal = fs::read_to_string(&checkpoint)
        .map_err(|error| format!("cannot read terminal portability checkpoint: {error}"))?;
    if !terminal.contains("\"lifecycle\": \"complete\"")
        || !terminal.contains("\"passed\": true")
        || terminal.contains("\"activePhase\"")
    {
        return Err("terminal portability checkpoint retains nonterminal state".to_owned());
    }
    fs::remove_file(checkpoint)
        .map_err(|error| format!("cannot remove portability checkpoint fixture: {error}"))?;
    Ok(())
}

fn verify_portability_attribution_contract() -> Result<(), String> {
    let launched = std::cell::Cell::new(false);
    let expired = Instant::now();
    if run_before_portability_deadline(expired, "expired-fixture", || {
        launched.set(true);
        Ok(())
    })
    .is_ok()
        || launched.get()
    {
        return Err("expired portability phase launched late work".to_owned());
    }
    if sanitize_portability_attribution("target with\ncontrol") != "target?with?control" {
        return Err("portability attribution is not bounded and sanitized".to_owned());
    }
    let mut attributed = PortabilityChildProgress::default();
    for chunk in [
        b"hell-progress-target=release_environment\n".as_slice(),
        b"test staged_native_".as_slice(),
        b"toolchain has been running for over 60 seconds\n".as_slice(),
        b"hell-progress-subphase=provenance-postflight\n".as_slice(),
    ] {
        attributed.observe("verifier", SupervisedOutputStream::Stdout, chunk);
    }
    let attribution = attributed.attribution();
    let acknowledged_transition = attribution.transition_elapsed;
    if attribution.sequence != 3
        || attribution.target.as_deref() != Some("release_environment")
        || attribution.case.as_deref() != Some("staged_native_toolchain")
        || attribution.case_state.as_deref() != Some("still-running")
        || attribution.subphase.as_deref() != Some("provenance-postflight")
        || attributed.attribution().transition_elapsed != acknowledged_transition
    {
        return Err("fragmented portability attribution lost typed active state".to_owned());
    }
    let relay = PortabilityChildProgress {
        stdout_observed: 300,
        stdout_relayed: 200,
        stderr_observed: 500,
        stderr_relayed: 400,
        ..PortabilityChildProgress::default()
    };
    let summary = relay.summary(
        "verifier",
        hell_testkit::SupervisedProgressLoss {
            chunks: 3,
            bytes: 100,
        },
    );
    if !summary.contains("stdoutObservedBytes=300 stdoutRelayedBytes=200")
        || !summary.contains("stderrObservedBytes=500 stderrRelayedBytes=400")
        || !summary.contains("droppedChunks=3 droppedBytes=100")
    {
        return Err("portability relay loss summary omitted typed totals".to_owned());
    }
    let mut phase_report = Report::new("portability-attribution-verifier");
    retain_portability_terminal_attribution(
        &mut phase_report,
        "portability",
        "no-output-phase",
        &PortabilityChildProgress::default(),
        hell_testkit::SupervisedProgressLoss {
            chunks: 0,
            bytes: 0,
        },
        Some(11),
        "completed",
    );
    retain_portability_terminal_attribution(
        &mut phase_report,
        "portability",
        "attributed-phase",
        &attributed,
        hell_testkit::SupervisedProgressLoss {
            chunks: 0,
            bytes: 0,
        },
        Some(12),
        "retained",
    );
    let phase_json = phase_report.to_json();
    if !phase_json.contains("\"phase\":\"no-output-phase\"")
        || !phase_json.contains("\"phase\":\"attributed-phase\"")
    {
        return Err("terminal attribution lost its enclosing phase provenance".to_owned());
    }
    Ok(())
}

fn verify_portability_worker_capacity() -> Result<(), String> {
    let permits = (0..4)
        .map(|_| PortabilityWorkerPermit::acquire())
        .collect::<Result<Vec<_>, _>>()?;
    if PortabilityWorkerPermit::acquire().is_ok() {
        return Err("portability worker launched without retained capacity".to_owned());
    }
    drop(permits);
    drop(PortabilityWorkerPermit::acquire()?);
    if *portability_worker_tracker()
        .active
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        != 0
    {
        return Err("portability retained-worker tracker did not reach idle".to_owned());
    }
    let (held_progress, _held_receiver) = SupervisedProgressObserver::bounded(1);
    let _connected_progress = held_progress.clone();
    let (terminal_sender, terminal_receiver) = mpsc::sync_channel(1);
    terminal_sender
        .send(())
        .map_err(|error| format!("cannot send portability terminal fixture: {error}"))?;
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(1))
        .ok_or_else(|| "portability terminal fixture deadline overflowed".to_owned())?;
    if !matches!(
        receive_portability_terminal(&terminal_receiver, deadline),
        PortabilityTerminal::Complete(())
    ) {
        return Err("connected progress queue masked typed worker completion".to_owned());
    }
    let (progress_sender, progress_receiver) =
        mpsc::sync_channel(PORTABILITY_PROGRESS_QUEUE_CAPACITY);
    for _ in 0..PORTABILITY_PROGRESS_QUEUE_CAPACITY {
        progress_sender
            .try_send(hell_testkit::SupervisedProgressChunk {
                stream: SupervisedOutputStream::Stdout,
                bytes: Vec::new(),
            })
            .map_err(|error| format!("cannot fill progress starvation fixture: {error}"))?;
    }
    let mut progress_state = PortabilityChildProgress::default();
    drain_portability_progress(&progress_receiver, &mut progress_state, "verifier");
    if progress_receiver.try_recv().is_ok() {
        return Err("bounded progress drain did not yield after its exact batch".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
const PORTABILITY_SUPERVISION_FIXTURE_TIMEOUT: Duration = Duration::from_millis(400);
#[cfg(unix)]
const PORTABILITY_SUPERVISION_COMPLETION_TIMEOUT: Duration = Duration::from_secs(5);

/// Exercises the real absolute-deadline and process-tree supervision seam.
///
/// # Errors
///
/// Returns an error unless child progress is observed before completion and the timed-out
/// fixture has no live descendant before the shared completion deadline.
#[cfg(unix)]
#[doc(hidden)]
pub fn verify_portability_supervision_for_integration() -> Result<(), String> {
    static SEQUENCE: AtomicU64 = AtomicU64::new(10_000);

    hell_testkit::verify_supervised_progress_loss_for_integration()
        .map_err(|error| format!("deterministic progress loss verification failed: {error}"))?;
    let first = SEQUENCE.fetch_add(64, Ordering::Relaxed);
    let fixture = NightlyFixtureRoot::create(first)?;
    let primary = (|| {
        let receipt = fixture.path.join("descendant.pid");
        let executable = std::env::current_exe()
            .map_err(|error| format!("cannot resolve portability fixture executable: {error}"))?;
        let started = Instant::now();
        let execution_deadline = started
            .checked_add(PORTABILITY_SUPERVISION_FIXTURE_TIMEOUT)
            .ok_or_else(|| "portability fixture execution deadline overflowed".to_owned())?;
        let completion_deadline = started
            .checked_add(PORTABILITY_SUPERVISION_COMPLETION_TIMEOUT)
            .ok_or_else(|| "portability fixture completion deadline overflowed".to_owned())?;
        let (progress, progress_receiver) = SupervisedProgressObserver::bounded(16);
        let result = CommandSpec::new(&executable, PORTABILITY_SUPERVISION_FIXTURE_TIMEOUT)
            .argument("__portability-supervision-fixture")
            .argument(receipt.as_os_str())
            .run_until(execution_deadline, completion_deadline, progress)
            .map_err(|error| format!("portability supervision fixture cannot run: {error}"))?;
        if !result.timed_out {
            return Err(
                "portability fixture did not terminate inside its absolute reserve".to_owned(),
            );
        }
        let observed = progress_receiver
            .try_iter()
            .flat_map(|chunk| chunk.bytes)
            .take(PORTABILITY_ATTRIBUTION_LINE_LIMIT)
            .collect::<Vec<_>>();
        if !contains_bytes(&observed, b"hell-progress-target=hell-testkit-lib\n")
            || !contains_bytes(&observed, b"hell-progress-case=blocked-case\n")
        {
            return Err(
                "portability fixture completed before attributed child progress".to_owned(),
            );
        }
        let descendant = fs::read_to_string(&receipt)
            .map_err(|error| format!("cannot read portability descendant receipt: {error}"))?;
        let descendant = descendant
            .strip_suffix('\n')
            .ok_or_else(|| "portability descendant receipt lacks its delimiter".to_owned())?;
        if descendant.is_empty() || !descendant.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("portability descendant receipt is not one decimal PID".to_owned());
        }
        let now = Instant::now();
        let probe_deadline = now
            .checked_add(Duration::from_millis(250))
            .unwrap_or(completion_deadline)
            .min(completion_deadline);
        let (discard_progress, _discard_receiver) = SupervisedProgressObserver::bounded(1);
        let probe = CommandSpec::new("/bin/ps", Duration::from_millis(250))
            .arguments(["-p", descendant, "-o", "pid=,ppid=,stat="])
            .run_until(probe_deadline, completion_deadline, discard_progress)
            .map_err(|error| format!("cannot probe portability descendant: {error}"))?;
        hell_testkit::wait_for_posix_uid_process_quiescence(
            probe_deadline,
            hell_testkit::PosixUidQuiescenceGoal::NoLiveProcesses,
            || {
                hell_testkit::parse_posix_uid_process_snapshot(
                    probe.status.code(),
                    &probe.stdout,
                    &probe.stderr,
                )
            },
            || {
                Err(std::io::Error::other(
                    "portability descendant remained live after supervised tree termination",
                ))
            },
            || {
                Err(std::io::Error::other(
                    "portability verifier must not signal after typed cleanup",
                ))
            },
        )
        .map_err(|error| format!("portability descendant did not reach no-live state: {error}"))?;
        Ok(())
    })();
    compose_fixture_cleanup(primary, fixture.close())
}

#[cfg(unix)]
fn compose_fixture_cleanup(
    primary: Result<(), String>,
    cleanup: Result<(), String>,
) -> Result<(), String> {
    match (primary, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(format!(
            "fixture failed: {primary}; cleanup also failed: {cleanup}"
        )),
    }
}

#[cfg(unix)]
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|candidate| candidate == needle)
}

#[cfg(unix)]
pub(crate) fn run_portability_supervision_fixture(arguments: &[std::ffi::OsString]) -> ! {
    let [receipt] = arguments else {
        panic!("portability supervision fixture requires one receipt path");
    };
    let executable = std::env::current_exe().unwrap_or_else(|error| {
        panic!("cannot resolve portability descendant executable: {error}")
    });
    let mut descendant = NativeProcessSpec::new(executable)
        .argument("__portability-supervision-descendant")
        .spawn()
        .unwrap_or_else(|error| panic!("cannot spawn portability descendant: {error}"));
    fs::write(receipt, format!("{}\n", descendant.id()))
        .unwrap_or_else(|error| panic!("cannot write portability descendant receipt: {error}"));
    println!("hell-progress-target=hell-testkit-lib");
    println!("hell-progress-case=blocked-case");
    std::io::stderr()
        .write_all(b"hell-progress-subphase=blocked-without-newline")
        .and_then(|()| std::io::stderr().flush())
        .unwrap_or_else(|error| panic!("cannot flush portability partial progress: {error}"));
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(b"hell-progress-subphase=blocked\n")
        .and_then(|()| stdout.flush())
        .unwrap_or_else(|error| panic!("cannot flush portability fixture progress: {error}"));
    let status = descendant
        .wait()
        .unwrap_or_else(|error| panic!("cannot wait for portability descendant: {error}"));
    panic!("portability descendant exited before supervision: {status}");
}

#[cfg(unix)]
pub(crate) fn run_portability_supervision_descendant() -> ! {
    loop {
        std::thread::park();
    }
}

pub(crate) fn verify_nightly_workspace_partition_for_integration() -> Result<(), String> {
    let workspace_arguments = nightly_workspace_test_arguments();
    verify_nightly_partition_arguments(&workspace_arguments)?;
    verify_nightly_partition_envelopes()
}

fn verify_nightly_partition_arguments(workspace_arguments: &[&str]) -> Result<(), String> {
    if NIGHTLY_WORKSPACE_TEST_TIMEOUT.checked_add(NIGHTLY_CORE_DATA_TEST_TIMEOUT)
        != Some(WORKSPACE_TEST_TIMEOUT)
        || NIGHTLY_COMMAND_CLEANUP_RESERVE != Duration::from_mins(5)
        || NIGHTLY_WORKSPACE_TEST_TIMEOUT.checked_sub(NIGHTLY_COMMAND_CLEANUP_RESERVE)
            != Some(Duration::from_mins(55))
        || NIGHTLY_CORE_DATA_TEST_TIMEOUT.checked_sub(NIGHTLY_COMMAND_CLEANUP_RESERVE)
            != Some(Duration::from_mins(25))
        || NIGHTLY_CORE_DATA_TEST
            != "core_data_obligations_round_trip_through_the_production_bundle_gate"
        || NIGHTLY_CORE_DATA_TEST_TARGET != "core_data_production_bundle"
    {
        return Err("nightly workspace partition differs from its exact total deadline".to_owned());
    }
    if workspace_arguments
        .iter()
        .filter(|argument| **argument == NIGHTLY_CORE_DATA_TEST)
        .count()
        != 1
    {
        return Err("nightly broad workspace does not exclude core data exactly once".to_owned());
    }
    #[cfg(target_os = "macos")]
    {
        let dedicated = nightly_macos_staged_native_toolchain_arguments();
        if NIGHTLY_MACOS_BROAD_WORKSPACE_TIMEOUT
            .checked_add(NIGHTLY_MACOS_STAGED_NATIVE_TOOLCHAIN_TIMEOUT)
            != Some(NIGHTLY_WORKSPACE_TEST_TIMEOUT)
            || workspace_arguments
                .iter()
                .filter(|argument| **argument == MACOS_STAGED_NATIVE_TOOLCHAIN_CASE)
                .count()
                != 1
            || dedicated
                .iter()
                .filter(|argument| **argument == MACOS_STAGED_NATIVE_TOOLCHAIN_CASE)
                .count()
                != 1
            || !dedicated.ends_with(&["--", "--exact", "--nocapture"])
        {
            return Err(
                "nightly macOS staged-native case is not partitioned exactly once".to_owned(),
            );
        }
    }
    Ok(())
}

fn verify_nightly_partition_envelopes() -> Result<(), String> {
    let now = Instant::now();
    let outer = now
        .checked_add(WORKSPACE_TEST_TIMEOUT)
        .ok_or_else(|| "nightly verifier outer deadline overflowed".to_owned())?;
    let workspace = SupervisionEnvelope::within(
        now,
        NIGHTLY_WORKSPACE_TEST_TIMEOUT,
        NIGHTLY_COMMAND_CLEANUP_RESERVE,
        NIGHTLY_REPORT_RESERVE,
        outer,
    )?;
    let core_started = now
        .checked_add(NIGHTLY_WORKSPACE_TEST_TIMEOUT)
        .ok_or_else(|| "nightly verifier core start overflowed".to_owned())?;
    let core = SupervisionEnvelope::within(
        core_started,
        NIGHTLY_CORE_DATA_TEST_TIMEOUT,
        NIGHTLY_COMMAND_CLEANUP_RESERVE,
        NIGHTLY_REPORT_RESERVE,
        outer,
    )?;
    #[cfg(target_os = "macos")]
    let macos_broad = SupervisionEnvelope::within(
        now,
        NIGHTLY_MACOS_BROAD_WORKSPACE_TIMEOUT,
        NIGHTLY_COMMAND_CLEANUP_RESERVE,
        NIGHTLY_REPORT_RESERVE,
        workspace.report_completion_deadline,
    )?;
    #[cfg(target_os = "macos")]
    let macos_staged_started = now
        .checked_add(NIGHTLY_MACOS_BROAD_WORKSPACE_TIMEOUT)
        .ok_or_else(|| "nightly verifier macOS staged start overflowed".to_owned())?;
    #[cfg(target_os = "macos")]
    let macos_staged = SupervisionEnvelope::within(
        macos_staged_started,
        NIGHTLY_MACOS_STAGED_NATIVE_TOOLCHAIN_TIMEOUT,
        NIGHTLY_COMMAND_CLEANUP_RESERVE,
        NIGHTLY_REPORT_RESERVE,
        workspace.report_completion_deadline,
    )?;
    #[cfg(target_os = "macos")]
    let macos_staged_invalid = macos_broad.report_completion_deadline != macos_staged_started
        || macos_staged.report_completion_deadline != workspace.report_completion_deadline
        || macos_broad.execution >= macos_broad.child_completion_deadline
        || macos_broad.child_completion_deadline >= macos_broad.report_completion_deadline
        || macos_staged.execution >= macos_staged.child_completion_deadline
        || macos_staged.child_completion_deadline >= macos_staged.report_completion_deadline;
    #[cfg(not(target_os = "macos"))]
    let macos_staged_invalid = false;
    if workspace.report_completion_deadline != core_started
        || workspace.execution
            != workspace
                .report_completion_deadline
                .checked_sub(NIGHTLY_COMMAND_CLEANUP_RESERVE)
                .ok_or_else(|| "nightly verifier workspace reserve underflowed".to_owned())?
        || workspace.child_completion_deadline
            != workspace
                .report_completion_deadline
                .checked_sub(NIGHTLY_REPORT_RESERVE)
                .ok_or_else(|| "nightly verifier workspace report reserve underflowed".to_owned())?
        || core.report_completion_deadline != outer
        || core.execution
            != outer
                .checked_sub(NIGHTLY_COMMAND_CLEANUP_RESERVE)
                .ok_or_else(|| "nightly verifier core reserve underflowed".to_owned())?
        || core.child_completion_deadline
            != outer
                .checked_sub(NIGHTLY_REPORT_RESERVE)
                .ok_or_else(|| "nightly verifier core report reserve underflowed".to_owned())?
        || workspace.execution >= workspace.child_completion_deadline
        || workspace.child_completion_deadline >= workspace.report_completion_deadline
        || core.execution >= core.child_completion_deadline
        || core.child_completion_deadline >= core.report_completion_deadline
        || macos_staged_invalid
        || SupervisionEnvelope::within(
            now,
            NIGHTLY_WORKSPACE_TEST_TIMEOUT,
            Duration::ZERO,
            NIGHTLY_REPORT_RESERVE,
            outer,
        )
        .is_ok()
    {
        return Err("nightly workspace admits a zero cleanup reserve".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn verify_nightly_failed_case_attribution_for_integration() -> Result<(), String> {
    let started = Instant::now();
    let outer = started
        .checked_add(Duration::from_secs(20))
        .ok_or_else(|| "nightly failed-case verifier deadline overflowed".to_owned())?;
    let envelope = SupervisionEnvelope::within(
        started,
        Duration::from_secs(20),
        Duration::from_secs(5),
        Duration::from_secs(2),
        outer,
    )?;
    verify_nightly_failed_case_terminal(started, envelope)?;
    verify_nightly_missing_case_attribution(envelope)
}

#[cfg(unix)]
fn verify_nightly_failed_case_terminal(
    started: Instant,
    envelope: SupervisionEnvelope,
) -> Result<(), String> {
    let executable = fs::canonicalize(
        std::env::current_exe()
            .map_err(|error| format!("cannot locate failed-case fixture child: {error}"))?,
    )
    .map_err(|error| format!("cannot canonicalize failed-case fixture child: {error}"))?;
    let spec = CommandSpec::new(
        executable,
        envelope.execution.saturating_duration_since(Instant::now()),
    )
    .argument("__nightly-failed-case-child");
    let (result, progress, loss) = execute_external_supervisor_command(
        spec,
        ExternalSupervisorPlan::NightlyWorkspace,
        "failed-case-attribution-fixture",
        envelope,
        |_| true,
    )?;
    let terminal = external_supervisor_terminal_from_result(
        result,
        &progress,
        loss,
        envelope.report_completion_deadline,
    );
    if terminal.execution.success || terminal.execution.timed_out || terminal.exit_code != Some(1) {
        return Err("nightly failed-case fixture did not produce bounded status 1".to_owned());
    }
    let failed = terminal
        .failed_case
        .as_ref()
        .ok_or_else(|| "nightly terminal omitted its causal failed case".to_owned())?;
    if failed.target.as_deref() != Some("failed-case-target")
        || failed.case != "causal_failure"
        || failed.stream != "stdout"
        || terminal.attribution.case.as_deref() != Some("later_success")
        || terminal.failed_case_unavailable.is_some()
        || !terminal
            .detail
            .contains("failed case: target=failed-case-target")
        || !terminal.detail.contains("case=causal_failure")
    {
        return Err("nightly causal failed-case receipt differs from its exact event".to_owned());
    }
    let request_sha256 = sha256_bytes(b"nightly-failed-case-request");
    let nonce = sha256_bytes(b"nightly-failed-case-nonce");
    let encoded = encode_external_supervisor_terminal(request_sha256, nonce, &terminal)?;
    let decoded = decode_external_supervisor_terminal(&encoded, request_sha256, nonce)?;
    let decoded_failed = decoded
        .failed_case
        .as_ref()
        .ok_or_else(|| "nightly durable terminal lost its causal failed case".to_owned())?;
    if decoded_failed.case != failed.case
        || decoded_failed.sequence != failed.sequence
        || decoded_failed.transition_elapsed != failed.transition_elapsed
        || decoded_failed.target != failed.target
        || decoded_failed.stream != failed.stream
    {
        return Err("nightly durable failed-case receipt changed during framing".to_owned());
    }
    let evidence = external_supervisor_terminal_evidence(
        ExternalSupervisorPlan::NightlyWorkspace,
        &decoded,
        request_sha256,
    );
    let mut report = Report::new("nightly-failed-case-attribution-verifier");
    report.evidence("nightly-failed-case-terminal", evidence);
    report.check(
        "nightly-workspace-tests",
        started.elapsed(),
        Err(decoded.detail),
    );
    let durable = report.to_json();
    if !durable.contains("\"failedCase\"")
        || !durable.contains("\"case\":\"causal_failure\"")
        || !durable.contains("\"stream\":\"stdout\"")
        || !durable.contains("\"target\":\"failed-case-target\"")
        || !durable.contains("\"transitionElapsedMillis\"")
        || !durable.contains("\"stdoutObservedBytes\"")
        || !durable.contains("\"stdoutSha256\"")
        || !durable.contains("\"cleanupTerminal\":true")
        || !durable.contains("failed case: target=failed-case-target")
    {
        return Err("nightly report omitted causal failed-case evidence".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn verify_nightly_missing_case_attribution(envelope: SupervisionEnvelope) -> Result<(), String> {
    let silent_spec = CommandSpec::new(
        "/usr/bin/false",
        envelope.execution.saturating_duration_since(Instant::now()),
    );
    let (silent_result, silent_progress, silent_loss) = execute_external_supervisor_command(
        silent_spec,
        ExternalSupervisorPlan::NightlyWorkspace,
        "silent-failure-attribution-fixture",
        envelope,
        |_| true,
    )?;
    let silent_terminal = external_supervisor_terminal_from_result(
        silent_result,
        &silent_progress,
        silent_loss,
        envelope.report_completion_deadline,
    );
    if silent_terminal.execution.success
        || silent_terminal.failed_case.is_some()
        || silent_terminal.failed_case_unavailable.as_deref() != Some("no-failed-case-observed")
        || !silent_terminal
            .detail
            .contains("failed case unavailable: no-failed-case-observed")
    {
        return Err("nightly silent status failure fabricated a failed case".to_owned());
    }
    let mut truncated = PortabilityChildProgress::seeded(
        "nightly",
        "truncated-target",
        "truncated-case",
        "fixture",
    );
    let mut line = b"test truncated_failure ... FAILED".to_vec();
    line.resize(PORTABILITY_ATTRIBUTION_LINE_LIMIT.saturating_add(1), b'x');
    line.push(b'\n');
    truncated.observe(
        "nightly-workspace-tests",
        SupervisedOutputStream::Stdout,
        &line,
    );
    if truncated.failed_case.is_some() || !truncated.case_line_truncated {
        return Err("truncated attribution line became authoritative".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn run_nightly_failed_case_child() {
    println!("hell-progress-target=failed-case-target");
    println!("test causal_failure ... FAILED");
    println!("test later_success ... ok");
}

#[cfg(unix)]
pub(crate) fn verify_nightly_attributed_supervision_for_integration() -> Result<(), String> {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const CANDIDATES: u64 = 64;

    hell_testkit::verify_supervised_progress_loss_for_integration()
        .map_err(|error| format!("deterministic progress loss verification failed: {error}"))?;
    let first = SEQUENCE.fetch_add(CANDIDATES + 1, Ordering::Relaxed);
    let collision = NightlyCollisionFixture::create(first)?;
    let fixture = match NightlyFixtureRoot::create(first) {
        Ok(fixture) => fixture,
        Err(primary) => {
            let (_, cleanup) = collision.finish();
            return match cleanup {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(format!("{primary}; cleanup also failed: {cleanup}")),
            };
        }
    };
    let receipt = fixture.path.join("descendant.pid");
    let checkpoint = fixture.path.join("report.json");
    let result = (|| {
        let executable = std::env::current_exe()
            .map_err(|error| format!("cannot resolve nightly fixture executable: {error}"))?;
        let started = Instant::now();
        let execution_deadline = started
            .checked_add(Duration::from_millis(400))
            .ok_or_else(|| "nightly fixture execution deadline overflowed".to_owned())?;
        let child_completion_deadline = started
            .checked_add(Duration::from_secs(4))
            .ok_or_else(|| "nightly fixture cleanup deadline overflowed".to_owned())?;
        let report_completion_deadline = started
            .checked_add(Duration::from_secs(6))
            .ok_or_else(|| "nightly fixture report deadline overflowed".to_owned())?;
        let mut report = Report::new("nightly-supervision-verifier");
        report
            .attach_checkpoint(checkpoint.clone())
            .map_err(|error| format!("cannot attach nightly fixture checkpoint: {error}"))?;
        let outcome = run_attributed_command(
            &mut report,
            AttributedRunContext {
                name: "nightly-workspace-tests",
                suite: "nightly-workspace-tests",
                suite_started: started,
                envelope: SupervisionEnvelope {
                    execution: execution_deadline,
                    child_completion_deadline,
                    report_completion_deadline,
                },
            },
            Some((
                "workspace-all-targets",
                "nightly-workspace-tests",
                "prelaunch",
            )),
            |timeout| {
                CommandSpec::new(&executable, timeout)
                    .argument("__portability-supervision-fixture")
                    .argument(receipt.as_os_str())
            },
        );
        if outcome != Err(FailureKind::Child) {
            return Err(
                "nightly production runner did not retain its cleanup/report reserve".to_owned(),
            );
        }
        verify_nightly_checkpoint_fields(&checkpoint)?;
        verify_nightly_descendant_quiescence(&receipt, report_completion_deadline)?;
        verify_nightly_capacity_rejection(&fixture, &executable)
    })();
    let cleanup = fixture.close();
    let (collision_preserved, collision_cleanup) = collision.finish();
    let result = if collision_preserved {
        result
    } else {
        Err("nightly allocator adopted or deleted its collision path".to_owned())
    };
    match (result, cleanup, collision_cleanup) {
        (Ok(()), Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(()), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup), Ok(())) | (Ok(()), Ok(()), Err(cleanup)) => Err(cleanup),
        (primary, cleanup, collision_cleanup) => Err(format!(
            "nightly supervision verification/cleanup failed: primary={primary:?}; root={cleanup:?}; collision={collision_cleanup:?}"
        )),
    }
}

#[cfg(unix)]
fn verify_nightly_checkpoint_fields(checkpoint: &Path) -> Result<(), String> {
    let durable = fs::read_to_string(checkpoint)
        .map_err(|error| format!("cannot read nightly durable checkpoint: {error}"))?;
    for required in [
        "nightly-workspace-tests-terminal-attribution",
        "nightly-workspace-tests-terminal-capture",
        "nightly-workspace-tests-worker-receipt",
        "timed-out-cleaned",
        "hell-testkit-lib",
        "blocked-case",
        "cleanupReceiptId",
        "cleanupState\":\"completed",
        "lifecycleIdle\":true",
        "workerState\":\"completed",
        "terminationReaped",
        "processGroupTerminationRequested",
        "leaderReaped",
        "candidateQuiescenceComplete\":false",
        "stdoutSha256",
        "stderrSha256",
        "stdoutTruncated",
        "droppedChunks",
        "droppedBytes",
        "blocked-without-newline",
        "subphase\":\"terminal",
    ] {
        if !durable.contains(required) {
            return Err(format!(
                "nightly durable checkpoint omitted required typed field {required}"
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
struct NightlyCollisionFixture {
    path: PathBuf,
    marker: PathBuf,
    root_handle: fs::File,
    marker_handle: fs::File,
    root_identity: fs::Metadata,
    marker_identity: fs::Metadata,
}

#[cfg(unix)]
impl NightlyCollisionFixture {
    fn create(sequence: u64) -> Result<Self, String> {
        let parent = fs::canonicalize(std::env::temp_dir())
            .map_err(|error| format!("cannot canonicalize nightly collision parent: {error}"))?;
        let path = parent.join(format!(
            "hell-nightly-supervision-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .map_err(|error| format!("cannot create nightly collision fixture: {error}"))?;
        let root_handle = fs::File::open(&path)
            .map_err(|error| format!("cannot retain nightly collision root: {error}"))?;
        let root_identity = root_handle
            .metadata()
            .map_err(|error| format!("cannot bind nightly collision root: {error}"))?;
        let marker = path.join("preserve");
        let marker_handle = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker)
            .map_err(|error| format!("cannot create nightly collision marker: {error}"))?;
        let marker_identity = marker_handle
            .metadata()
            .map_err(|error| format!("cannot bind nightly collision marker: {error}"))?;
        Ok(Self {
            path,
            marker,
            root_handle,
            marker_handle,
            root_identity,
            marker_identity,
        })
    }

    fn finish(self) -> (bool, Result<(), String>) {
        let path_identity = fs::symlink_metadata(&self.path);
        let marker_path_identity = fs::symlink_metadata(&self.marker);
        let preserved = path_identity.is_ok_and(|metadata| {
            metadata.file_type().is_dir()
                && !metadata.file_type().is_symlink()
                && (metadata.dev(), metadata.ino())
                    == (self.root_identity.dev(), self.root_identity.ino())
        }) && marker_path_identity.is_ok_and(|metadata| {
            metadata.file_type().is_file()
                && !metadata.file_type().is_symlink()
                && (metadata.dev(), metadata.ino())
                    == (self.marker_identity.dev(), self.marker_identity.ino())
        });
        drop(self.marker_handle);
        drop(self.root_handle);
        let cleanup = fs::remove_file(&self.marker)
            .and_then(|()| fs::remove_dir(&self.path))
            .map_err(|error| format!("cannot remove owned nightly collision fixture: {error}"));
        (preserved, cleanup)
    }
}

#[cfg(unix)]
fn verify_nightly_descendant_quiescence(
    receipt: &Path,
    report_completion_deadline: Instant,
) -> Result<(), String> {
    let descendant = fs::read_to_string(receipt)
        .map_err(|error| format!("cannot read nightly descendant receipt: {error}"))?;
    let descendant = descendant
        .strip_suffix('\n')
        .ok_or_else(|| "nightly descendant receipt lacks its delimiter".to_owned())?;
    if descendant.is_empty() || !descendant.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("nightly descendant receipt is not one decimal PID".to_owned());
    }
    let now = Instant::now();
    let probe_deadline = now
        .checked_add(Duration::from_millis(250))
        .unwrap_or(report_completion_deadline)
        .min(report_completion_deadline);
    let (progress, _receiver) = SupervisedProgressObserver::bounded(1);
    let probe = CommandSpec::new("/bin/ps", Duration::from_millis(250))
        .arguments(["-p", descendant, "-o", "pid=,ppid=,stat="])
        .run_until(probe_deadline, report_completion_deadline, progress)
        .map_err(|error| format!("cannot probe nightly descendant: {error}"))?;
    hell_testkit::wait_for_posix_uid_process_quiescence(
        probe_deadline,
        hell_testkit::PosixUidQuiescenceGoal::NoLiveProcesses,
        || {
            hell_testkit::parse_posix_uid_process_snapshot(
                probe.status.code(),
                &probe.stdout,
                &probe.stderr,
            )
        },
        || {
            Err(std::io::Error::other(
                "nightly descendant remained live after supervised tree termination",
            ))
        },
        || {
            Err(std::io::Error::other(
                "nightly verifier must not signal after typed cleanup",
            ))
        },
    )
    .map_err(|error| format!("nightly descendant did not reach no-live state: {error}"))?;
    Ok(())
}

#[cfg(unix)]
fn verify_nightly_capacity_rejection(
    fixture: &NightlyFixtureRoot,
    executable: &Path,
) -> Result<(), String> {
    let permits = (0..4)
        .map(|_| PortabilityWorkerPermit::acquire())
        .collect::<Result<Vec<_>, _>>()?;
    let started = Instant::now();
    let execution = started
        .checked_add(Duration::from_secs(1))
        .ok_or_else(|| "nightly capacity execution deadline overflowed".to_owned())?;
    let cleanup = started
        .checked_add(Duration::from_secs(2))
        .ok_or_else(|| "nightly capacity cleanup deadline overflowed".to_owned())?;
    let report_deadline = started
        .checked_add(Duration::from_secs(3))
        .ok_or_else(|| "nightly capacity report deadline overflowed".to_owned())?;
    let mut report = Report::new("nightly-capacity-verifier");
    let launch_marker = fixture.path.join("capacity-launch.pid");
    let outcome = run_attributed_command(
        &mut report,
        AttributedRunContext {
            name: "nightly-capacity",
            suite: "nightly-workspace-tests",
            suite_started: started,
            envelope: SupervisionEnvelope {
                execution,
                child_completion_deadline: cleanup,
                report_completion_deadline: report_deadline,
            },
        },
        Some(("workspace-all-targets", "capacity-rejection", "prelaunch")),
        |timeout| {
            CommandSpec::new(executable, timeout)
                .argument("__portability-supervision-fixture")
                .argument(launch_marker.as_os_str())
        },
    );
    drop(permits);
    if outcome != Err(FailureKind::Child)
        || !report.to_json().contains("launch-failed")
        || !report.to_json().contains("captureState\":\"unavailable")
        || launch_marker.exists()
    {
        return Err(
            "nightly production runner did not reject exhausted capacity before launch".to_owned(),
        );
    }
    Ok(())
}

#[cfg(unix)]
struct NightlyFixtureRoot {
    path: PathBuf,
    parent: fs::File,
    root: fs::File,
    parent_identity: (u64, u64),
    root_identity: (u64, u64),
    workspace: Option<fs::File>,
}

#[cfg(unix)]
impl NightlyFixtureRoot {
    fn create(first: u64) -> Result<Self, String> {
        Self::create_in(&std::env::temp_dir(), first)
    }

    fn create_in(parent_path: &Path, first: u64) -> Result<Self, String> {
        const CANDIDATES: usize = 64;
        let (parent_path, parent, parent_identity) = nightly_fixture_parent(parent_path)?;
        for offset in 0..CANDIDATES {
            let candidate = first
                .checked_add(u64::try_from(offset).unwrap_or(u64::MAX))
                .ok_or_else(|| "nightly fixture candidate sequence overflowed".to_owned())?;
            let path = parent_path.join(format!(
                "hell-nightly-supervision-{}-{candidate}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    let root = match fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
                        .open(&path)
                    {
                        Ok(root) => root,
                        Err(primary) => {
                            return compose_partial_nightly_fixture_cleanup(
                                format!("cannot retain nightly fixture root: {primary}"),
                                &path,
                                None,
                                &parent,
                                parent_identity,
                            );
                        }
                    };
                    let root_metadata = match root.metadata() {
                        Ok(metadata) => metadata,
                        Err(primary) => {
                            return compose_partial_nightly_fixture_cleanup(
                                format!("cannot bind retained nightly root: {primary}"),
                                &path,
                                None,
                                &parent,
                                parent_identity,
                            );
                        }
                    };
                    let path_metadata = match fs::symlink_metadata(&path) {
                        Ok(metadata) => metadata,
                        Err(primary) => {
                            return compose_partial_nightly_fixture_cleanup(
                                format!("cannot revalidate retained nightly root path: {primary}"),
                                &path,
                                Some((root_metadata.dev(), root_metadata.ino())),
                                &parent,
                                parent_identity,
                            );
                        }
                    };
                    if (root_metadata.dev(), root_metadata.ino())
                        != (path_metadata.dev(), path_metadata.ino())
                        || !root_metadata.is_dir()
                        || !path_metadata.is_dir()
                        || path_metadata.file_type().is_symlink()
                    {
                        return compose_partial_nightly_fixture_cleanup(
                            "nightly fixture root changed during retained binding".to_owned(),
                            &path,
                            Some((root_metadata.dev(), root_metadata.ino())),
                            &parent,
                            parent_identity,
                        );
                    }
                    let owner = Self {
                        path,
                        parent,
                        root,
                        parent_identity,
                        root_identity: (root_metadata.dev(), root_metadata.ino()),
                        workspace: None,
                    };
                    let setup = owner
                        .root
                        .set_permissions(fs::Permissions::from_mode(0o700))
                        .map_err(|error| format!("cannot restrict nightly fixture root: {error}"))
                        .and_then(|()| owner.revalidate());
                    return match setup {
                        Ok(()) => Ok(owner),
                        Err(primary) => match owner.close() {
                            Ok(()) => Err(primary),
                            Err(cleanup) => {
                                Err(format!("{primary}; cleanup also failed: {cleanup}"))
                            }
                        },
                    };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!("cannot create nightly fixture root: {error}"));
                }
            }
        }
        Err("nightly fixture root exhausted its bounded candidate sequence".to_owned())
    }

    fn close(self) -> Result<(), String> {
        let deadline = Instant::now()
            .checked_add(NIGHTLY_SUPERVISOR_START_TIMEOUT)
            .unwrap_or_else(Instant::now);
        self.close_until(deadline)
    }

    fn close_until(&self, deadline: Instant) -> Result<(), String> {
        const MAXIMUM_ENTRIES: usize = 5;
        self.revalidate()?;
        if Instant::now() >= deadline {
            return Err("nightly fixture cleanup deadline expired before enumeration".to_owned());
        }
        let mut children = fs::read_dir(&self.path)
            .map_err(|error| format!("cannot enumerate nightly fixture cleanup: {error}"))?;
        for index in 0..=MAXIMUM_ENTRIES {
            if Instant::now() >= deadline {
                return Err(
                    "nightly fixture cleanup deadline expired during enumeration".to_owned(),
                );
            }
            let Some(child) = children.next() else {
                break;
            };
            if index == MAXIMUM_ENTRIES {
                return Err(
                    "nightly fixture cleanup entry count exceeds its exact allowlist".to_owned(),
                );
            }
            let child = child
                .map_err(|error| format!("cannot read nightly fixture cleanup entry: {error}"))?;
            self.revalidate()?;
            let name = child.file_name();
            if name != "descendant.pid"
                && name != "report.json"
                && name != "request.bin"
                && name != "started.receipt"
                && name != "terminal.receipt"
            {
                return Err(format!(
                    "nightly fixture contains unexpected entry {}",
                    name.to_string_lossy()
                ));
            }
            let metadata = fs::symlink_metadata(child.path())
                .map_err(|error| format!("cannot bind nightly fixture cleanup entry: {error}"))?;
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(format!(
                    "nightly fixture cleanup entry {} is not a file",
                    name.to_string_lossy()
                ));
            }
            fs::remove_file(child.path()).map_err(|error| {
                format!(
                    "cannot remove nightly fixture entry {}: {error}",
                    name.to_string_lossy()
                )
            })?;
        }
        self.revalidate()?;
        fs::remove_dir(&self.path)
            .map_err(|error| format!("cannot remove exact nightly fixture root: {error}"))?;
        match fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "cannot attest nightly fixture root absence: {error}"
            )),
            Ok(_) => Err("nightly fixture root remains after exact cleanup".to_owned()),
        }
    }

    fn bind_existing(path: &Path, root_identity: (u64, u64), uid: u32) -> Result<Self, String> {
        let parent_path = path
            .parent()
            .ok_or_else(|| "nightly fixture root has no parent".to_owned())?;
        let parent = fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(parent_path)
            .map_err(|error| format!("cannot retain nightly fixture parent: {error}"))?;
        let root = fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| format!("cannot retain existing nightly fixture root: {error}"))?;
        let parent_metadata = parent
            .metadata()
            .map_err(|error| format!("cannot bind existing nightly fixture parent: {error}"))?;
        let root_metadata = root
            .metadata()
            .map_err(|error| format!("cannot bind existing nightly fixture root: {error}"))?;
        if (root_metadata.dev(), root_metadata.ino()) != root_identity
            || root_metadata.uid() != uid
            || root_metadata.mode() & 0o777 != 0o700
        {
            return Err("existing nightly fixture root receipt differs".to_owned());
        }
        let owner = Self {
            path: path.to_owned(),
            parent,
            root,
            parent_identity: (parent_metadata.dev(), parent_metadata.ino()),
            root_identity,
            workspace: None,
        };
        owner.revalidate()?;
        Ok(owner)
    }

    fn revalidate(&self) -> Result<(), String> {
        let parent = self
            .parent
            .metadata()
            .map_err(|error| format!("cannot revalidate nightly fixture parent: {error}"))?;
        let root = self
            .root
            .metadata()
            .map_err(|error| format!("cannot revalidate retained nightly root: {error}"))?;
        let path = fs::symlink_metadata(&self.path)
            .map_err(|error| format!("cannot revalidate nightly fixture root path: {error}"))?;
        if (parent.dev(), parent.ino()) != self.parent_identity
            || (root.dev(), root.ino()) != self.root_identity
            || (path.dev(), path.ino()) != self.root_identity
            || !path.file_type().is_dir()
            || path.file_type().is_symlink()
        {
            return Err("nightly fixture authority changed before cleanup".to_owned());
        }
        Ok(())
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn retain_workspace(&mut self, workspace: fs::File) {
        self.workspace = Some(workspace);
    }

    fn revalidate_workspace(&self, request: &ExternalSupervisorRequest) -> Result<(), String> {
        let workspace = self
            .workspace
            .as_ref()
            .ok_or_else(|| "nightly supervisor workspace handle is unavailable".to_owned())?;
        let retained = workspace
            .metadata()
            .map_err(|error| format!("cannot revalidate retained nightly workspace: {error}"))?;
        let path = fs::symlink_metadata(&request.root)
            .map_err(|error| format!("cannot revalidate nightly workspace path: {error}"))?;
        if (retained.dev(), retained.ino()) != (request.root_device, request.root_inode)
            || (path.dev(), path.ino()) != (request.root_device, request.root_inode)
            || retained.uid() != request.root_uid
            || retained.mode() != request.root_mode
            || !retained.is_dir()
            || path.file_type().is_symlink()
        {
            return Err("nightly supervisor workspace changed before command spawn".to_owned());
        }
        Ok(())
    }
}

#[cfg(unix)]
fn nightly_fixture_parent(parent_path: &Path) -> Result<(PathBuf, fs::File, (u64, u64)), String> {
    let path = fs::canonicalize(parent_path)
        .map_err(|error| format!("cannot canonicalize nightly fixture parent: {error}"))?;
    let handle = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|error| format!("cannot retain nightly fixture parent: {error}"))?;
    let metadata = handle
        .metadata()
        .map_err(|error| format!("cannot bind nightly fixture parent: {error}"))?;
    let identity = (metadata.dev(), metadata.ino());
    Ok((path, handle, identity))
}

#[cfg(unix)]
fn compose_partial_nightly_fixture_cleanup(
    primary: String,
    path: &Path,
    identity: Option<(u64, u64)>,
    parent: &fs::File,
    parent_identity: (u64, u64),
) -> Result<NightlyFixtureRoot, String> {
    let retained_parent = parent
        .metadata()
        .map_err(|error| format!("cannot revalidate partial nightly fixture parent: {error}"));
    let cleanup = match retained_parent {
        Ok(metadata) if (metadata.dev(), metadata.ino()) == parent_identity => {
            match fs::symlink_metadata(path) {
                Ok(metadata)
                    if metadata.file_type().is_dir()
                        && !metadata.file_type().is_symlink()
                        && identity.is_none_or(|identity| {
                            (metadata.dev(), metadata.ino()) == identity
                        }) =>
                {
                    match fs::read_dir(path) {
                        Ok(mut entries) => match entries.next() {
                            Some(_) => Err("partial nightly fixture root is not empty".to_owned()),
                            None => fs::remove_dir(path).map_err(|error| {
                                format!("cannot remove partial nightly fixture root: {error}")
                            }),
                        },
                        Err(error) => Err(format!(
                            "cannot enumerate partial nightly fixture root: {error}"
                        )),
                    }
                }
                Ok(_) => Err("partial nightly fixture root changed before cleanup".to_owned()),
                Err(error) => Err(format!(
                    "cannot revalidate partial nightly fixture root: {error}"
                )),
            }
        }
        Ok(_) => Err("partial nightly fixture parent changed before cleanup".to_owned()),
        Err(error) => Err(error),
    };
    match cleanup {
        Ok(()) => Err(primary),
        Err(cleanup) => Err(format!("{primary}; cleanup also failed: {cleanup}")),
    }
}

#[cfg(any(unix, windows))]
fn push_supervisor_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

#[cfg(any(unix, windows))]
fn push_supervisor_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

#[cfg(any(unix, windows))]
fn take_supervisor_bytes<'a>(
    bytes: &mut &'a [u8],
    count: usize,
    field: &str,
) -> Result<&'a [u8], String> {
    let Some((head, tail)) = bytes.split_at_checked(count) else {
        return Err(format!("nightly supervisor request truncated at {field}"));
    };
    *bytes = tail;
    Ok(head)
}

#[cfg(any(unix, windows))]
fn take_supervisor_u32(bytes: &mut &[u8], field: &str) -> Result<u32, String> {
    let raw = take_supervisor_bytes(bytes, size_of::<u32>(), field)?;
    Ok(u32::from_be_bytes(raw.try_into().map_err(|_| {
        format!("nightly supervisor {field} width drifted")
    })?))
}

#[cfg(any(unix, windows))]
fn take_supervisor_u64(bytes: &mut &[u8], field: &str) -> Result<u64, String> {
    let raw = take_supervisor_bytes(bytes, size_of::<u64>(), field)?;
    Ok(u64::from_be_bytes(raw.try_into().map_err(|_| {
        format!("nightly supervisor {field} width drifted")
    })?))
}

#[cfg(unix)]
fn encode_external_supervisor_request(
    request: &ExternalSupervisorRequest,
) -> Result<Vec<u8>, String> {
    let root = request.root.as_os_str().as_bytes();
    let root_length = u32::try_from(root.len())
        .map_err(|_| "nightly supervisor root path is too long".to_owned())?;
    let mut bytes = Vec::with_capacity(NIGHTLY_SUPERVISOR_PROTOCOL_MAGIC.len() + root.len() + 96);
    bytes.extend_from_slice(NIGHTLY_SUPERVISOR_PROTOCOL_MAGIC);
    bytes.push(request.plan.code());
    bytes.extend_from_slice(&request.nonce.0);
    push_supervisor_u64(&mut bytes, request.session_device);
    push_supervisor_u64(&mut bytes, request.session_inode);
    push_supervisor_u32(&mut bytes, request.session_uid);
    push_supervisor_u64(&mut bytes, request.root_device);
    push_supervisor_u64(&mut bytes, request.root_inode);
    push_supervisor_u32(&mut bytes, request.root_uid);
    push_supervisor_u32(&mut bytes, request.root_mode);
    bytes.push(u8::from(request.terminal_observer.is_some()));
    if let Some(observer) = request.terminal_observer {
        bytes.extend_from_slice(&observer.ip().octets());
        bytes.extend_from_slice(&observer.port().to_be_bytes());
    }
    bytes.push(u8::from(request.launch_gate.is_some()));
    if let Some(gate) = request.launch_gate {
        bytes.extend_from_slice(&gate.ip().octets());
        bytes.extend_from_slice(&gate.port().to_be_bytes());
    }
    bytes.push(u8::from(request.fixture_command));
    bytes.push(request.fixture_control as u8);
    push_supervisor_u32(&mut bytes, root_length);
    bytes.extend_from_slice(root);
    if bytes.len() > NIGHTLY_SUPERVISOR_REQUEST_LIMIT {
        return Err("nightly supervisor request exceeds its byte limit".to_owned());
    }
    Ok(bytes)
}

#[cfg(unix)]
fn decode_external_supervisor_request(bytes: &[u8]) -> Result<ExternalSupervisorRequest, String> {
    if bytes.len() > NIGHTLY_SUPERVISOR_REQUEST_LIMIT {
        return Err("nightly supervisor request exceeds its byte limit".to_owned());
    }
    let mut remaining = bytes;
    if take_supervisor_bytes(
        &mut remaining,
        NIGHTLY_SUPERVISOR_PROTOCOL_MAGIC.len(),
        "protocol magic",
    )? != NIGHTLY_SUPERVISOR_PROTOCOL_MAGIC
    {
        return Err("nightly supervisor request has invalid protocol magic".to_owned());
    }
    let plan =
        ExternalSupervisorPlan::from_code(take_supervisor_bytes(&mut remaining, 1, "plan")?[0])?;
    let nonce = Digest(
        take_supervisor_bytes(&mut remaining, Digest::default().0.len(), "nonce")?
            .try_into()
            .map_err(|_| "nightly supervisor nonce width drifted".to_owned())?,
    );
    let session_device = take_supervisor_u64(&mut remaining, "session device")?;
    let session_inode = take_supervisor_u64(&mut remaining, "session inode")?;
    let session_uid = take_supervisor_u32(&mut remaining, "session uid")?;
    let root_device = take_supervisor_u64(&mut remaining, "root device")?;
    let root_inode = take_supervisor_u64(&mut remaining, "root inode")?;
    let root_uid = take_supervisor_u32(&mut remaining, "root uid")?;
    let root_mode = take_supervisor_u32(&mut remaining, "root mode")?;
    let terminal_observer = match take_supervisor_bytes(&mut remaining, 1, "observer flag")?[0] {
        0 => None,
        1 => {
            let address = Ipv4Addr::from(
                <[u8; 4]>::try_from(take_supervisor_bytes(
                    &mut remaining,
                    4,
                    "observer address",
                )?)
                .map_err(|_| "nightly supervisor observer address width drifted".to_owned())?,
            );
            let port = u16::from_be_bytes(
                take_supervisor_bytes(&mut remaining, size_of::<u16>(), "observer port")?
                    .try_into()
                    .map_err(|_| "nightly supervisor observer port width drifted".to_owned())?,
            );
            Some(SocketAddrV4::new(address, port))
        }
        _ => return Err("nightly supervisor observer flag is invalid".to_owned()),
    };
    let launch_gate = match take_supervisor_bytes(&mut remaining, 1, "gate flag")?[0] {
        0 => None,
        1 => {
            let address = Ipv4Addr::from(
                <[u8; 4]>::try_from(take_supervisor_bytes(&mut remaining, 4, "gate address")?)
                    .map_err(|_| "nightly supervisor gate address width drifted".to_owned())?,
            );
            let port = u16::from_be_bytes(
                take_supervisor_bytes(&mut remaining, size_of::<u16>(), "gate port")?
                    .try_into()
                    .map_err(|_| "nightly supervisor gate port width drifted".to_owned())?,
            );
            Some(SocketAddrV4::new(address, port))
        }
        _ => return Err("nightly supervisor gate flag is invalid".to_owned()),
    };
    let fixture_command = match take_supervisor_bytes(&mut remaining, 1, "fixture flag")?[0] {
        0 => false,
        1 => true,
        _ => return Err("nightly supervisor fixture flag is invalid".to_owned()),
    };
    let fixture_control = ExternalSupervisorFixtureControl::from_byte(
        take_supervisor_bytes(&mut remaining, 1, "fixture control")?[0],
    )?;
    if fixture_control != ExternalSupervisorFixtureControl::Normal && !fixture_command {
        return Err("nightly supervisor fixture control requires a fixture command".to_owned());
    }
    let root_length = usize::try_from(take_supervisor_u32(&mut remaining, "root length")?)
        .map_err(|_| "nightly supervisor root length is not representable".to_owned())?;
    let root = PathBuf::from(std::ffi::OsString::from_vec(
        take_supervisor_bytes(&mut remaining, root_length, "root")?.to_vec(),
    ));
    if !remaining.is_empty() {
        return Err("nightly supervisor request has trailing bytes".to_owned());
    }
    Ok(ExternalSupervisorRequest {
        plan,
        root,
        root_device,
        root_inode,
        root_uid,
        root_mode,
        nonce,
        session_device,
        session_inode,
        session_uid,
        terminal_observer,
        launch_gate,
        fixture_command,
        fixture_control,
    })
}

#[cfg(unix)]
fn supervisor_nonce() -> Digest {
    static SEQUENCE: AtomicU64 = AtomicU64::new(1);
    let mut bytes = Vec::with_capacity(size_of::<u32>() + size_of::<u64>());
    bytes.extend_from_slice(&std::process::id().to_be_bytes());
    bytes.extend_from_slice(&SEQUENCE.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    sha256_bytes(&bytes)
}

#[cfg(unix)]
fn write_create_new_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("cannot sync {}: {error}", path.display()))
}

#[cfg(unix)]
fn read_bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot bind {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() > u64::try_from(limit).unwrap_or(u64::MAX) {
        return Err(format!("{} is not a bounded regular file", path.display()));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(limit));
    std::io::Read::by_ref(&mut file)
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() > limit {
        return Err(format!("{} exceeds its byte limit", path.display()));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn read_bounded_handle(file: &mut fs::File, path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot bind {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() > u64::try_from(limit).unwrap_or(u64::MAX) {
        return Err(format!("{} is not a bounded regular file", path.display()));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(limit));
    std::io::Read::by_ref(file)
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() > limit {
        return Err(format!("{} exceeds its byte limit", path.display()));
    }
    Ok(bytes)
}

#[cfg(any(unix, windows))]
fn supervisor_handshake_bytes(
    message: ExternalSupervisorMessage,
    request_sha256: Digest,
    nonce: Digest,
) -> Vec<u8> {
    let digest_width = Digest::default().0.len();
    let mut bytes = Vec::with_capacity(1 + digest_width * 2);
    bytes.push(message as u8);
    bytes.extend_from_slice(&request_sha256.0);
    bytes.extend_from_slice(&nonce.0);
    bytes
}

#[cfg(any(unix, windows))]
fn write_supervisor_handshake(
    stream: &mut impl std::io::Write,
    message: ExternalSupervisorMessage,
    request_sha256: Digest,
    nonce: Digest,
) -> Result<(), String> {
    stream
        .write_all(&supervisor_handshake_bytes(message, request_sha256, nonce))
        .and_then(|()| stream.flush())
        .map_err(|error| format!("cannot write nightly supervisor handshake: {error}"))
}

#[cfg(any(unix, windows))]
fn read_supervisor_handshake(
    stream: &mut impl std::io::Read,
    expected: ExternalSupervisorMessage,
    request_sha256: Digest,
    nonce: Digest,
) -> Result<(), String> {
    let digest_width = Digest::default().0.len();
    let mut bytes = vec![0; 1 + digest_width * 2];
    stream
        .read_exact(&mut bytes)
        .map_err(|error| format!("cannot read nightly supervisor handshake: {error}"))?;
    validate_supervisor_handshake_bytes(&bytes, expected, request_sha256, nonce)
}

#[cfg(any(unix, windows))]
fn validate_supervisor_handshake_bytes(
    bytes: &[u8],
    expected: ExternalSupervisorMessage,
    request_sha256: Digest,
    nonce: Digest,
) -> Result<(), String> {
    let digest_width = Digest::default().0.len();
    if bytes.len() != 1 + digest_width * 2 {
        return Err("nightly supervisor handshake width differs".to_owned());
    }
    let actual = ExternalSupervisorMessage::from_byte(bytes[0])?;
    if actual != expected
        || bytes[1..=digest_width] != request_sha256.0[..]
        || bytes[1 + digest_width..] != nonce.0[..]
    {
        return Err("nightly supervisor handshake did not match its bound request".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn read_supervisor_handshake_until(
    stream: &mut (impl std::io::Read + std::os::fd::AsFd),
    expected: ExternalSupervisorMessage,
    request_sha256: Digest,
    nonce: Digest,
    deadline: Instant,
) -> Result<bool, String> {
    let digest_width = Digest::default().0.len();
    let mut bytes = vec![0; 1 + digest_width * 2];
    if !read_supervisor_bytes_until(stream, &mut bytes, deadline)? {
        return Ok(false);
    }
    validate_supervisor_handshake_bytes(&bytes, expected, request_sha256, nonce)?;
    Ok(true)
}

#[cfg(unix)]
fn read_supervisor_message_until(
    stream: &mut (impl std::io::Read + std::os::fd::AsFd),
    request_sha256: Digest,
    nonce: Digest,
    deadline: Instant,
) -> Result<Option<ExternalSupervisorMessage>, String> {
    let digest_width = Digest::default().0.len();
    let mut bytes = vec![0; 1 + digest_width * 2];
    if !read_supervisor_bytes_until(stream, &mut bytes, deadline)? {
        return Ok(None);
    }
    let message = ExternalSupervisorMessage::from_byte(bytes[0])?;
    validate_supervisor_handshake_bytes(&bytes, message, request_sha256, nonce)?;
    Ok(Some(message))
}

#[cfg(unix)]
fn read_supervisor_bytes_until(
    stream: &mut (impl std::io::Read + std::os::fd::AsFd),
    bytes: &mut [u8],
    deadline: Instant,
) -> Result<bool, String> {
    let mut offset = 0;
    loop {
        if offset == bytes.len() {
            return Ok(true);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        let timeout = i32::try_from(remaining.as_millis())
            .unwrap_or(i32::MAX)
            .max(1);
        let mut descriptors = [nix::poll::PollFd::new(
            &*stream,
            nix::poll::PollFlags::POLLIN,
        )];
        let result = nix::poll::poll(&mut descriptors, timeout)
            .map_err(|error| format!("cannot poll nightly supervisor handshake: {error}"))?;
        if result == 0 {
            return Ok(false);
        }
        let read = stream
            .read(&mut bytes[offset..])
            .map_err(|error| format!("cannot read nightly supervisor bytes: {error}"))?;
        if read == 0 {
            return Err("nightly supervisor control channel closed mid-frame".to_owned());
        }
        offset = offset.saturating_add(read);
    }
}

#[cfg(unix)]
fn wait_supervisor_eof_until(
    stream: &mut (impl std::io::Read + std::os::fd::AsFd),
    deadline: Instant,
) -> Result<bool, String> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        let timeout = i32::try_from(remaining.as_millis())
            .unwrap_or(i32::MAX)
            .max(1);
        let mut descriptors = [nix::poll::PollFd::new(
            &*stream,
            nix::poll::PollFlags::POLLIN | nix::poll::PollFlags::POLLHUP,
        )];
        if nix::poll::poll(&mut descriptors, timeout)
            .map_err(|error| format!("cannot poll nightly supervisor exit: {error}"))?
            == 0
        {
            return Ok(false);
        }
        let mut unexpected = [0_u8; 1];
        match stream.read(&mut unexpected) {
            Ok(0) => return Ok(true),
            Ok(_) => {
                return Err("nightly supervisor emitted bytes after its cleanup receipt".to_owned());
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(format!("cannot read nightly supervisor exit: {error}")),
        }
    }
}

#[cfg(unix)]
fn write_supervisor_terminal_payload(
    stream: &mut impl std::io::Write,
    bytes: &[u8],
) -> Result<(), String> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| "nightly supervisor terminal payload is too large".to_owned())?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(bytes))
        .and_then(|()| stream.flush())
        .map_err(|error| format!("cannot write nightly supervisor terminal payload: {error}"))
}

#[cfg(unix)]
fn read_supervisor_terminal_payload_until(
    stream: &mut (impl std::io::Read + std::os::fd::AsFd),
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let mut length = [0_u8; size_of::<u32>()];
    if !read_supervisor_bytes_until(stream, &mut length, deadline)? {
        return Err("nightly supervisor terminal length exceeded its deadline".to_owned());
    }
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| "nightly supervisor terminal length is not representable".to_owned())?;
    if length > NIGHTLY_SUPERVISOR_TERMINAL_LIMIT {
        return Err("nightly supervisor terminal payload exceeds its byte limit".to_owned());
    }
    let mut bytes = vec![0; length];
    if !read_supervisor_bytes_until(stream, &mut bytes, deadline)? {
        return Err("nightly supervisor terminal payload exceeded its deadline".to_owned());
    }
    Ok(bytes)
}

#[cfg(unix)]
fn duration_millis(duration: Duration, field: &str) -> Result<u64, String> {
    u64::try_from(duration.as_millis())
        .map_err(|_| format!("nightly supervisor {field} duration is too large"))
}

#[cfg(unix)]
fn write_supervisor_budget(
    stream: &mut impl std::io::Write,
    envelope: SupervisionEnvelope,
    started: Instant,
) -> Result<(), String> {
    let mut bytes = vec![ExternalSupervisorMessage::Budget as u8];
    push_supervisor_u64(
        &mut bytes,
        duration_millis(
            envelope.execution.saturating_duration_since(started),
            "execution",
        )?,
    );
    push_supervisor_u64(
        &mut bytes,
        duration_millis(
            envelope
                .child_completion_deadline
                .saturating_duration_since(started),
            "child completion",
        )?,
    );
    push_supervisor_u64(
        &mut bytes,
        duration_millis(
            envelope
                .report_completion_deadline
                .saturating_duration_since(started),
            "report completion",
        )?,
    );
    stream
        .write_all(&bytes)
        .and_then(|()| stream.flush())
        .map_err(|error| format!("cannot write nightly supervisor budget: {error}"))
}

#[cfg(unix)]
fn read_supervisor_budget(
    stream: &mut (impl std::io::Read + std::os::fd::AsFd),
    started: Instant,
    deadline: Instant,
) -> Result<SupervisionEnvelope, String> {
    let mut bytes = [0_u8; 1 + size_of::<u64>() * 3];
    if !read_supervisor_bytes_until(stream, &mut bytes, deadline)? {
        return Err("nightly supervisor budget exceeded its startup deadline".to_owned());
    }
    if ExternalSupervisorMessage::from_byte(bytes[0])? != ExternalSupervisorMessage::Budget {
        return Err("nightly supervisor expected a budget message".to_owned());
    }
    let mut remaining = &bytes[1..];
    let execution = Duration::from_millis(take_supervisor_u64(&mut remaining, "execution budget")?);
    let cleanup = Duration::from_millis(take_supervisor_u64(&mut remaining, "cleanup budget")?);
    let report = Duration::from_millis(take_supervisor_u64(&mut remaining, "report budget")?);
    if execution.is_zero() || execution >= cleanup || cleanup >= report {
        return Err("nightly supervisor received an unordered budget".to_owned());
    }
    Ok(SupervisionEnvelope {
        execution: started
            .checked_add(execution)
            .ok_or_else(|| "nightly supervisor execution deadline overflowed".to_owned())?,
        child_completion_deadline: started
            .checked_add(cleanup)
            .ok_or_else(|| "nightly supervisor cleanup deadline overflowed".to_owned())?,
        report_completion_deadline: started
            .checked_add(report)
            .ok_or_else(|| "nightly supervisor report deadline overflowed".to_owned())?,
    })
}

#[cfg(any(unix, windows))]
fn encode_external_supervisor_terminal(
    request_sha256: Digest,
    nonce: Digest,
    terminal: &ExternalSupervisorTerminal,
) -> Result<Vec<u8>, String> {
    const FIXED_RECEIPT_RESERVE: usize = 8 * 1024;
    let mut text_budget = NIGHTLY_SUPERVISOR_TERMINAL_LIMIT
        .checked_sub(FIXED_RECEIPT_RESERVE)
        .ok_or_else(|| "nightly supervisor terminal fixed reserve is invalid".to_owned())?;
    let mut bytes = Vec::with_capacity(NIGHTLY_SUPERVISOR_TERMINAL_LIMIT);
    bytes.extend_from_slice(NIGHTLY_SUPERVISOR_PROTOCOL_MAGIC);
    bytes.push(NIGHTLY_SUPERVISOR_TERMINAL_MESSAGE);
    bytes.extend_from_slice(&request_sha256.0);
    bytes.extend_from_slice(&nonce.0);
    encode_external_supervisor_terminal_fixed(&mut bytes, terminal);
    push_supervisor_optional_text_with_budget(
        &mut bytes,
        Some(&terminal.cleanup_state),
        &mut text_budget,
    )?;
    push_supervisor_optional_text_with_budget(
        &mut bytes,
        terminal.cleanup_error.as_deref(),
        &mut text_budget,
    )?;
    push_supervisor_u32(
        &mut bytes,
        u32::try_from(terminal.cleanup_failures.len())
            .map_err(|_| "nightly supervisor cleanup failure count is too large".to_owned())?,
    );
    for failure in &terminal.cleanup_failures {
        push_supervisor_optional_text_with_budget(&mut bytes, Some(failure), &mut text_budget)?;
    }
    let detail = bounded_external_supervisor_text(&terminal.detail, text_budget);
    text_budget = text_budget.saturating_sub(detail.len());
    let detail = detail.as_bytes();
    let detail_length = u32::try_from(detail.len())
        .map_err(|_| "nightly supervisor terminal detail is too long".to_owned())?;
    push_supervisor_u32(&mut bytes, detail_length);
    bytes.extend_from_slice(detail);
    encode_external_supervisor_attribution(&mut bytes, terminal, &mut text_budget)?;
    push_supervisor_u64(&mut bytes, terminal.dropped_chunks);
    push_supervisor_u64(&mut bytes, terminal.dropped_bytes);
    if bytes.len() > NIGHTLY_SUPERVISOR_TERMINAL_LIMIT {
        return Err("nightly supervisor terminal receipt exceeds its byte limit".to_owned());
    }
    Ok(bytes)
}

#[cfg(any(unix, windows))]
fn encode_external_supervisor_terminal_fixed(
    bytes: &mut Vec<u8>,
    terminal: &ExternalSupervisorTerminal,
) {
    bytes.push(u8::from(terminal.execution.success));
    bytes.push(u8::from(terminal.execution.timed_out));
    bytes.extend_from_slice(&terminal.exit_code.unwrap_or(i32::MIN).to_be_bytes());
    push_supervisor_u64(bytes, terminal.stdout_bytes);
    bytes.extend_from_slice(&terminal.stdout_sha256.0);
    bytes.push(u8::from(terminal.capture.stdout_truncated));
    push_supervisor_u64(bytes, terminal.stderr_bytes);
    bytes.extend_from_slice(&terminal.stderr_sha256.0);
    bytes.push(u8::from(terminal.capture.stderr_truncated));
    bytes.push(u8::from(terminal.capture.available));
    bytes.push(u8::from(terminal.cleanup.terminal));
    push_supervisor_u64(bytes, terminal.cleanup_id.unwrap_or(u64::MAX));
    bytes.push(u8::from(terminal.cleanup.termination_requested));
    bytes.push(u8::from(terminal.cleanup.leader_reaped));
    bytes.push(u8::from(terminal.candidate_quiescence_complete));
}

#[cfg(any(unix, windows))]
fn encode_external_supervisor_attribution(
    bytes: &mut Vec<u8>,
    terminal: &ExternalSupervisorTerminal,
    text_budget: &mut usize,
) -> Result<(), String> {
    push_supervisor_u64(bytes, terminal.attribution.sequence);
    push_supervisor_u64(
        bytes,
        encode_external_supervisor_elapsed(terminal.attribution.transition_elapsed),
    );
    push_supervisor_optional_text_with_budget(
        bytes,
        terminal.attribution.target.as_deref(),
        text_budget,
    )?;
    push_supervisor_optional_text_with_budget(
        bytes,
        terminal.attribution.case.as_deref(),
        text_budget,
    )?;
    push_supervisor_optional_text_with_budget(
        bytes,
        terminal.attribution.case_state.as_deref(),
        text_budget,
    )?;
    push_supervisor_optional_text_with_budget(
        bytes,
        terminal.attribution.subphase.as_deref(),
        text_budget,
    )?;
    bytes.push(u8::from(terminal.failed_case.is_some()));
    if let Some(failed_case) = &terminal.failed_case {
        push_supervisor_u64(bytes, failed_case.sequence);
        push_supervisor_u64(
            bytes,
            encode_external_supervisor_elapsed(failed_case.transition_elapsed),
        );
        push_supervisor_optional_text_with_budget(
            bytes,
            failed_case.target.as_deref(),
            text_budget,
        )?;
        push_supervisor_optional_text_with_budget(bytes, Some(&failed_case.case), text_budget)?;
        push_supervisor_optional_text_with_budget(bytes, Some(&failed_case.stream), text_budget)?;
    }
    push_supervisor_optional_text_with_budget(
        bytes,
        terminal.failed_case_unavailable.as_deref(),
        text_budget,
    )?;
    Ok(())
}

#[cfg(any(unix, windows))]
fn push_supervisor_optional_text_with_budget(
    bytes: &mut Vec<u8>,
    value: Option<&str>,
    budget: &mut usize,
) -> Result<(), String> {
    let bounded = value.map(|value| bounded_external_supervisor_text(value, *budget));
    if let Some(value) = &bounded {
        *budget = (*budget).saturating_sub(value.len());
    }
    push_supervisor_optional_text(bytes, bounded.as_deref())
}

#[cfg(any(unix, windows))]
fn push_supervisor_optional_text(bytes: &mut Vec<u8>, value: Option<&str>) -> Result<(), String> {
    bytes.push(u8::from(value.is_some()));
    if let Some(value) = value {
        let length = u32::try_from(value.len())
            .map_err(|_| "nightly supervisor attribution field is too long".to_owned())?;
        push_supervisor_u32(bytes, length);
        bytes.extend_from_slice(value.as_bytes());
    }
    Ok(())
}

#[cfg(any(unix, windows))]
fn take_supervisor_optional_text(bytes: &mut &[u8], field: &str) -> Result<Option<String>, String> {
    match take_supervisor_bytes(bytes, 1, field)?[0] {
        0 => Ok(None),
        1 => {
            let length = usize::try_from(take_supervisor_u32(bytes, field)?)
                .map_err(|_| format!("nightly supervisor {field} length is not representable"))?;
            String::from_utf8(take_supervisor_bytes(bytes, length, field)?.to_vec())
                .map(Some)
                .map_err(|_| format!("nightly supervisor {field} is not UTF-8"))
        }
        _ => Err(format!(
            "nightly supervisor {field} presence flag is invalid"
        )),
    }
}

#[cfg(any(unix, windows))]
fn take_supervisor_bool(bytes: &mut &[u8], field: &str) -> Result<bool, String> {
    match take_supervisor_bytes(bytes, 1, field)?[0] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(format!("nightly supervisor {field} flag is invalid")),
    }
}

fn canonical_external_supervisor_elapsed(duration: Duration) -> Duration {
    Duration::from_millis(
        u64::try_from(duration.as_millis()).unwrap_or(NIGHTLY_SUPERVISOR_ELAPSED_MAX_MILLIS),
    )
}

#[cfg(any(unix, windows))]
fn encode_external_supervisor_elapsed(elapsed: Option<Duration>) -> u64 {
    elapsed.map_or(NIGHTLY_SUPERVISOR_ELAPSED_NONE, |duration| {
        u64::try_from(canonical_external_supervisor_elapsed(duration).as_millis())
            .unwrap_or(NIGHTLY_SUPERVISOR_ELAPSED_MAX_MILLIS)
    })
}

#[cfg(any(unix, windows))]
fn decode_external_supervisor_elapsed(encoded: u64) -> Option<Duration> {
    (encoded != NIGHTLY_SUPERVISOR_ELAPSED_NONE).then_some(Duration::from_millis(encoded))
}

#[cfg(any(unix, windows))]
fn encode_external_supervisor_progress(
    progress: &PortabilityChildProgress,
) -> Result<Vec<u8>, String> {
    let attribution = progress.attribution();
    let mut bytes = Vec::with_capacity(1024);
    push_supervisor_u64(&mut bytes, attribution.sequence);
    push_supervisor_u64(
        &mut bytes,
        encode_external_supervisor_elapsed(attribution.transition_elapsed),
    );
    push_supervisor_optional_text(&mut bytes, attribution.target.as_deref())?;
    push_supervisor_optional_text(&mut bytes, attribution.case.as_deref())?;
    push_supervisor_optional_text(&mut bytes, attribution.case_state.as_deref())?;
    push_supervisor_optional_text(&mut bytes, attribution.subphase.as_deref())?;
    if bytes.len() > NIGHTLY_SUPERVISOR_PROGRESS_LIMIT {
        return Err("nightly supervisor progress payload exceeds its byte limit".to_owned());
    }
    Ok(bytes)
}

#[cfg(any(unix, windows))]
fn decode_external_supervisor_progress(bytes: &[u8]) -> Result<ActivePhaseAttribution, String> {
    let mut remaining = bytes;
    let sequence = take_supervisor_u64(&mut remaining, "progress sequence")?;
    let transition = take_supervisor_u64(&mut remaining, "progress transition")?;
    let attribution = ActivePhaseAttribution {
        sequence,
        transition_elapsed: decode_external_supervisor_elapsed(transition),
        target: take_supervisor_optional_text(&mut remaining, "progress target")?,
        case: take_supervisor_optional_text(&mut remaining, "progress case")?,
        case_state: take_supervisor_optional_text(&mut remaining, "progress case state")?,
        subphase: take_supervisor_optional_text(&mut remaining, "progress subphase")?,
    };
    if !remaining.is_empty() {
        return Err("nightly supervisor progress payload has trailing bytes".to_owned());
    }
    Ok(attribution)
}

#[cfg(unix)]
fn try_write_external_supervisor_progress(
    stream: &impl std::os::fd::AsFd,
    request_sha256: Digest,
    nonce: Digest,
    progress: &PortabilityChildProgress,
) -> Result<bool, String> {
    let payload = encode_external_supervisor_progress(progress)?;
    let length = u32::try_from(payload.len())
        .map_err(|_| "nightly supervisor progress payload is too large".to_owned())?;
    let mut frame =
        supervisor_handshake_bytes(ExternalSupervisorMessage::Progress, request_sha256, nonce);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    if frame.len() > NIGHTLY_SUPERVISOR_PROGRESS_LIMIT {
        return Err("nightly supervisor progress frame exceeds its atomic byte limit".to_owned());
    }
    let fd = stream.as_fd().as_raw_fd();
    let pipe_buf = nix::unistd::fpathconf(fd, nix::unistd::PathconfVar::PIPE_BUF)
        .map_err(|error| format!("cannot inspect nightly progress atomic limit: {error}"))?
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| "nightly progress pipe has no representable atomic limit".to_owned())?;
    if frame.len() > pipe_buf {
        return Ok(false);
    }
    match nix::unistd::write(fd, &frame) {
        Ok(written) if written == frame.len() => Ok(true),
        Ok(_) => Err("nightly supervisor progress frame was only partially written".to_owned()),
        Err(nix::errno::Errno::EAGAIN) => Ok(false),
        Err(error) => Err(format!("cannot write nightly supervisor progress: {error}")),
    }
}

#[cfg(unix)]
fn set_supervisor_nonblocking(
    stream: &impl std::os::fd::AsFd,
    enabled: bool,
) -> Result<(), String> {
    use nix::fcntl::{FcntlArg, OFlag, fcntl};

    let fd = stream.as_fd().as_raw_fd();
    let raw = fcntl(fd, FcntlArg::F_GETFL)
        .map_err(|error| format!("cannot inspect nightly supervisor pipe flags: {error}"))?;
    let mut flags = OFlag::from_bits_truncate(raw);
    flags.set(OFlag::O_NONBLOCK, enabled);
    fcntl(fd, FcntlArg::F_SETFL(flags))
        .map(|_| ())
        .map_err(|error| format!("cannot update nightly supervisor pipe flags: {error}"))
}

#[cfg(any(unix, windows))]
fn decode_external_supervisor_terminal(
    bytes: &[u8],
    request_sha256: Digest,
    nonce: Digest,
) -> Result<ExternalSupervisorTerminal, String> {
    if bytes.len() > NIGHTLY_SUPERVISOR_TERMINAL_LIMIT {
        return Err("nightly supervisor terminal receipt exceeds its byte limit".to_owned());
    }
    let mut remaining = decode_external_supervisor_terminal_binding(bytes, request_sha256, nonce)?;
    let success = take_supervisor_bool(&mut remaining, "success")?;
    let timed_out = take_supervisor_bool(&mut remaining, "timeout")?;
    let raw_code = i32::from_be_bytes(
        take_supervisor_bytes(&mut remaining, size_of::<i32>(), "exit code")?
            .try_into()
            .map_err(|_| "nightly supervisor exit code width drifted".to_owned())?,
    );
    let stdout_bytes = take_supervisor_u64(&mut remaining, "stdout bytes")?;
    let stdout_sha256 = Digest(
        take_supervisor_bytes(&mut remaining, Digest::default().0.len(), "stdout digest")?
            .try_into()
            .map_err(|_| "nightly supervisor stdout digest width drifted".to_owned())?,
    );
    let stdout_truncated = take_supervisor_bool(&mut remaining, "stdout truncation")?;
    let stderr_bytes = take_supervisor_u64(&mut remaining, "stderr bytes")?;
    let stderr_sha256 = Digest(
        take_supervisor_bytes(&mut remaining, Digest::default().0.len(), "stderr digest")?
            .try_into()
            .map_err(|_| "nightly supervisor stderr digest width drifted".to_owned())?,
    );
    let stderr_truncated = take_supervisor_bool(&mut remaining, "stderr truncation")?;
    let capture_available = take_supervisor_bool(&mut remaining, "capture availability")?;
    let cleanup_terminal = take_supervisor_bool(&mut remaining, "cleanup state")?;
    let cleanup_id = take_supervisor_u64(&mut remaining, "cleanup id")?;
    let termination_requested = take_supervisor_bool(&mut remaining, "termination request")?;
    let leader_reaped = take_supervisor_bool(&mut remaining, "leader reap")?;
    let candidate_quiescence_complete =
        take_supervisor_bool(&mut remaining, "candidate quiescence")?;
    let cleanup_state = take_supervisor_optional_text(&mut remaining, "cleanup state name")?
        .ok_or_else(|| "nightly supervisor cleanup state name is unavailable".to_owned())?;
    let cleanup_error = take_supervisor_optional_text(&mut remaining, "cleanup error")?;
    let cleanup_failures = decode_external_supervisor_cleanup_failures(&mut remaining)?;
    let detail_length = usize::try_from(take_supervisor_u32(&mut remaining, "detail length")?)
        .map_err(|_| "nightly supervisor detail length is not representable".to_owned())?;
    let detail =
        String::from_utf8(take_supervisor_bytes(&mut remaining, detail_length, "detail")?.to_vec())
            .map_err(|_| "nightly supervisor terminal detail is not UTF-8".to_owned())?;
    let sequence = take_supervisor_u64(&mut remaining, "attribution sequence")?;
    let transition_millis = take_supervisor_u64(&mut remaining, "transition elapsed")?;
    let attribution = ActivePhaseAttribution {
        sequence,
        transition_elapsed: decode_external_supervisor_elapsed(transition_millis),
        target: take_supervisor_optional_text(&mut remaining, "attribution target")?,
        case: take_supervisor_optional_text(&mut remaining, "attribution case")?,
        case_state: take_supervisor_optional_text(&mut remaining, "attribution case state")?,
        subphase: take_supervisor_optional_text(&mut remaining, "attribution subphase")?,
    };
    let failed_case = decode_external_supervisor_failed_case(&mut remaining)?;
    let failed_case_unavailable =
        take_supervisor_optional_text(&mut remaining, "failed case unavailable reason")?;
    if failed_case
        .as_ref()
        .is_some_and(|failed| !matches!(failed.stream.as_str(), "stdout" | "stderr"))
    {
        return Err("nightly supervisor failed case stream is invalid".to_owned());
    }
    let dropped_chunks = take_supervisor_u64(&mut remaining, "dropped progress chunks")?;
    let dropped_bytes = take_supervisor_u64(&mut remaining, "dropped progress bytes")?;
    if !remaining.is_empty() {
        return Err("nightly supervisor terminal receipt has trailing bytes".to_owned());
    }
    Ok(ExternalSupervisorTerminal {
        execution: ExternalSupervisorExecutionState { success, timed_out },
        exit_code: (raw_code != i32::MIN).then_some(raw_code),
        stdout_bytes,
        stdout_sha256,
        stderr_bytes,
        stderr_sha256,
        capture: ExternalSupervisorCaptureState {
            stdout_truncated,
            stderr_truncated,
            available: capture_available,
        },
        cleanup: ExternalSupervisorCleanupState {
            terminal: cleanup_terminal,
            termination_requested,
            leader_reaped,
        },
        cleanup_id: (cleanup_id != u64::MAX).then_some(cleanup_id),
        candidate_quiescence_complete,
        cleanup_state,
        cleanup_error,
        cleanup_failures,
        detail,
        attribution,
        failed_case,
        failed_case_unavailable,
        dropped_chunks,
        dropped_bytes,
    })
}

#[cfg(any(unix, windows))]
fn decode_external_supervisor_terminal_binding(
    bytes: &[u8],
    request_sha256: Digest,
    nonce: Digest,
) -> Result<&[u8], String> {
    let mut remaining = bytes;
    if take_supervisor_bytes(
        &mut remaining,
        NIGHTLY_SUPERVISOR_PROTOCOL_MAGIC.len(),
        "terminal magic",
    )? != NIGHTLY_SUPERVISOR_PROTOCOL_MAGIC
        || take_supervisor_bytes(&mut remaining, 1, "terminal message")?[0]
            != NIGHTLY_SUPERVISOR_TERMINAL_MESSAGE
        || take_supervisor_bytes(&mut remaining, request_sha256.0.len(), "request digest")?
            != request_sha256.0
        || take_supervisor_bytes(&mut remaining, nonce.0.len(), "nonce")? != nonce.0
    {
        return Err("nightly supervisor terminal receipt binding differs".to_owned());
    }
    Ok(remaining)
}

#[cfg(any(unix, windows))]
fn decode_external_supervisor_cleanup_failures(
    remaining: &mut &[u8],
) -> Result<Vec<String>, String> {
    let cleanup_failure_count =
        usize::try_from(take_supervisor_u32(remaining, "cleanup failure count")?).map_err(
            |_| "nightly supervisor cleanup failure count is not representable".to_owned(),
        )?;
    if cleanup_failure_count > 8 {
        return Err("nightly supervisor cleanup failure count exceeds its bound".to_owned());
    }
    let mut cleanup_failures = Vec::with_capacity(cleanup_failure_count);
    for _ in 0..cleanup_failure_count {
        cleanup_failures.push(
            take_supervisor_optional_text(remaining, "cleanup failure")?
                .ok_or_else(|| "nightly supervisor cleanup failure is unavailable".to_owned())?,
        );
    }
    Ok(cleanup_failures)
}

#[cfg(any(unix, windows))]
fn decode_external_supervisor_failed_case(
    remaining: &mut &[u8],
) -> Result<Option<CausalFailedCase>, String> {
    let failed_case = if take_supervisor_bool(remaining, "failed case availability")? {
        let sequence = take_supervisor_u64(remaining, "failed case sequence")?;
        let transition_millis = take_supervisor_u64(remaining, "failed case transition")?;
        Some(CausalFailedCase {
            sequence,
            transition_elapsed: decode_external_supervisor_elapsed(transition_millis),
            target: take_supervisor_optional_text(remaining, "failed case target")?,
            case: take_supervisor_optional_text(remaining, "failed case name")?
                .ok_or_else(|| "nightly supervisor failed case name is unavailable".to_owned())?,
            stream: take_supervisor_optional_text(remaining, "failed case stream")?
                .ok_or_else(|| "nightly supervisor failed case stream is unavailable".to_owned())?,
        })
    } else {
        None
    };
    Ok(failed_case)
}

#[cfg(any(unix, windows))]
struct ExternalSupervisorCleanupOutcome {
    lifecycle: ExternalSupervisorCleanupState,
    cleanup_id: Option<u64>,
    candidate_quiescence_complete: bool,
    state: String,
    error: Option<String>,
    failures: Vec<String>,
    stdout: Option<(u64, Digest, bool)>,
    stderr: Option<(u64, Digest, bool)>,
}

#[cfg(any(unix, windows))]
fn external_supervisor_cleanup_outcome(
    error: &crate::command::CommandRunError,
    deadline: Instant,
) -> ExternalSupervisorCleanupOutcome {
    let mut outcome = ExternalSupervisorCleanupOutcome {
        lifecycle: ExternalSupervisorCleanupState {
            terminal: true,
            termination_requested: false,
            leader_reaped: false,
        },
        cleanup_id: None,
        candidate_quiescence_complete: false,
        state: "completed".to_owned(),
        error: None,
        failures: Vec::new(),
        stdout: None,
        stderr: None,
    };
    if let Some(receipt) = error.retained_cleanup_receipt() {
        outcome.cleanup_id = Some(receipt.id());
        let snapshot = receipt.wait_until(deadline);
        match snapshot.state {
            hell_testkit::RetainedTerminationState::Completed(report) => {
                outcome.lifecycle.termination_requested = report.forced;
                outcome.lifecycle.leader_reaped = report.reaped;
                if !snapshot.lifecycle_idle {
                    outcome.lifecycle.terminal = false;
                    outcome.failures.push(
                        "process:lifecycle-owned: process cleanup completed before its I/O lifecycle became idle".to_owned(),
                    );
                }
            }
            hell_testkit::RetainedTerminationState::Failed(detail) => {
                outcome.lifecycle.terminal = false;
                outcome.failures.push(format!("process:failed: {detail}"));
            }
            hell_testkit::RetainedTerminationState::Owned => {
                outcome.lifecycle.terminal = false;
                outcome
                    .failures
                    .push("process:owned: retained process cleanup remains owned".to_owned());
            }
        }
    }
    if let Some(receipt) = error.supervised_io_receipt() {
        let snapshot = receipt.wait_until(deadline);
        for (label, task) in [
            ("stdout", snapshot.stdout),
            ("stderr", snapshot.stderr),
            ("stdin", snapshot.stdin),
        ] {
            if task.state == hell_testkit::SupervisedIoTaskState::Completed {
                let capture = task
                    .bytes
                    .zip(task.sha256)
                    .zip(task.truncated)
                    .map(|((bytes, sha256), truncated)| (bytes, sha256, truncated));
                match label {
                    "stdout" => outcome.stdout = capture,
                    "stderr" => outcome.stderr = capture,
                    _ => {}
                }
            } else {
                outcome.lifecycle.terminal = false;
                outcome.failures.push(format!(
                    "{label}:{:?}: {}",
                    task.state,
                    task.error.unwrap_or_else(|| "no error detail".to_owned())
                ));
            }
        }
    }
    if let Some(receipt) = error.candidate_quiescence_receipt() {
        match receipt.state() {
            hell_testkit::CandidateQuiescenceState::Completed => {
                outcome.candidate_quiescence_complete = true;
            }
            hell_testkit::CandidateQuiescenceState::Failed(detail) => {
                outcome.lifecycle.terminal = false;
                outcome
                    .failures
                    .push(format!("candidate-quiescence:failed: {detail}"));
            }
            hell_testkit::CandidateQuiescenceState::Owned => {
                outcome.lifecycle.terminal = false;
                outcome.failures.push(
                    "candidate-quiescence:owned: candidate quiescence remains owned".to_owned(),
                );
            }
        }
    }
    if !outcome.failures.is_empty() {
        "failed".clone_into(&mut outcome.state);
        outcome.error = Some(bounded_external_supervisor_detail(
            &outcome.failures.join("; "),
        ));
    }
    outcome
}

#[cfg(unix)]
fn external_supervisor_command(
    request: &ExternalSupervisorRequest,
    request_sha256: Digest,
    timeout: Duration,
) -> Result<CommandSpec, String> {
    if !request.fixture_command {
        return Ok(request.plan.command(&request.root, timeout));
    }
    let gate = request
        .launch_gate
        .ok_or_else(|| "nightly supervisor fixture command has no launch gate".to_owned())?;
    let executable = fs::canonicalize(
        std::env::current_exe()
            .map_err(|error| format!("cannot locate nightly supervisor fixture child: {error}"))?,
    )
    .map_err(|error| format!("cannot canonicalize nightly supervisor fixture child: {error}"))?;
    Ok(CommandSpec::new(executable, timeout).arguments([
        std::ffi::OsString::from("__nightly-supervisor-owned-child"),
        std::ffi::OsString::from(gate.ip().to_string()),
        std::ffi::OsString::from(gate.port().to_string()),
        std::ffi::OsString::from(request_sha256.hex()),
        std::ffi::OsString::from(request.nonce.hex()),
    ]))
}

#[cfg(any(unix, windows))]
fn execute_external_supervisor_command(
    spec: CommandSpec,
    plan: ExternalSupervisorPlan,
    case: &str,
    envelope: SupervisionEnvelope,
    mut publish: impl FnMut(&PortabilityChildProgress) -> bool,
) -> Result<
    (
        Result<crate::command::CommandResult, crate::command::CommandRunError>,
        PortabilityChildProgress,
        hell_testkit::SupervisedProgressLoss,
    ),
    String,
> {
    let worker = attributed_worker_sender()?;
    let permit = PortabilityWorkerPermit::acquire()?;
    let receipt = AttributedWorkerReceipt::new(permit.id);
    let (progress, progress_receiver) =
        SupervisedProgressObserver::bounded(PORTABILITY_PROGRESS_QUEUE_CAPACITY);
    let loss = progress.loss_receipt();
    let (terminal, terminal_receiver) = mpsc::sync_channel(1);
    let worker_receipt = receipt.clone();
    worker
        .send(AttributedWorkerTask {
            spec,
            execution_deadline: envelope.execution,
            child_completion_deadline: envelope.child_completion_deadline,
            progress,
            terminal,
            receipt,
            permit,
        })
        .map_err(|_| "nightly supervisor command executor disconnected before launch".to_owned())?;
    let seed = plan.seed();
    let mut observed = PortabilityChildProgress::seeded("nightly", seed.0, case, seed.2);
    let mut published_sequence = u64::MAX;
    let mut published_frames = 0_u64;
    let mut suppressed_frames = 0_u64;
    loop {
        drain_portability_progress(&progress_receiver, &mut observed, plan.name());
        if observed.sequence != published_sequence {
            if published_frames < NIGHTLY_SUPERVISOR_PROGRESS_FRAME_CAPACITY && publish(&observed) {
                published_frames = published_frames.saturating_add(1);
            } else {
                suppressed_frames = suppressed_frames.saturating_add(1);
            }
            published_sequence = observed.sequence;
        }
        let completion_remaining = envelope
            .child_completion_deadline
            .saturating_duration_since(Instant::now());
        let receive_for = completion_remaining.min(PORTABILITY_PROGRESS_DRAIN_INTERVAL);
        if receive_for.is_zero() {
            let state = worker_receipt.wait_until(envelope.report_completion_deadline);
            if state == AttributedWorkerState::Owned {
                return Err(format!(
                    "nightly supervisor command worker remains externally owned at its report deadline: workerId={}",
                    worker_receipt.id
                ));
            }
            match terminal_receiver.try_recv() {
                Ok(AttributedWorkerTerminal::Complete(result)) => {
                    drain_portability_progress(&progress_receiver, &mut observed, plan.name());
                    let mut loss = loss.snapshot();
                    loss.chunks = loss.chunks.saturating_add(suppressed_frames);
                    return Ok((result, observed, loss));
                }
                Ok(AttributedWorkerTerminal::Panicked) => {
                    let _ = hell_testkit::CleanupLifecycleReceipt::wait_for_all_until(
                        envelope.report_completion_deadline,
                    );
                    return Err(format!(
                        "nightly supervisor command worker panicked after its child completion deadline: workerId={}",
                        worker_receipt.id
                    ));
                }
                Err(error) => {
                    return Err(format!(
                        "nightly supervisor terminal receipt differed after worker terminal: workerId={}, state={state:?}, receipt={error}",
                        worker_receipt.id
                    ));
                }
            }
        }
        match terminal_receiver.recv_timeout(receive_for) {
            Ok(AttributedWorkerTerminal::Complete(result)) => {
                drain_portability_progress(&progress_receiver, &mut observed, plan.name());
                let mut loss = loss.snapshot();
                loss.chunks = loss.chunks.saturating_add(suppressed_frames);
                return Ok((result, observed, loss));
            }
            Ok(AttributedWorkerTerminal::Panicked) => {
                let _ = hell_testkit::CleanupLifecycleReceipt::wait_for_all_until(
                    envelope.report_completion_deadline,
                );
                return Err("nightly supervisor command worker panicked".to_owned());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("nightly supervisor command receipt disconnected".to_owned());
            }
        }
    }
}

#[cfg(any(unix, windows))]
fn bounded_external_supervisor_detail(detail: &str) -> String {
    bounded_external_supervisor_text(detail, NIGHTLY_SUPERVISOR_TERMINAL_LIMIT / 4)
}

#[cfg(any(unix, windows))]
fn bounded_external_supervisor_text(detail: &str, limit: usize) -> String {
    let mut bounded = String::new();
    for character in detail.chars() {
        let character = if character.is_control() {
            '�'
        } else {
            character
        };
        if bounded.len().saturating_add(character.len_utf8()) > limit {
            break;
        }
        bounded.push(character);
    }
    bounded
}

#[cfg(any(unix, windows))]
fn external_supervisor_terminal_from_result(
    result: Result<crate::command::CommandResult, crate::command::CommandRunError>,
    progress: &PortabilityChildProgress,
    loss: hell_testkit::SupervisedProgressLoss,
    cleanup_deadline: Instant,
) -> ExternalSupervisorTerminal {
    let attribution = progress.attribution();
    let failed_case = progress.failed_case.clone();
    match result {
        Ok(result) => external_supervisor_completed_terminal(
            &result,
            progress,
            attribution,
            failed_case,
            loss,
        ),
        Err(error) => external_supervisor_error_terminal(
            &error,
            progress,
            attribution,
            failed_case,
            loss,
            cleanup_deadline,
        ),
    }
}

#[cfg(any(unix, windows))]
fn failed_case_unavailable_reason(
    progress: &PortabilityChildProgress,
    loss: hell_testkit::SupervisedProgressLoss,
    failed_case_present: bool,
) -> Option<String> {
    if failed_case_present {
        None
    } else if progress.case_line_truncated
        || progress.stdout_line_truncated
        || progress.stderr_line_truncated
    {
        Some("authoritative-case-line-truncated".to_owned())
    } else if loss.chunks != 0 || loss.bytes != 0 {
        Some("progress-observation-loss".to_owned())
    } else {
        Some("no-failed-case-observed".to_owned())
    }
}

#[cfg(any(unix, windows))]
fn external_supervisor_completed_terminal(
    result: &crate::command::CommandResult,
    progress: &PortabilityChildProgress,
    attribution: ActivePhaseAttribution,
    failed_case: Option<CausalFailedCase>,
    loss: hell_testkit::SupervisedProgressLoss,
) -> ExternalSupervisorTerminal {
    let success = result.status.success() && !result.timed_out;
    let causal_failed_case = (!success).then_some(failed_case).flatten();
    let base_detail = if success {
        "completed".to_owned()
    } else {
        format!(
            "status {:?}, timed out: {}",
            result.status.code(),
            result.timed_out
        )
    };
    let failed_case_unavailable = (!success)
        .then(|| failed_case_unavailable_reason(progress, loss, causal_failed_case.is_some()))
        .flatten();
    ExternalSupervisorTerminal {
        execution: ExternalSupervisorExecutionState {
            success,
            timed_out: result.timed_out,
        },
        exit_code: result.status.code(),
        stdout_bytes: result.stdout_bytes,
        stdout_sha256: result.stdout_sha256,
        stderr_bytes: result.stderr_bytes,
        stderr_sha256: result.stderr_sha256,
        capture: ExternalSupervisorCaptureState {
            stdout_truncated: result.stdout_truncated,
            stderr_truncated: result.stderr_truncated,
            available: true,
        },
        cleanup: ExternalSupervisorCleanupState {
            terminal: true,
            termination_requested: result.termination.forced,
            leader_reaped: result.termination.reaped,
        },
        cleanup_id: result.termination.cleanup_id,
        candidate_quiescence_complete: result.termination.candidate_quiescence_complete,
        cleanup_state: "completed".to_owned(),
        cleanup_error: None,
        cleanup_failures: Vec::new(),
        detail: causal_failed_case_detail(
            &base_detail,
            causal_failed_case.as_ref(),
            failed_case_unavailable.as_deref(),
        ),
        attribution,
        failed_case: causal_failed_case,
        failed_case_unavailable,
        dropped_chunks: loss.chunks,
        dropped_bytes: loss.bytes,
    }
}

#[cfg(any(unix, windows))]
fn external_supervisor_error_terminal(
    error: &crate::command::CommandRunError,
    progress: &PortabilityChildProgress,
    attribution: ActivePhaseAttribution,
    failed_case: Option<CausalFailedCase>,
    loss: hell_testkit::SupervisedProgressLoss,
    cleanup_deadline: Instant,
) -> ExternalSupervisorTerminal {
    let cleanup = external_supervisor_cleanup_outcome(error, cleanup_deadline);
    let completed = error.completed();
    let stdout = completed
        .map(|result| {
            (
                result.stdout_bytes,
                result.stdout_sha256,
                result.stdout_truncated,
            )
        })
        .or(cleanup.stdout);
    let stderr = completed
        .map(|result| {
            (
                result.stderr_bytes,
                result.stderr_sha256,
                result.stderr_truncated,
            )
        })
        .or(cleanup.stderr);
    let failed_case_unavailable =
        failed_case_unavailable_reason(progress, loss, failed_case.is_some());
    ExternalSupervisorTerminal {
        execution: ExternalSupervisorExecutionState {
            success: false,
            timed_out: error.kind() == std::io::ErrorKind::TimedOut
                || completed.is_some_and(|result| result.timed_out),
        },
        exit_code: completed.and_then(|result| result.status.code()),
        stdout_bytes: stdout.map_or(0, |capture| capture.0),
        stdout_sha256: stdout.map_or_else(Digest::default, |capture| capture.1),
        stderr_bytes: stderr.map_or(0, |capture| capture.0),
        stderr_sha256: stderr.map_or_else(Digest::default, |capture| capture.1),
        capture: ExternalSupervisorCaptureState {
            stdout_truncated: stdout.is_some_and(|capture| capture.2),
            stderr_truncated: stderr.is_some_and(|capture| capture.2),
            available: stdout.is_some() && stderr.is_some(),
        },
        cleanup: ExternalSupervisorCleanupState {
            terminal: cleanup.lifecycle.terminal,
            termination_requested: cleanup.lifecycle.termination_requested
                || completed.is_some_and(|result| result.termination.forced),
            leader_reaped: cleanup.lifecycle.leader_reaped
                || completed.is_some_and(|result| result.termination.reaped),
        },
        cleanup_id: cleanup
            .cleanup_id
            .or_else(|| completed.and_then(|result| result.termination.cleanup_id)),
        candidate_quiescence_complete: cleanup.candidate_quiescence_complete
            || completed.is_some_and(|result| result.termination.candidate_quiescence_complete),
        cleanup_state: cleanup.state,
        cleanup_error: cleanup.error,
        cleanup_failures: cleanup
            .failures
            .into_iter()
            .map(|failure| {
                bounded_external_supervisor_text(&failure, NIGHTLY_SUPERVISOR_TERMINAL_LIMIT / 32)
            })
            .collect(),
        detail: bounded_external_supervisor_detail(&causal_failed_case_detail(
            &error.to_string(),
            failed_case.as_ref(),
            failed_case_unavailable.as_deref(),
        )),
        attribution,
        failed_case,
        failed_case_unavailable,
        dropped_chunks: loss.chunks,
        dropped_bytes: loss.bytes,
    }
}

#[cfg(any(unix, windows))]
fn causal_failed_case_detail(
    base: &str,
    failed_case: Option<&CausalFailedCase>,
    unavailable: Option<&str>,
) -> String {
    if let Some(failed_case) = failed_case {
        format!(
            "{base}; failed case: target={}, case={}, sequence={}, stream={}",
            failed_case.target.as_deref().unwrap_or("unknown"),
            failed_case.case,
            failed_case.sequence,
            failed_case.stream,
        )
    } else if let Some(unavailable) = unavailable {
        format!("{base}; failed case unavailable: {unavailable}")
    } else {
        base.to_owned()
    }
}

#[cfg(any(unix, windows))]
fn apply_terminal_failed_case(
    progress: &mut PortabilityChildProgress,
    terminal: &ExternalSupervisorTerminal,
) {
    progress.failed_case.clone_from(&terminal.failed_case);
    if !terminal.execution.success
        && let Some(failed) = &terminal.failed_case
    {
        progress.target.clone_from(&failed.target);
        progress.case = Some(failed.case.clone());
        progress.case_state = Some(PortabilityCaseState::Failed);
    }
}

#[cfg(any(unix, windows))]
fn external_supervisor_failure_terminal(
    plan: ExternalSupervisorPlan,
    detail: impl AsRef<str>,
    cleanup_terminal: bool,
) -> ExternalSupervisorTerminal {
    let seed = plan.seed();
    ExternalSupervisorTerminal {
        execution: ExternalSupervisorExecutionState {
            success: false,
            timed_out: false,
        },
        exit_code: None,
        stdout_bytes: 0,
        stdout_sha256: Digest::default(),
        stderr_bytes: 0,
        stderr_sha256: Digest::default(),
        capture: ExternalSupervisorCaptureState {
            stdout_truncated: false,
            stderr_truncated: false,
            available: false,
        },
        cleanup: ExternalSupervisorCleanupState {
            terminal: cleanup_terminal,
            termination_requested: false,
            leader_reaped: false,
        },
        cleanup_id: None,
        candidate_quiescence_complete: false,
        cleanup_state: if cleanup_terminal {
            "completed"
        } else {
            "unavailable"
        }
        .to_owned(),
        cleanup_error: (!cleanup_terminal)
            .then(|| "cleanup outcome is unavailable after infrastructure failure".to_owned()),
        cleanup_failures: if cleanup_terminal {
            Vec::new()
        } else {
            vec!["infrastructure: cleanup outcome unavailable".to_owned()]
        },
        detail: bounded_external_supervisor_detail(detail.as_ref()),
        attribution: ActivePhaseAttribution {
            sequence: 1,
            transition_elapsed: None,
            target: Some(seed.0.to_owned()),
            case: Some(seed.1.to_owned()),
            case_state: Some("launch-failed".to_owned()),
            subphase: Some(seed.2.to_owned()),
        },
        failed_case: None,
        failed_case_unavailable: Some("infrastructure-failure-before-case-observation".to_owned()),
        dropped_chunks: 0,
        dropped_bytes: 0,
    }
}

#[cfg(unix)]
fn execute_external_supervisor_plan(
    request: &ExternalSupervisorRequest,
    session: &NightlyFixtureRoot,
    request_sha256: Digest,
    envelope: SupervisionEnvelope,
    started_receipt: &[u8],
    started_path: &Path,
    publish: impl FnMut(&PortabilityChildProgress) -> bool,
) -> ExternalSupervisorTerminal {
    let prelaunch = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        write_create_new_file(started_path, started_receipt)?;
        let timeout = envelope.execution.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            return Err("nightly supervisor execution deadline expired before launch".to_owned());
        }
        session.revalidate_workspace(request)?;
        let spec = external_supervisor_command(request, request_sha256, timeout)?;
        session.revalidate_workspace(request)?;
        Ok::<CommandSpec, String>(spec)
    }));
    let spec = match prelaunch {
        Ok(Ok(spec)) => spec,
        Ok(Err(error)) => return external_supervisor_failure_terminal(request.plan, error, true),
        Err(_) => {
            return external_supervisor_failure_terminal(
                request.plan,
                "nightly supervisor panicked before command launch",
                true,
            );
        }
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        execute_external_supervisor_command(
            spec,
            request.plan,
            if request.fixture_command {
                "external-supervisor-owned-child"
            } else {
                request.plan.seed().1
            },
            envelope,
            publish,
        )
    }));
    match outcome {
        Ok(Ok((result, progress, loss))) => external_supervisor_terminal_from_result(
            result,
            &progress,
            loss,
            envelope.report_completion_deadline,
        ),
        Ok(Err(error)) => external_supervisor_failure_terminal(request.plan, error, false),
        Err(_) => {
            let _ = hell_testkit::CleanupLifecycleReceipt::wait_for_all_until(
                envelope.report_completion_deadline,
            );
            external_supervisor_failure_terminal(
                request.plan,
                "nightly supervisor panicked after accepting command ownership",
                false,
            )
        }
    }
}

#[cfg(unix)]
fn validate_external_supervisor_session(
    request_path: &Path,
    request: &ExternalSupervisorRequest,
) -> Result<NightlyFixtureRoot, String> {
    let session = request_path
        .parent()
        .ok_or_else(|| "nightly supervisor request has no session directory".to_owned())?;
    let metadata = fs::symlink_metadata(session)
        .map_err(|error| format!("cannot inspect nightly supervisor session: {error}"))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || (metadata.dev(), metadata.ino()) != (request.session_device, request.session_inode)
        || metadata.uid() != request.session_uid
        || metadata.mode() & 0o777 != 0o700
    {
        return Err("nightly supervisor session authority differs".to_owned());
    }
    let canonical_root = fs::canonicalize(&request.root)
        .map_err(|error| format!("cannot canonicalize nightly supervisor root: {error}"))?;
    if canonical_root != request.root {
        return Err("nightly supervisor root is not canonical".to_owned());
    }
    let root = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(&request.root)
        .map_err(|error| format!("cannot retain nightly supervisor root: {error}"))?;
    let retained_root = root
        .metadata()
        .map_err(|error| format!("cannot bind nightly supervisor root: {error}"))?;
    let root_path = fs::symlink_metadata(&request.root)
        .map_err(|error| format!("cannot revalidate nightly supervisor root path: {error}"))?;
    if (retained_root.dev(), retained_root.ino()) != (request.root_device, request.root_inode)
        || (root_path.dev(), root_path.ino()) != (request.root_device, request.root_inode)
        || retained_root.uid() != request.root_uid
        || retained_root.mode() != request.root_mode
        || !retained_root.is_dir()
        || root_path.file_type().is_symlink()
    {
        return Err("nightly supervisor workspace receipt differs before spawn".to_owned());
    }
    let mut session = NightlyFixtureRoot::bind_existing(
        session,
        (request.session_device, request.session_inode),
        request.session_uid,
    )?;
    session.retain_workspace(root);
    Ok(session)
}

#[cfg(unix)]
pub(crate) fn run_external_nightly_supervisor(
    arguments: &[std::ffi::OsString],
) -> Result<(), String> {
    nix::unistd::setsid()
        .map_err(|error| format!("cannot isolate nightly command supervisor session: {error}"))?;
    let LoadedExternalSupervisor {
        request_path,
        expected_digest,
        request,
        session,
    } = load_external_supervisor(arguments)?;
    let mut finalizer_deadline = Instant::now()
        .checked_add(NIGHTLY_SUPERVISOR_START_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let mut session_closed = false;
    let mut terminal_receipt_persisted = false;
    let mut terminal_receipt_acknowledged = false;
    let primary = (|| -> Result<(), String> {
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        let mut control_input = stdin.lock();
        let mut control_output = stdout.lock();
        let startup = authorize_external_supervisor_start(
            &mut control_input,
            &mut control_output,
            &request_path,
            expected_digest,
            &request,
            finalizer_deadline,
        )?;
        let envelope = startup.envelope;
        finalizer_deadline = envelope.report_completion_deadline;
        let terminal = execute_and_persist_external_supervisor_terminal(
            &mut control_output,
            &request_path,
            expected_digest,
            &request,
            &session,
            envelope,
            &startup,
        )?;
        terminal_receipt_persisted = terminal.persisted;
        match request.fixture_control {
            ExternalSupervisorFixtureControl::Normal => {}
            ExternalSupervisorFixtureControl::CloseBeforeTerminal => return Ok(()),
            ExternalSupervisorFixtureControl::FailBeforeTerminal => {
                return Err("injected nightly supervisor pre-terminal failure".to_owned());
            }
        }
        let acknowledgement = publish_external_supervisor_terminal(
            &mut control_input,
            &mut control_output,
            expected_digest,
            &request,
            &session,
            envelope,
            &terminal,
        )?;
        terminal_receipt_acknowledged = acknowledgement.acknowledged;
        session_closed = acknowledgement.session_closed;
        acknowledgement.completion?;
        Ok(())
    })();
    let cleanup =
        if session_closed || (terminal_receipt_persisted && !terminal_receipt_acknowledged) {
            Ok(())
        } else {
            session.close_until(finalizer_deadline)
        };
    match (primary, cleanup) {
        (Ok(()), Ok(())) => std::process::exit(0),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(format!(
            "{primary}; supervisor session cleanup also failed: {cleanup}"
        )),
    }
}

#[cfg(unix)]
struct LoadedExternalSupervisor {
    request_path: PathBuf,
    expected_digest: Digest,
    request: ExternalSupervisorRequest,
    session: NightlyFixtureRoot,
}

#[cfg(unix)]
fn load_external_supervisor(
    arguments: &[std::ffi::OsString],
) -> Result<LoadedExternalSupervisor, String> {
    let [
        request_path,
        expected_digest,
        request_device,
        request_inode,
        request_uid,
        request_mode,
        request_length,
    ] = arguments
    else {
        return Err(
            "nightly command supervisor requires request path, digest, and receipt".to_owned(),
        );
    };
    let request_path = PathBuf::from(request_path);
    let parse_receipt = |value: &std::ffi::OsStr, field: &str| {
        value
            .to_str()
            .ok_or_else(|| format!("nightly supervisor {field} is not UTF-8"))?
            .parse::<u64>()
            .map_err(|error| format!("nightly supervisor {field} is invalid: {error}"))
    };
    let request_device = parse_receipt(request_device, "request device")?;
    let request_inode = parse_receipt(request_inode, "request inode")?;
    let request_uid = parse_receipt(request_uid, "request uid")?;
    let request_mode = parse_receipt(request_mode, "request mode")?;
    let request_length = parse_receipt(request_length, "request length")?;
    let expected_digest = expected_digest
        .to_str()
        .ok_or_else(|| "nightly supervisor request digest is not UTF-8".to_owned())?;
    let expected_digest = Digest::from_hex(expected_digest)
        .map_err(|error| format!("nightly supervisor request digest is invalid: {error}"))?;
    let mut request_handle = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&request_path)
        .map_err(|error| format!("cannot retain nightly supervisor request: {error}"))?;
    let request_metadata = request_handle
        .metadata()
        .map_err(|error| format!("cannot bind nightly supervisor request: {error}"))?;
    let request_path_metadata = fs::symlink_metadata(&request_path)
        .map_err(|error| format!("cannot revalidate nightly supervisor request: {error}"))?;
    if (request_metadata.dev(), request_metadata.ino()) != (request_device, request_inode)
        || (request_path_metadata.dev(), request_path_metadata.ino())
            != (request_device, request_inode)
        || u64::from(request_metadata.uid()) != request_uid
        || u64::from(request_metadata.mode()) != request_mode
        || request_metadata.len() != request_length
        || !request_metadata.is_file()
        || request_path_metadata.file_type().is_symlink()
    {
        return Err("nightly supervisor request receipt differs".to_owned());
    }
    let request_bytes = read_bounded_handle(
        &mut request_handle,
        &request_path,
        NIGHTLY_SUPERVISOR_REQUEST_LIMIT,
    )?;
    if sha256_bytes(&request_bytes) != expected_digest {
        return Err("nightly supervisor request digest differs".to_owned());
    }
    let request = decode_external_supervisor_request(&request_bytes)?;
    let session = validate_external_supervisor_session(&request_path, &request)?;
    Ok(LoadedExternalSupervisor {
        request_path,
        expected_digest,
        request,
        session,
    })
}

#[cfg(unix)]
struct ExternalSupervisorStartup {
    envelope: SupervisionEnvelope,
    started_path: PathBuf,
    started_receipt: Vec<u8>,
}

#[cfg(unix)]
fn authorize_external_supervisor_start(
    control_input: &mut std::io::StdinLock<'_>,
    control_output: &mut std::io::StdoutLock<'_>,
    request_path: &Path,
    expected_digest: Digest,
    request: &ExternalSupervisorRequest,
    finalizer_deadline: Instant,
) -> Result<ExternalSupervisorStartup, String> {
    let startup_deadline = finalizer_deadline
        .checked_sub(NIGHTLY_SUPERVISOR_START_CLEANUP_RESERVE)
        .unwrap_or_else(Instant::now);
    write_supervisor_handshake(
        control_output,
        ExternalSupervisorMessage::Ready,
        expected_digest,
        request.nonce,
    )?;
    if !read_supervisor_handshake_until(
        control_input,
        ExternalSupervisorMessage::Go,
        expected_digest,
        request.nonce,
        startup_deadline,
    )? {
        return Err(
            "nightly supervisor start authorization exceeded its startup deadline".to_owned(),
        );
    }
    let started = Instant::now();
    write_supervisor_handshake(
        control_output,
        ExternalSupervisorMessage::Started,
        expected_digest,
        request.nonce,
    )?;
    let envelope = read_supervisor_budget(control_input, started, startup_deadline)?;
    if envelope
        .report_completion_deadline
        .saturating_duration_since(started)
        > request.plan.total()
    {
        return Err("nightly supervisor budget exceeds its named plan total".to_owned());
    }
    write_supervisor_handshake(
        control_output,
        ExternalSupervisorMessage::Ready,
        expected_digest,
        request.nonce,
    )?;
    if !read_supervisor_handshake_until(
        control_input,
        ExternalSupervisorMessage::Go,
        expected_digest,
        request.nonce,
        startup_deadline,
    )? {
        return Err(
            "nightly supervisor launch authorization exceeded its startup deadline".to_owned(),
        );
    }
    let started_path = request_path.with_file_name("started.receipt");
    let mut started_receipt = supervisor_handshake_bytes(
        ExternalSupervisorMessage::Started,
        expected_digest,
        request.nonce,
    );
    for (deadline, field) in [
        (envelope.execution, "execution"),
        (envelope.child_completion_deadline, "cleanup"),
        (envelope.report_completion_deadline, "report"),
    ] {
        push_supervisor_u64(
            &mut started_receipt,
            duration_millis(deadline.saturating_duration_since(started), field)?,
        );
    }
    Ok(ExternalSupervisorStartup {
        envelope,
        started_path,
        started_receipt,
    })
}

#[cfg(unix)]
struct ExternalSupervisorTerminalReceipt {
    bytes: Vec<u8>,
    progress_channel_usable: bool,
    persisted: bool,
}

#[cfg(unix)]
fn execute_and_persist_external_supervisor_terminal(
    control_output: &mut std::io::StdoutLock<'_>,
    request_path: &Path,
    expected_digest: Digest,
    request: &ExternalSupervisorRequest,
    session: &NightlyFixtureRoot,
    envelope: SupervisionEnvelope,
    startup: &ExternalSupervisorStartup,
) -> Result<ExternalSupervisorTerminalReceipt, String> {
    let progress_nonblocking = set_supervisor_nonblocking(control_output, true);
    let mut progress_channel_usable = progress_nonblocking.is_ok();
    let mut terminal = match progress_nonblocking.as_ref() {
        Ok(()) => execute_external_supervisor_plan(
            request,
            session,
            expected_digest,
            envelope,
            &startup.started_receipt,
            &startup.started_path,
            |progress| {
                if let Ok(published) = try_write_external_supervisor_progress(
                    control_output,
                    expected_digest,
                    request.nonce,
                    progress,
                ) {
                    published
                } else {
                    progress_channel_usable = false;
                    false
                }
            },
        ),
        Err(error) => external_supervisor_failure_terminal(request.plan, error, true),
    };
    if progress_nonblocking.is_ok()
        && let Err(error) = set_supervisor_nonblocking(control_output, false)
    {
        terminal = external_supervisor_failure_terminal(
            request.plan,
            format!(
                "{}; progress relay pipe restoration failed: {error}",
                terminal.detail
            ),
            terminal.cleanup.terminal,
        );
    }
    let mut bytes = encode_external_supervisor_terminal(expected_digest, request.nonce, &terminal)?;
    let persisted =
        match write_create_new_file(&request_path.with_file_name("terminal.receipt"), &bytes) {
            Ok(()) => true,
            Err(error) => {
                terminal = external_supervisor_failure_terminal(
                    request.plan,
                    format!("{}; terminal receipt unavailable: {error}", terminal.detail),
                    terminal.cleanup.terminal,
                );
                bytes =
                    encode_external_supervisor_terminal(expected_digest, request.nonce, &terminal)?;
                false
            }
        };
    Ok(ExternalSupervisorTerminalReceipt {
        bytes,
        progress_channel_usable,
        persisted,
    })
}

#[cfg(unix)]
struct ExternalSupervisorTerminalAcknowledgement {
    acknowledged: bool,
    session_closed: bool,
    completion: Result<(), String>,
}

#[cfg(unix)]
fn publish_external_supervisor_terminal(
    control_input: &mut std::io::StdinLock<'_>,
    control_output: &mut std::io::StdoutLock<'_>,
    expected_digest: Digest,
    request: &ExternalSupervisorRequest,
    session: &NightlyFixtureRoot,
    envelope: SupervisionEnvelope,
    terminal: &ExternalSupervisorTerminalReceipt,
) -> Result<ExternalSupervisorTerminalAcknowledgement, String> {
    let acknowledged = if let Some(observer) = request.terminal_observer {
        let connect_timeout = envelope
            .report_completion_deadline
            .saturating_duration_since(Instant::now());
        if connect_timeout.is_zero() {
            return Ok(ExternalSupervisorTerminalAcknowledgement {
                acknowledged: false,
                session_closed: false,
                completion: Ok(()),
            });
        }
        let mut observer =
            TcpStream::connect_timeout(&std::net::SocketAddr::V4(observer), connect_timeout)
                .map_err(|error| format!("cannot connect nightly terminal observer: {error}"))?;
        write_supervisor_handshake(
            &mut observer,
            ExternalSupervisorMessage::Terminal,
            expected_digest,
            request.nonce,
        )?;
        write_supervisor_terminal_payload(&mut observer, &terminal.bytes)?;
        if !read_supervisor_handshake_until(
            &mut observer,
            ExternalSupervisorMessage::Go,
            expected_digest,
            request.nonce,
            envelope.report_completion_deadline,
        )? {
            return Ok(ExternalSupervisorTerminalAcknowledgement {
                acknowledged: false,
                session_closed: false,
                completion: Ok(()),
            });
        }
        session.close_until(envelope.report_completion_deadline)?;
        let completion = write_supervisor_handshake(
            &mut observer,
            ExternalSupervisorMessage::Ready,
            expected_digest,
            request.nonce,
        );
        return Ok(ExternalSupervisorTerminalAcknowledgement {
            acknowledged: true,
            session_closed: true,
            completion,
        });
    } else if terminal.progress_channel_usable
        && write_supervisor_handshake(
            control_output,
            ExternalSupervisorMessage::Terminal,
            expected_digest,
            request.nonce,
        )
        .and_then(|()| write_supervisor_terminal_payload(control_output, &terminal.bytes))
        .is_ok()
    {
        if !read_supervisor_handshake_until(
            control_input,
            ExternalSupervisorMessage::Go,
            expected_digest,
            request.nonce,
            envelope.report_completion_deadline,
        )? {
            return Ok(ExternalSupervisorTerminalAcknowledgement {
                acknowledged: false,
                session_closed: false,
                completion: Ok(()),
            });
        }
        session.close_until(envelope.report_completion_deadline)?;
        let completion = write_supervisor_handshake(
            control_output,
            ExternalSupervisorMessage::Ready,
            expected_digest,
            request.nonce,
        );
        return Ok(ExternalSupervisorTerminalAcknowledgement {
            acknowledged: true,
            session_closed: true,
            completion,
        });
    } else {
        false
    };
    Ok(ExternalSupervisorTerminalAcknowledgement {
        acknowledged,
        session_closed: acknowledged,
        completion: Ok(()),
    })
}

#[cfg(unix)]
fn close_failed_external_supervisor_start(
    primary: String,
    mut child: Option<std::process::Child>,
    session: NightlyFixtureRoot,
) -> Result<ExternalSupervisorStarted, String> {
    let process_cleanup = child.as_mut().map_or(Ok(()), |child| {
        child
            .kill()
            .or_else(|error| {
                child
                    .try_wait()
                    .and_then(|status| status.map_or(Err(error), |_| Ok(())))
            })
            .and_then(|()| {
                child.try_wait().and_then(|status| {
                    status.map_or_else(
                        || {
                            Err(std::io::Error::other(
                                "failed nightly supervisor exit is not yet observable after SIGKILL; no retained userspace exit receipt exists and kernel reparenting will own reap when the reporter exits",
                            ))
                        },
                        |_| Ok(()),
                    )
                })
            })
            .map_err(|error| format!("cannot terminate failed nightly supervisor: {error}"))
    });
    let session_cleanup = session.close();
    match (process_cleanup, session_cleanup) {
        (Ok(()), Ok(())) => Err(primary),
        (process, session) => Err(format!(
            "{primary}; nightly supervisor cleanup failed: process={process:?}; session={session:?}"
        )),
    }
}

#[cfg(unix)]
fn start_external_nightly_supervisor(
    root: &Path,
    session_parent: &Path,
    plan: ExternalSupervisorPlan,
    phase_started: Instant,
    outer_deadline: Instant,
) -> Result<ExternalSupervisorStarted, String> {
    start_external_nightly_supervisor_with_policy(
        root,
        plan,
        phase_started,
        outer_deadline,
        &ExternalSupervisorStartPolicy {
            total: plan.total(),
            cleanup_reserve: NIGHTLY_COMMAND_CLEANUP_RESERVE,
            report_reserve: NIGHTLY_REPORT_RESERVE,
            terminal_observer: None,
            launch_gate: None,
            fixture_command: false,
            fixture_control: ExternalSupervisorFixtureControl::Normal,
            session_parent: session_parent.to_owned(),
        },
    )
}

#[cfg(unix)]
fn start_external_nightly_supervisor_with_policy(
    root: &Path,
    plan: ExternalSupervisorPlan,
    phase_started: Instant,
    outer_deadline: Instant,
    policy: &ExternalSupervisorStartPolicy,
) -> Result<ExternalSupervisorStarted, String> {
    static SESSION_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    let session = NightlyFixtureRoot::create_in(
        &policy.session_parent,
        SESSION_SEQUENCE.fetch_add(1, Ordering::Relaxed),
    )?;
    let prepared = match prepare_external_supervisor_request(root, plan, policy, &session) {
        Ok(prepared) => prepared,
        Err(error) => return close_failed_external_supervisor_start(error, None, session),
    };
    let request = prepared.request;
    let spawn = match prepare_external_supervisor_spawn(&session, &request) {
        Ok(spawn) => spawn,
        Err(error) => return close_failed_external_supervisor_start(error, None, session),
    };
    let request_sha256 = spawn.request_sha256;
    let request_path = spawn.request_path;
    let request_handle = spawn.request_handle;
    let request_metadata = spawn.request_metadata;
    let executable = spawn.executable;
    let executable_identity = spawn.executable_identity;
    let exit_waiter = spawn.exit_waiter;
    let mut child = match NativeProcessSpec::new(&executable)
        .argument("__release-command-supervisor-v1")
        .argument(&request_path)
        .argument(request_sha256.hex())
        .argument(request_metadata.dev().to_string())
        .argument(request_metadata.ino().to_string())
        .argument(request_metadata.uid().to_string())
        .argument(request_metadata.mode().to_string())
        .argument(request_metadata.len().to_string())
        .stdin(NativeStdio::Piped)
        .stdout(NativeStdio::Piped)
        .stderr(NativeStdio::Null)
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return close_failed_external_supervisor_start(
                format!("cannot start nightly command supervisor: {error}"),
                None,
                session,
            );
        }
    };
    if let Err(error) = verify_external_supervisor_executable(&executable, &executable_identity) {
        return close_failed_external_supervisor_start(error, Some(child), session);
    }
    let Some(mut control_input) = child.stdin.take() else {
        return close_failed_external_supervisor_start(
            "nightly supervisor stdin pipe is unavailable".to_owned(),
            Some(child),
            session,
        );
    };
    let Some(mut control_output) = child.stdout.take() else {
        return close_failed_external_supervisor_start(
            "nightly supervisor stdout pipe is unavailable".to_owned(),
            Some(child),
            session,
        );
    };
    let envelope = match complete_external_supervisor_start_handshake(
        &mut control_input,
        &mut control_output,
        ExternalSupervisorStartHandshake {
            request: &request,
            request_sha256,
            request_handle,
            phase_started,
            outer_deadline,
            policy,
        },
    ) {
        Ok(envelope) => envelope,
        Err(error) => return close_failed_external_supervisor_start(error, Some(child), session),
    };
    let exit = match exit_waiter.transfer(child) {
        Ok(exit) => exit,
        Err((error, child)) => {
            return close_failed_external_supervisor_start(error, Some(child), session);
        }
    };
    let launch_ownership_uncertain = write_supervisor_handshake(
        &mut control_input,
        ExternalSupervisorMessage::Go,
        request_sha256,
        request.nonce,
    )
    .err();
    Ok(ExternalSupervisorStarted {
        exit,
        control_input,
        control_output,
        session,
        request_sha256,
        nonce: request.nonce,
        envelope,
        launch_ownership_uncertain,
    })
}

#[cfg(unix)]
fn verify_external_supervisor_executable(
    executable: &Path,
    expected: &fs::Metadata,
) -> Result<(), String> {
    let observed = fs::symlink_metadata(executable)
        .map_err(|error| format!("cannot revalidate nightly supervisor executable: {error}"))?;
    if (observed.dev(), observed.ino()) == (expected.dev(), expected.ino()) {
        Ok(())
    } else {
        Err("nightly supervisor executable changed across spawn".to_owned())
    }
}

#[cfg(unix)]
struct ExternalSupervisorStartHandshake<'a> {
    request: &'a ExternalSupervisorRequest,
    request_sha256: Digest,
    request_handle: fs::File,
    phase_started: Instant,
    outer_deadline: Instant,
    policy: &'a ExternalSupervisorStartPolicy,
}

#[cfg(unix)]
fn complete_external_supervisor_start_handshake(
    control_input: &mut std::process::ChildStdin,
    control_output: &mut std::process::ChildStdout,
    handshake: ExternalSupervisorStartHandshake<'_>,
) -> Result<SupervisionEnvelope, String> {
    let phase_completion_deadline = handshake
        .phase_started
        .checked_add(handshake.policy.total)
        .ok_or_else(|| "nightly supervisor phase deadline overflowed".to_owned())?
        .min(handshake.outer_deadline);
    let startup_deadline = Instant::now()
        .checked_add(NIGHTLY_SUPERVISOR_START_TIMEOUT)
        .unwrap_or(phase_completion_deadline)
        .min(phase_completion_deadline);
    require_external_supervisor_handshake(
        control_output,
        ExternalSupervisorMessage::Ready,
        handshake.request_sha256,
        handshake.request.nonce,
        startup_deadline,
        "nightly supervisor Ready handshake exceeded its startup deadline",
    )?;
    drop(handshake.request_handle);
    write_supervisor_handshake(
        control_input,
        ExternalSupervisorMessage::Go,
        handshake.request_sha256,
        handshake.request.nonce,
    )?;
    require_external_supervisor_handshake(
        control_output,
        ExternalSupervisorMessage::Started,
        handshake.request_sha256,
        handshake.request.nonce,
        startup_deadline,
        "nightly supervisor Started handshake exceeded its startup deadline",
    )?;
    let observed_started = Instant::now();
    let envelope = SupervisionEnvelope::within(
        handshake.phase_started,
        handshake.policy.total,
        handshake.policy.cleanup_reserve,
        handshake.policy.report_reserve,
        handshake.outer_deadline,
    )?;
    write_supervisor_budget(control_input, envelope, observed_started)?;
    require_external_supervisor_handshake(
        control_output,
        ExternalSupervisorMessage::Ready,
        handshake.request_sha256,
        handshake.request.nonce,
        startup_deadline,
        "nightly supervisor launch admission exceeded its startup deadline",
    )?;
    Ok(envelope)
}

#[cfg(unix)]
fn require_external_supervisor_handshake(
    control_output: &mut std::process::ChildStdout,
    expected: ExternalSupervisorMessage,
    request_sha256: Digest,
    nonce: Digest,
    deadline: Instant,
    deadline_error: &str,
) -> Result<(), String> {
    match read_supervisor_handshake_until(control_output, expected, request_sha256, nonce, deadline)
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(deadline_error.to_owned()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
struct PreparedExternalSupervisorRequest {
    request: ExternalSupervisorRequest,
    _root_handle: fs::File,
}

#[cfg(unix)]
struct PreparedExternalSupervisorSpawn {
    request_sha256: Digest,
    request_path: PathBuf,
    request_handle: fs::File,
    request_metadata: fs::Metadata,
    executable: PathBuf,
    _executable_handle: fs::File,
    executable_identity: fs::Metadata,
    exit_waiter: ExternalSupervisorExitWaiter,
}

#[cfg(unix)]
fn prepare_external_supervisor_spawn(
    session: &NightlyFixtureRoot,
    request: &ExternalSupervisorRequest,
) -> Result<PreparedExternalSupervisorSpawn, String> {
    let request_bytes = encode_external_supervisor_request(request)?;
    let request_sha256 = sha256_bytes(&request_bytes);
    let request_path = session.path().join("request.bin");
    write_create_new_file(&request_path, &request_bytes)?;
    let request_handle = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&request_path)
        .map_err(|error| format!("cannot retain nightly supervisor request: {error}"))?;
    let request_metadata = request_handle
        .metadata()
        .map_err(|error| format!("cannot bind nightly supervisor request: {error}"))?;
    let executable = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|error| format!("cannot bind nightly supervisor executable: {error}"))?;
    let executable_handle = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&executable)
        .map_err(|error| format!("cannot retain nightly supervisor executable: {error}"))?;
    let executable_identity = executable_handle
        .metadata()
        .map_err(|error| format!("cannot inspect retained nightly supervisor: {error}"))?;
    Ok(PreparedExternalSupervisorSpawn {
        request_sha256,
        request_path,
        request_handle,
        request_metadata,
        executable,
        _executable_handle: executable_handle,
        executable_identity,
        exit_waiter: ExternalSupervisorExitWaiter::prepare()?,
    })
}

#[cfg(unix)]
fn prepare_external_supervisor_request(
    root: &Path,
    plan: ExternalSupervisorPlan,
    policy: &ExternalSupervisorStartPolicy,
    session: &NightlyFixtureRoot,
) -> Result<PreparedExternalSupervisorRequest, String> {
    let root = fs::canonicalize(root)
        .map_err(|error| format!("cannot canonicalize nightly supervisor workspace: {error}"))?;
    let root_handle = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(&root)
        .map_err(|error| format!("cannot retain nightly supervisor workspace: {error}"))?;
    let root_metadata = root_handle
        .metadata()
        .map_err(|error| format!("cannot bind nightly supervisor workspace: {error}"))?;
    let session_uid = session
        .root
        .metadata()
        .map_err(|error| format!("cannot bind nightly supervisor session owner: {error}"))?
        .uid();
    Ok(PreparedExternalSupervisorRequest {
        request: ExternalSupervisorRequest {
            plan,
            root,
            root_device: root_metadata.dev(),
            root_inode: root_metadata.ino(),
            root_uid: root_metadata.uid(),
            root_mode: root_metadata.mode(),
            nonce: supervisor_nonce(),
            session_device: session.root_identity.0,
            session_inode: session.root_identity.1,
            session_uid,
            terminal_observer: policy.terminal_observer,
            launch_gate: policy.launch_gate,
            fixture_command: policy.fixture_command,
            fixture_control: policy.fixture_control,
        },
        _root_handle: root_handle,
    })
}

#[cfg(any(unix, windows))]
fn parse_loopback_address(
    address: &std::ffi::OsStr,
    port: &std::ffi::OsStr,
) -> Result<SocketAddrV4, String> {
    let address = address
        .to_str()
        .ok_or_else(|| "nightly supervisor fixture address is not UTF-8".to_owned())?
        .parse::<Ipv4Addr>()
        .map_err(|error| format!("nightly supervisor fixture address is invalid: {error}"))?;
    let port = port
        .to_str()
        .ok_or_else(|| "nightly supervisor fixture port is not UTF-8".to_owned())?
        .parse::<u16>()
        .map_err(|error| format!("nightly supervisor fixture port is invalid: {error}"))?;
    if !address.is_loopback() {
        return Err("nightly supervisor fixture address is not loopback".to_owned());
    }
    Ok(SocketAddrV4::new(address, port))
}

#[cfg(unix)]
fn encode_external_supervisor_session(
    started: &ExternalSupervisorStarted,
) -> Result<Vec<u8>, String> {
    let path = started.session.path().as_os_str().as_bytes();
    let path_length = u32::try_from(path.len())
        .map_err(|_| "nightly supervisor session path is too long".to_owned())?;
    let mut bytes = Vec::with_capacity(path.len() + 96);
    bytes.extend_from_slice(NIGHTLY_SUPERVISOR_PROTOCOL_MAGIC);
    push_supervisor_u32(&mut bytes, path_length);
    bytes.extend_from_slice(path);
    push_supervisor_u32(&mut bytes, started.pid());
    bytes.extend_from_slice(&started.request_sha256.0);
    bytes.extend_from_slice(&started.nonce.0);
    Ok(bytes)
}

#[cfg(unix)]
fn decode_external_supervisor_session(
    bytes: &[u8],
) -> Result<(PathBuf, u32, Digest, Digest), String> {
    let mut remaining = bytes;
    if take_supervisor_bytes(
        &mut remaining,
        NIGHTLY_SUPERVISOR_PROTOCOL_MAGIC.len(),
        "session magic",
    )? != NIGHTLY_SUPERVISOR_PROTOCOL_MAGIC
    {
        return Err("nightly supervisor session message has invalid magic".to_owned());
    }
    let path_length = usize::try_from(take_supervisor_u32(&mut remaining, "session path length")?)
        .map_err(|_| "nightly supervisor session path length is not representable".to_owned())?;
    let path = PathBuf::from(std::ffi::OsString::from_vec(
        take_supervisor_bytes(&mut remaining, path_length, "session path")?.to_vec(),
    ));
    let pid = take_supervisor_u32(&mut remaining, "supervisor pid")?;
    let request_sha256 = Digest(
        take_supervisor_bytes(&mut remaining, Digest::default().0.len(), "request digest")?
            .try_into()
            .map_err(|_| "nightly supervisor request digest width drifted".to_owned())?,
    );
    let nonce = Digest(
        take_supervisor_bytes(&mut remaining, Digest::default().0.len(), "session nonce")?
            .try_into()
            .map_err(|_| "nightly supervisor session nonce width drifted".to_owned())?,
    );
    if !remaining.is_empty() {
        return Err("nightly supervisor session message has trailing bytes".to_owned());
    }
    Ok((path, pid, request_sha256, nonce))
}

#[cfg(unix)]
pub(crate) fn run_external_supervisor_reporter_fixture(
    arguments: &[std::ffi::OsString],
) -> Result<(), String> {
    let [
        root,
        observer_address,
        observer_port,
        gate_address,
        gate_port,
    ] = arguments
    else {
        return Err(
            "nightly supervisor reporter fixture requires root and two loopback addresses"
                .to_owned(),
        );
    };
    let observer = parse_loopback_address(observer_address, observer_port)?;
    let gate = parse_loopback_address(gate_address, gate_port)?;
    let total = Duration::from_mins(5);
    let started = start_external_nightly_supervisor_with_policy(
        Path::new(root),
        ExternalSupervisorPlan::NightlyCoreData,
        Instant::now(),
        Instant::now()
            .checked_add(total)
            .ok_or_else(|| "nightly supervisor fixture deadline overflowed".to_owned())?,
        &ExternalSupervisorStartPolicy {
            total,
            cleanup_reserve: Duration::from_mins(1),
            report_reserve: Duration::from_secs(30),
            terminal_observer: Some(observer),
            launch_gate: Some(gate),
            fixture_command: true,
            fixture_control: ExternalSupervisorFixtureControl::Normal,
            session_parent: std::env::temp_dir(),
        },
    )?;
    let session = encode_external_supervisor_session(&started)?;
    let mut observer = TcpStream::connect(observer)
        .map_err(|error| format!("cannot connect nightly reporter observer: {error}"))?;
    let mut framed = Vec::with_capacity(size_of::<u32>() + session.len());
    push_supervisor_u32(
        &mut framed,
        u32::try_from(session.len())
            .map_err(|_| "nightly session message is too long".to_owned())?,
    );
    framed.extend_from_slice(&session);
    observer
        .write_all(&framed)
        .map_err(|error| format!("cannot publish nightly supervisor session: {error}"))?;
    read_supervisor_handshake(
        &mut observer,
        ExternalSupervisorMessage::Go,
        started.request_sha256,
        started.nonce,
    )
}

#[cfg(any(unix, windows))]
pub(crate) fn run_external_supervisor_owned_child(
    arguments: &[std::ffi::OsString],
) -> Result<(), String> {
    #[cfg(unix)]
    let [address, port, request_sha256, nonce] = arguments else {
        return Err("nightly supervisor owned child requires gate and receipt binding".to_owned());
    };
    #[cfg(windows)]
    let [
        address,
        port,
        request_sha256,
        nonce,
        session_path,
        writable_target,
        supervisor_pid,
    ] = arguments
    else {
        return Err(
            "nightly supervisor owned child requires gate, receipt, session, and target binding"
                .to_owned(),
        );
    };
    let gate = parse_loopback_address(address, port)?;
    let request_sha256 = request_sha256
        .to_str()
        .ok_or_else(|| "nightly owned child request digest is not UTF-8".to_owned())?;
    let request_sha256 = Digest::from_hex(request_sha256)
        .map_err(|error| format!("nightly owned child request digest is invalid: {error}"))?;
    let nonce = nonce
        .to_str()
        .ok_or_else(|| "nightly owned child nonce is not UTF-8".to_owned())?;
    let nonce = Digest::from_hex(nonce)
        .map_err(|error| format!("nightly owned child nonce is invalid: {error}"))?;
    let executable = fs::canonicalize(
        std::env::current_exe()
            .map_err(|error| format!("cannot locate nightly owned grandchild: {error}"))?,
    )
    .map_err(|error| format!("cannot canonicalize nightly owned grandchild: {error}"))?;
    let mut grandchild = NativeProcessSpec::new(executable)
        .argument("__nightly-supervisor-owned-grandchild")
        .stdin(NativeStdio::Piped)
        .stdout(NativeStdio::Null)
        .stderr(NativeStdio::Null)
        .spawn()
        .map_err(|error| format!("cannot start nightly owned grandchild: {error}"))?;
    let mut grandchild_input = grandchild
        .stdin
        .take()
        .ok_or_else(|| "nightly owned grandchild stdin is unavailable".to_owned())?;
    let mut gate = TcpStream::connect(gate)
        .map_err(|error| format!("cannot connect nightly owned child gate: {error}"))?;
    write_supervisor_handshake(
        &mut gate,
        ExternalSupervisorMessage::Started,
        request_sha256,
        nonce,
    )?;
    gate.write_all(&std::process::id().to_be_bytes())
        .and_then(|()| gate.write_all(&grandchild.id().to_be_bytes()))
        .map_err(|error| format!("cannot publish nightly owned process ids: {error}"))?;
    #[cfg(windows)]
    publish_windows_owned_child_receipt(
        &mut gate,
        Path::new(session_path),
        Path::new(writable_target),
        supervisor_pid,
    )?;
    read_supervisor_handshake(
        &mut gate,
        ExternalSupervisorMessage::Go,
        request_sha256,
        nonce,
    )?;
    grandchild_input
        .write_all(&[ExternalSupervisorMessage::Go as u8])
        .map_err(|error| format!("cannot release nightly owned grandchild: {error}"))?;
    let status = grandchild
        .wait()
        .map_err(|error| format!("cannot reap nightly owned grandchild: {error}"))?;
    if !status.success() {
        return Err(format!(
            "nightly owned grandchild failed with status {:?}",
            status.code()
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn publish_windows_owned_child_receipt(
    gate: &mut TcpStream,
    session_path: &Path,
    writable_target: &Path,
    supervisor_pid: &std::ffi::OsStr,
) -> Result<(), String> {
    let token = windows_owned_child_token_receipt()?;
    let session = windows_owned_child_session_receipt(session_path);
    let process = windows_owned_child_process_receipt(
        &session_path.join("ownership.receipt"),
        writable_target,
        supervisor_pid,
    )?;
    let receipt = [
        token[0], token[1], token[2], session[0], session[1], session[2], session[3], session[4],
        process[0], process[1], process[2], process[3],
    ];
    gate.write_all(&receipt)
        .map_err(|error| format!("cannot publish nightly payload token receipt: {error}"))
}

#[cfg(windows)]
fn windows_owned_child_token_receipt() -> Result<[u8; 3], String> {
    let token =
        firehazard::open_process_token(firehazard::get_current_process(), firehazard::token::QUERY)
            .map_err(|error| format!("cannot inspect nightly payload token: {error:?}"))?;
    let authenticated_users = firehazard::convert_string_sid_to_sid_a("S-1-5-11")
        .map_err(|error| format!("cannot bind authenticated-users SID: {error:?}"))?;
    let restricted_code = firehazard::convert_string_sid_to_sid_a("S-1-5-12")
        .map_err(|error| format!("cannot bind restricted-code SID: {error:?}"))?;
    let restricted_sids = token
        .restricted_sids()
        .map_err(|error| format!("cannot inspect nightly restricted SIDs: {error:?}"))?;
    let exact_restricted_sids = restricted_sids.groups().len() == 2
        && restricted_sids
            .groups()
            .iter()
            .any(|group| *group.sid == *authenticated_users)
        && restricted_sids
            .groups()
            .iter()
            .any(|group| *group.sid == *restricted_code);
    let privileges = token
        .privileges()
        .map_err(|error| format!("cannot inspect nightly restricted privileges: {error:?}"))?;
    let privileges_minimal = privileges.privileges().len() <= 1
        && privileges
            .privileges()
            .iter()
            .all(|privilege| privilege.luid == firehazard::privilege::name::CHANGE_NOTIFY.luid());
    Ok([
        u8::from(firehazard::is_token_restricted(&token)),
        u8::from(exact_restricted_sids),
        u8::from(privileges_minimal),
    ])
}

#[cfg(windows)]
fn windows_owned_child_session_receipt(session_path: &Path) -> [u8; 5] {
    let ownership_path = session_path.join("ownership.receipt");
    let collision = session_path.join("candidate-forgery.receipt");
    let session_write_denied = match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&collision)
    {
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => true,
        Err(_) => false,
        Ok(file) => {
            drop(file);
            let _ = fs::remove_file(collision);
            false
        }
    };
    let existing_write_denied = matches!(
        fs::OpenOptions::new().write(true).open(&ownership_path),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied
    );
    let existing_truncate_denied = matches!(
        fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&ownership_path),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied
    );
    let renamed = session_path.join("candidate-renamed.receipt");
    let rename_denied = fs::rename(&ownership_path, &renamed).is_err();
    if !rename_denied {
        let _ = fs::rename(&renamed, &ownership_path);
    }
    let delete_denied = fs::remove_file(&ownership_path).is_err();
    [
        u8::from(session_write_denied),
        u8::from(existing_write_denied),
        u8::from(existing_truncate_denied),
        u8::from(rename_denied),
        u8::from(delete_denied),
    ]
}

#[cfg(windows)]
fn windows_owned_child_process_receipt(
    ownership_path: &Path,
    writable_target: &Path,
    supervisor_pid: &std::ffi::OsStr,
) -> Result<[u8; 4], String> {
    let environment = ProcessEnvironment::from_process();
    let system_root = environment
        .value(StandardVariable::SystemRoot)
        .map(PathBuf::from)
        .ok_or_else(|| "SystemRoot is absent from nightly restricted child".to_owned())?;
    let supervisor_pid = supervisor_pid
        .to_str()
        .ok_or_else(|| "Windows supervisor PID is not UTF-8".to_owned())?;
    let tasklist = NativeProcessSpec::new(system_root.join("System32").join("tasklist.exe"))
        .arguments(["/FO", "CSV", "/NH"])
        .stdin(NativeStdio::Null)
        .stdout(NativeStdio::Piped)
        .stderr(NativeStdio::Piped)
        .output()
        .map_err(|error| format!("cannot inspect restricted supervisor liveness: {error}"))?;
    let supervisor_liveness_allowed = tasklist.status.success()
        && String::from_utf8_lossy(&tasklist.stdout)
            .lines()
            .filter_map(|line| windows_csv_fields(line).ok())
            .any(|fields| fields.get(1).is_some_and(|pid| pid == supervisor_pid));
    let supervisor_terminate_denied =
        !NativeProcessSpec::new(system_root.join("System32").join("taskkill.exe"))
            .arguments(["/PID", supervisor_pid, "/F"])
            .stdin(NativeStdio::Null)
            .stdout(NativeStdio::Null)
            .stderr(NativeStdio::Null)
            .status()
            .is_ok_and(|status| status.success());
    let dacl_mutation_denied =
        !NativeProcessSpec::new(system_root.join("System32").join("icacls.exe"))
            .arguments([
                ownership_path.as_os_str(),
                std::ffi::OsStr::new("/grant:r"),
                std::ffi::OsStr::new("*S-1-5-12:(F)"),
            ])
            .stdin(NativeStdio::Null)
            .stdout(NativeStdio::Null)
            .stderr(NativeStdio::Null)
            .status()
            .is_ok_and(|status| status.success());
    let mut target_nonce = [0_u8; 16];
    getrandom::getrandom(&mut target_nonce)
        .map_err(|error| format!("cannot allocate nightly target receipt: {error}"))?;
    let target_receipt = writable_target.join(format!(
        "nightly-restricted-write-{}",
        sha256_bytes(&target_nonce).hex()
    ));
    let target_write_succeeded = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target_receipt)
        .and_then(|mut file| file.write_all(b"nightly-write-restricted\n"))
        .and_then(|()| fs::remove_file(&target_receipt))
        .is_ok();
    Ok([
        u8::from(dacl_mutation_denied),
        u8::from(target_write_succeeded),
        u8::from(supervisor_liveness_allowed),
        u8::from(supervisor_terminate_denied),
    ])
}

#[cfg(windows)]
fn windows_restricted_receipt_mutation_denied(
    path: &Path,
    replacement: &Path,
    icacls: &Path,
) -> bool {
    let write_denied = fs::OpenOptions::new().write(true).open(path).is_err();
    let truncate_denied = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .is_err();
    let rename_denied = fs::rename(path, replacement).is_err();
    let delete_denied = fs::remove_file(path).is_err();
    let acl_denied = !NativeProcessSpec::new(icacls)
        .arguments([
            path.as_os_str(),
            std::ffi::OsStr::new("/grant:r"),
            std::ffi::OsStr::new("*S-1-5-12:(F)"),
        ])
        .stdin(NativeStdio::Null)
        .stdout(NativeStdio::Null)
        .stderr(NativeStdio::Null)
        .status()
        .is_ok_and(|status| status.success());
    write_denied && truncate_denied && rename_denied && delete_denied && acl_denied
}

#[cfg(windows)]
fn windows_restricted_directory_mutation_denied(
    path: &Path,
    collision: &Path,
    replacement: &Path,
    icacls: &Path,
) -> bool {
    let create_denied = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(collision)
        .is_err();
    let rename_denied = match fs::rename(path, replacement) {
        Err(_) => true,
        Ok(()) => {
            drop(fs::rename(replacement, path));
            false
        }
    };
    let acl_denied = !NativeProcessSpec::new(icacls)
        .arguments([
            path.as_os_str(),
            std::ffi::OsStr::new("/grant:r"),
            std::ffi::OsStr::new("*S-1-5-12:(F)"),
        ])
        .stdin(NativeStdio::Null)
        .stdout(NativeStdio::Null)
        .stderr(NativeStdio::Null)
        .status()
        .is_ok_and(|status| status.success());
    create_denied && rename_denied && acl_denied
}

#[cfg(windows)]
fn windows_restricted_non_executable_authority_file(root: &Path) -> Option<PathBuf> {
    const ENTRY_LIMIT: usize = 4096;

    let mut pending = vec![root.to_path_buf()];
    let mut observed = 0_usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).ok()? {
            observed = observed.checked_add(1)?;
            if observed > ENTRY_LIMIT {
                return None;
            }
            let entry = entry.ok()?;
            let metadata = fs::symlink_metadata(entry.path()).ok()?;
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file()
                && entry.path().extension() != Some(std::ffi::OsStr::new("exe"))
            {
                return Some(entry.path());
            }
        }
    }
    None
}

#[cfg(windows)]
pub(crate) fn run_windows_supervisor_session_probe(
    arguments: &[std::ffi::OsString],
) -> Result<(), String> {
    let [
        session_path,
        late_receipt_path,
        writable_target,
        authority_root,
    ] = arguments
    else {
        return Err(
            "Windows supervisor session probe requires session, late receipt, writable target, and authority root".to_owned(),
        );
    };
    let session_path = Path::new(session_path);
    let late_receipt_path = Path::new(late_receipt_path);
    let receipt_names = [
        "ownership.receipt",
        "request.digest",
        "authority.manifest",
        "started.receipt",
        "terminal.receipt",
        "workspace.receipt",
        "abnormal.receipt",
        "cleanup.commit",
        "cleanup.receipt",
    ];
    let environment = ProcessEnvironment::from_process();
    let system_root = environment
        .value(StandardVariable::SystemRoot)
        .map(PathBuf::from)
        .ok_or_else(|| "SystemRoot is absent from Windows supervisor session probe".to_owned())?;
    let icacls = system_root.join("System32").join("icacls.exe");
    let root_acl_denied = !NativeProcessSpec::new(&icacls)
        .arguments([
            session_path.as_os_str(),
            std::ffi::OsStr::new("/grant:r"),
            std::ffi::OsStr::new("*S-1-5-12:(F)"),
        ])
        .stdin(NativeStdio::Null)
        .stdout(NativeStdio::Null)
        .stderr(NativeStdio::Null)
        .status()
        .is_ok_and(|status| status.success());
    let collision = session_path.join("candidate-session-probe.receipt");
    let create_denied = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&collision)
        .is_err();
    let mut receipts_denied = root_acl_denied && create_denied;
    for (index, name) in receipt_names.iter().enumerate() {
        let path = session_path.join(name);
        let replacement = session_path.join(format!("candidate-session-probe-{index}.receipt"));
        receipts_denied &= windows_restricted_receipt_mutation_denied(&path, &replacement, &icacls);
    }
    let late_replacement = late_receipt_path.with_extension("candidate-replacement");
    let late_receipt_denied =
        windows_restricted_receipt_mutation_denied(late_receipt_path, &late_replacement, &icacls);
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|error| format!("cannot allocate Windows target probe receipt: {error}"))?;
    let target_receipt = Path::new(writable_target).join(format!(
        "nightly-restricted-probe-{}",
        sha256_bytes(&random).hex()
    ));
    let target_write_succeeded = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target_receipt)
        .and_then(|mut file| file.write_all(b"nightly-write-restricted-probe\n"))
        .and_then(|()| fs::remove_file(&target_receipt))
        .is_ok();
    let authority_denied = if authority_root.is_empty() {
        true
    } else {
        let authority_root = Path::new(authority_root);
        let bin = authority_root.join("bin");
        let cargo = bin.join("cargo.exe");
        let metadata = windows_restricted_non_executable_authority_file(authority_root);
        windows_restricted_directory_mutation_denied(
            authority_root,
            &authority_root.join("candidate-root-probe"),
            &authority_root.with_extension("candidate-replacement"),
            &icacls,
        ) && windows_restricted_directory_mutation_denied(
            &bin,
            &bin.join("candidate-bin-probe"),
            &authority_root.join("candidate-bin-replacement"),
            &icacls,
        ) && windows_restricted_receipt_mutation_denied(
            &cargo,
            &bin.join("candidate-cargo.exe"),
            &icacls,
        ) && metadata.is_some_and(|metadata| {
            windows_restricted_receipt_mutation_denied(
                &metadata,
                &metadata.with_extension("candidate-replacement"),
                &icacls,
            )
        })
    };
    if !receipts_denied || !late_receipt_denied || !target_write_succeeded || !authority_denied {
        return Err(format!(
            "Windows supervisor restricted-access probe differed: rootAclDenied={root_acl_denied}, createDenied={create_denied}, receiptsDenied={receipts_denied}, lateReceiptDenied={late_receipt_denied}, targetWriteSucceeded={target_write_succeeded}, authorityDenied={authority_denied}"
        ));
    }
    Ok(())
}

#[cfg(any(unix, windows))]
pub(crate) fn run_external_supervisor_owned_grandchild() -> Result<(), String> {
    let mut release = [0_u8; 1];
    std::io::stdin()
        .read_exact(&mut release)
        .map_err(|error| format!("cannot read nightly owned grandchild release: {error}"))?;
    if release[0] != ExternalSupervisorMessage::Go as u8 {
        return Err("nightly owned grandchild release differs".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn receive_external_supervisor_connection(
    receiver: &mpsc::Receiver<std::io::Result<TcpStream>>,
    phase: &str,
) -> Result<TcpStream, String> {
    receiver
        .recv_timeout(NIGHTLY_SUPERVISOR_START_TIMEOUT)
        .map_err(|error| format!("nightly supervisor {phase} exceeded its deadline: {error}"))?
        .map_err(|error| format!("cannot accept nightly supervisor {phase}: {error}"))
}

#[cfg(unix)]
fn read_external_supervisor_session(
    stream: &mut TcpStream,
) -> Result<(PathBuf, u32, Digest, Digest), String> {
    stream
        .set_read_timeout(Some(NIGHTLY_SUPERVISOR_START_TIMEOUT))
        .map_err(|error| format!("cannot bound nightly session receipt: {error}"))?;
    let mut length = [0_u8; size_of::<u32>()];
    stream
        .read_exact(&mut length)
        .map_err(|error| format!("cannot read nightly session length: {error}"))?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| "nightly session length is not representable".to_owned())?;
    if length > NIGHTLY_SUPERVISOR_REQUEST_LIMIT {
        return Err("nightly session receipt exceeds its byte limit".to_owned());
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .map_err(|error| format!("cannot read nightly session receipt: {error}"))?;
    decode_external_supervisor_session(&bytes)
}

#[cfg(unix)]
fn start_external_supervisor_exit_fixture(
    executable: &Path,
) -> Result<(ExternalSupervisorExitReceipt, std::process::ChildStdin), String> {
    let waiter = ExternalSupervisorExitWaiter::prepare()?;
    let mut child = NativeProcessSpec::new(executable)
        .argument("__nightly-supervisor-owned-grandchild")
        .stdin(NativeStdio::Piped)
        .stdout(NativeStdio::Null)
        .stderr(NativeStdio::Null)
        .spawn()
        .map_err(|error| format!("cannot start nightly exit receipt fixture: {error}"))?;
    let Some(control) = child.stdin.take() else {
        drop(child.kill());
        drop(child.wait());
        return Err("nightly exit receipt fixture stdin is unavailable".to_owned());
    };
    match waiter.transfer(child) {
        Ok(receipt) => Ok((receipt, control)),
        Err((error, mut child)) => {
            drop(child.kill());
            drop(child.wait());
            Err(error)
        }
    }
}

#[cfg(unix)]
fn verify_external_supervisor_exit_receipt_for_integration(
    executable: &Path,
) -> Result<(), String> {
    let (delayed, mut delayed_control) = start_external_supervisor_exit_fixture(executable)?;
    if !matches!(
        delayed.wait_until(Instant::now()),
        ExternalSupervisorExitState::DeadlineExpired
    ) {
        return Err("nightly exit receipt did not retain a still-running supervisor".to_owned());
    }
    delayed_control
        .write_all(&[ExternalSupervisorMessage::Go as u8])
        .map_err(|error| format!("cannot release delayed nightly exit fixture: {error}"))?;
    drop(delayed_control);
    let delayed_deadline = Instant::now()
        .checked_add(NIGHTLY_SUPERVISOR_START_TIMEOUT)
        .ok_or_else(|| "delayed nightly exit receipt deadline overflowed".to_owned())?;
    match delayed.wait_until(delayed_deadline) {
        ExternalSupervisorExitState::Exited(status) if status.success() => {}
        ExternalSupervisorExitState::Exited(status) => {
            return Err(format!(
                "delayed nightly exit fixture failed with status {:?}",
                status.code()
            ));
        }
        ExternalSupervisorExitState::DeadlineExpired => {
            return Err("delayed nightly exit receipt exceeded its deadline".to_owned());
        }
        ExternalSupervisorExitState::Failed(error) => return Err(error),
    }

    let (failed, mut failed_control) = start_external_supervisor_exit_fixture(executable)?;
    failed_control
        .write_all(&[ExternalSupervisorMessage::Ready as u8])
        .map_err(|error| format!("cannot release failing nightly exit fixture: {error}"))?;
    drop(failed_control);
    let failed_deadline = Instant::now()
        .checked_add(NIGHTLY_SUPERVISOR_START_TIMEOUT)
        .ok_or_else(|| "failing nightly exit receipt deadline overflowed".to_owned())?;
    match failed.wait_until(failed_deadline) {
        ExternalSupervisorExitState::Exited(status) if !status.success() => Ok(()),
        ExternalSupervisorExitState::Exited(status) => Err(format!(
            "failing nightly exit fixture unexpectedly succeeded with status {:?}",
            status.code()
        )),
        ExternalSupervisorExitState::DeadlineExpired => {
            Err("failing nightly exit receipt exceeded its deadline".to_owned())
        }
        ExternalSupervisorExitState::Failed(error) => Err(error),
    }
}

#[cfg(unix)]
struct ExternalSupervisorVerifierFinalizer {
    supervisor_pid: u32,
    session_path: PathBuf,
    request_sha256: Digest,
    nonce: Digest,
    reporter_release: Option<TcpStream>,
    target_release: Option<TcpStream>,
    owned_pids: Vec<u32>,
    armed: bool,
}

#[cfg(unix)]
impl ExternalSupervisorVerifierFinalizer {
    fn new(
        supervisor_pid: u32,
        session_path: PathBuf,
        request_sha256: Digest,
        nonce: Digest,
        reporter_release: Option<TcpStream>,
    ) -> Self {
        Self {
            supervisor_pid,
            session_path,
            request_sha256,
            nonce,
            reporter_release,
            target_release: None,
            owned_pids: Vec::new(),
            armed: true,
        }
    }

    fn retain_target_release(&mut self, release: TcpStream) {
        self.target_release = Some(release);
    }

    fn release_reporter(&mut self) -> Result<(), String> {
        let mut release = self
            .reporter_release
            .take()
            .ok_or_else(|| "nightly reporter release authority is unavailable".to_owned())?;
        write_supervisor_handshake(
            &mut release,
            ExternalSupervisorMessage::Go,
            self.request_sha256,
            self.nonce,
        )
    }

    fn retain_owned_pids(&mut self, pids: impl IntoIterator<Item = u32>) {
        self.owned_pids
            .extend(pids.into_iter().filter(|pid| *pid != 0));
    }

    fn disarm(&mut self) {
        self.armed = false;
        self.reporter_release = None;
        self.target_release = None;
        self.owned_pids.clear();
    }

    fn close(&mut self) -> Result<(), String> {
        if !self.armed {
            return Ok(());
        }
        self.armed = false;
        self.release_controls();
        let mut cleanup_errors = Vec::new();
        let supervisor_pid = if self.supervisor_pid == 0 {
            cleanup_errors.push("nightly verifier supervisor pid is invalid".to_owned());
            None
        } else {
            i32::try_from(self.supervisor_pid).map_or_else(
                |_| {
                    cleanup_errors
                        .push("nightly verifier supervisor pid is not representable".to_owned());
                    None
                },
                Some,
            )
        };
        for pid in self
            .owned_pids
            .iter()
            .copied()
            .chain((self.supervisor_pid != 0).then_some(self.supervisor_pid))
        {
            let Ok(pid) = i32::try_from(pid) else {
                cleanup_errors.push("nightly verifier owned pid is not representable".to_owned());
                continue;
            };
            match nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            ) {
                Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
                Err(error) => cleanup_errors.push(format!(
                    "cannot terminate nightly verifier process {pid}: {error}"
                )),
            }
        }
        if let Some(supervisor_pid) = supervisor_pid {
            match nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(-supervisor_pid),
                nix::sys::signal::Signal::SIGKILL,
            ) {
                Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
                Err(error) => cleanup_errors.push(format!(
                    "cannot terminate nightly verifier process group {supervisor_pid}: {error}"
                )),
            }
        }
        let deadline = Instant::now()
            .checked_add(NIGHTLY_SUPERVISOR_START_TIMEOUT)
            .unwrap_or_else(Instant::now);
        for pid in self
            .owned_pids
            .iter()
            .copied()
            .chain((self.supervisor_pid != 0).then_some(self.supervisor_pid))
        {
            let Ok(pid) = i32::try_from(pid) else {
                continue;
            };
            loop {
                match nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None) {
                    Err(nix::errno::Errno::ESRCH) => break,
                    Err(error) => {
                        cleanup_errors.push(format!(
                            "cannot attest nightly verifier process {pid} absence: {error}"
                        ));
                        break;
                    }
                    Ok(()) if Instant::now() < deadline => std::thread::yield_now(),
                    Ok(()) => {
                        cleanup_errors.push(format!(
                            "nightly verifier process {pid} remained past cleanup deadline"
                        ));
                        break;
                    }
                }
            }
        }
        if let Err(error) = close_external_supervisor_verifier_session(&self.session_path) {
            cleanup_errors.push(error);
        }
        if cleanup_errors.is_empty() {
            Ok(())
        } else {
            Err(cleanup_errors.join("; "))
        }
    }

    fn release_controls(&mut self) {
        if let Some(mut release) = self.reporter_release.take() {
            drop(write_supervisor_handshake(
                &mut release,
                ExternalSupervisorMessage::Go,
                self.request_sha256,
                self.nonce,
            ));
        }
        if let Some(mut release) = self.target_release.take() {
            drop(write_supervisor_handshake(
                &mut release,
                ExternalSupervisorMessage::Go,
                self.request_sha256,
                self.nonce,
            ));
        }
    }
}

#[cfg(unix)]
impl Drop for ExternalSupervisorVerifierFinalizer {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("nightly external supervisor verifier cleanup failed: {error}");
        }
    }
}

#[cfg(unix)]
fn close_external_supervisor_verifier_session(path: &Path) -> Result<(), String> {
    const MAXIMUM_ENTRIES: usize = 5;

    let Some(name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
        return Err("nightly verifier session name is not UTF-8".to_owned());
    };
    if name.strip_prefix("hell-nightly-supervision-").is_none() {
        return Err("nightly verifier session name is outside its exact namespace".to_owned());
    }
    let Some(parent_path) = path.parent() else {
        return Err("nightly verifier session has no parent".to_owned());
    };
    let parent = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(parent_path)
        .map_err(|error| format!("cannot retain nightly verifier session parent: {error}"))?;
    let parent_identity = parent
        .metadata()
        .map(|metadata| (metadata.dev(), metadata.ino()))
        .map_err(|error| format!("cannot bind nightly verifier session parent: {error}"))?;
    let root = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(root) => root,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("cannot retain nightly verifier session: {error}")),
    };
    let root_metadata = root
        .metadata()
        .map_err(|error| format!("cannot bind nightly verifier session: {error}"))?;
    if root_metadata.uid() != nix::unistd::Uid::effective().as_raw() {
        return Err("nightly verifier session owner differs".to_owned());
    }
    let mut children = fs::read_dir(path)
        .map_err(|error| format!("cannot enumerate nightly verifier session: {error}"))?;
    for index in 0..=MAXIMUM_ENTRIES {
        let Some(child) = children.next() else {
            break;
        };
        if index == MAXIMUM_ENTRIES {
            return Err("nightly verifier session exceeds its exact entry bound".to_owned());
        }
        let child = child
            .map_err(|error| format!("cannot read nightly verifier session entry: {error}"))?;
        let name = child.file_name();
        if name != "descendant.pid"
            && name != "report.json"
            && name != "request.bin"
            && name != "started.receipt"
            && name != "terminal.receipt"
        {
            return Err(format!(
                "nightly verifier session contains unexpected entry {}",
                name.to_string_lossy()
            ));
        }
        let metadata = fs::symlink_metadata(child.path())
            .map_err(|error| format!("cannot inspect nightly verifier session entry: {error}"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("nightly verifier session entry is not a regular file".to_owned());
        }
        fs::remove_file(child.path())
            .map_err(|error| format!("cannot remove nightly verifier session entry: {error}"))?;
    }
    let rebound_parent = parent
        .metadata()
        .map(|metadata| (metadata.dev(), metadata.ino()))
        .map_err(|error| format!("cannot revalidate nightly verifier session parent: {error}"))?;
    let rebound_root = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot revalidate nightly verifier session: {error}"))?;
    if rebound_parent != parent_identity
        || (rebound_root.dev(), rebound_root.ino()) != (root_metadata.dev(), root_metadata.ino())
        || rebound_root.file_type().is_symlink()
    {
        return Err("nightly verifier session identity changed during cleanup".to_owned());
    }
    fs::remove_dir(path).map_err(|error| format!("cannot remove nightly verifier session: {error}"))
}

#[cfg(unix)]
fn verify_external_supervisor_control_recovery_case(
    root: &Path,
    fixture_control: ExternalSupervisorFixtureControl,
    target_release: ExternalSupervisorMessage,
    expect_success: bool,
) -> Result<(), String> {
    let mut recovery = start_external_supervisor_recovery_case(root, fixture_control)?;
    let observation = observe_external_supervisor_control_failure(&mut recovery, target_release)?;
    let started = &mut recovery.started;
    let finalizer = &mut recovery.finalizer;
    let phase_started = recovery.phase_started;
    let context = AttributedRunContext {
        name: ExternalSupervisorPlan::NightlyCoreData.name(),
        suite: "nightly-recovery-verifier",
        suite_started: phase_started,
        envelope: started.envelope,
    };
    let seed = ExternalSupervisorPlan::NightlyCoreData.seed();
    let mut progress = PortabilityChildProgress::seeded(
        context.suite,
        seed.0,
        "external-supervisor-owned-child",
        seed.2,
    );
    let mut report = Report::new(context.suite);
    let result = finish_external_supervisor_after_control_failure(
        &mut report,
        context,
        &mut progress,
        &ExternalSupervisorControlFailure {
            plan: ExternalSupervisorPlan::NightlyCoreData,
            started,
            control_error: &observation.control_error,
            exit_deadline: observation.lifecycle_deadline,
            lifecycle_deadline: started.envelope.report_completion_deadline,
        },
    );
    for (label, pid) in [
        ("target", observation.target_pid),
        ("descendant", observation.descendant_pid),
    ] {
        let pid = i32::try_from(pid)
            .map_err(|_| format!("nightly recovery {label} pid is not representable"))?;
        match nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None) {
            Err(nix::errno::Errno::ESRCH) => {}
            Err(error) => {
                return Err(format!(
                    "cannot attest nightly recovery {label} absence: {error}"
                ));
            }
            Ok(()) => return Err(format!("nightly recovery {label} remains after cleanup")),
        }
    }
    let session_absent = matches!(
        fs::symlink_metadata(started.session.path()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    );
    if !session_absent {
        return Err("nightly recovery verifier session remains".to_owned());
    }
    if expect_success {
        if result.is_err() || !report.failures.is_empty() {
            return Err(format!(
                "nightly clean EOF recovery failed: result={result:?}, failures={:?}",
                report.failures
            ));
        }
    } else {
        if result.is_ok() {
            return Err("nightly failing EOF recovery unexpectedly succeeded".to_owned());
        }
        let target_failure = report.failures.iter().position(|failure| {
            failure.starts_with(ExternalSupervisorPlan::NightlyCoreData.name())
                && !failure.contains("external-supervisor-exit")
        });
        let exit_failure = report
            .failures
            .iter()
            .position(|failure| failure.contains("external-supervisor-exit"));
        if !matches!((target_failure, exit_failure), (Some(target), Some(exit)) if target < exit) {
            return Err(format!(
                "nightly target/exit causality order differs: {:?}",
                report.failures
            ));
        }
    }
    finalizer.disarm();
    Ok(())
}

#[cfg(unix)]
struct ExternalSupervisorRecoveryObservation {
    target_pid: u32,
    descendant_pid: u32,
    lifecycle_deadline: Instant,
    control_error: String,
}

#[cfg(unix)]
fn observe_external_supervisor_control_failure(
    recovery: &mut ExternalSupervisorRecoveryStart,
    target_release: ExternalSupervisorMessage,
) -> Result<ExternalSupervisorRecoveryObservation, String> {
    let mut owned_pids = [0_u8; size_of::<u32>() * 2];
    recovery
        .gate
        .read_exact(&mut owned_pids)
        .map_err(|error| format!("cannot read nightly recovery process ids: {error}"))?;
    let target_pid = u32::from_be_bytes(
        owned_pids[..size_of::<u32>()]
            .try_into()
            .map_err(|_| "nightly recovery target pid width drifted".to_owned())?,
    );
    let descendant_pid = u32::from_be_bytes(
        owned_pids[size_of::<u32>()..]
            .try_into()
            .map_err(|_| "nightly recovery descendant pid width drifted".to_owned())?,
    );
    recovery
        .finalizer
        .retain_owned_pids([target_pid, descendant_pid]);
    write_supervisor_handshake(
        &mut recovery.gate,
        target_release,
        recovery.started.request_sha256,
        recovery.started.nonce,
    )?;
    let lifecycle_deadline = recovery
        .started
        .envelope
        .report_completion_deadline
        .checked_sub(REPORT_WRITE_RESERVE)
        .unwrap_or(recovery.started.envelope.child_completion_deadline)
        .max(recovery.started.envelope.child_completion_deadline);
    let control_error = loop {
        match read_supervisor_message_until(
            &mut recovery.started.control_output,
            recovery.started.request_sha256,
            recovery.started.nonce,
            lifecycle_deadline,
        ) {
            Ok(Some(ExternalSupervisorMessage::Progress)) => {
                drop(read_supervisor_terminal_payload_until(
                    &mut recovery.started.control_output,
                    lifecycle_deadline,
                )?);
            }
            Ok(Some(message)) => {
                return Err(format!(
                    "nightly recovery verifier observed unexpected {message:?}"
                ));
            }
            Ok(None) if Instant::now() < lifecycle_deadline => {}
            Ok(None) => break "nightly recovery verifier reached its lifecycle cutoff".to_owned(),
            Err(error) => break error,
        }
    };
    Ok(ExternalSupervisorRecoveryObservation {
        target_pid,
        descendant_pid,
        lifecycle_deadline,
        control_error,
    })
}

#[cfg(unix)]
struct ExternalSupervisorRecoveryStart {
    started: ExternalSupervisorStarted,
    finalizer: ExternalSupervisorVerifierFinalizer,
    gate: TcpStream,
    phase_started: Instant,
}

#[cfg(unix)]
fn start_external_supervisor_recovery_case(
    root: &Path,
    fixture_control: ExternalSupervisorFixtureControl,
) -> Result<ExternalSupervisorRecoveryStart, String> {
    let gate = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| format!("cannot bind nightly recovery verifier gate: {error}"))?;
    let gate_address = gate
        .local_addr()
        .map_err(|error| format!("cannot inspect nightly recovery verifier gate: {error}"))?;
    let std::net::SocketAddr::V4(gate_address) = gate_address else {
        return Err("nightly recovery verifier gate is not IPv4".to_owned());
    };
    let gate_receiver = submit_external_supervisor_accept(gate)?;
    let total = NIGHTLY_SUPERVISOR_START_TIMEOUT.saturating_mul(4);
    let phase_started = Instant::now();
    let outer_deadline = phase_started
        .checked_add(total)
        .ok_or_else(|| "nightly recovery verifier deadline overflowed".to_owned())?;
    let started = start_external_nightly_supervisor_with_policy(
        root,
        ExternalSupervisorPlan::NightlyCoreData,
        phase_started,
        outer_deadline,
        &ExternalSupervisorStartPolicy {
            total,
            cleanup_reserve: NIGHTLY_SUPERVISOR_START_TIMEOUT.saturating_mul(2),
            report_reserve: NIGHTLY_SUPERVISOR_START_TIMEOUT,
            terminal_observer: None,
            launch_gate: Some(gate_address),
            fixture_command: true,
            fixture_control,
            session_parent: std::env::temp_dir(),
        },
    )?;
    let mut finalizer = ExternalSupervisorVerifierFinalizer::new(
        started.pid(),
        started.session.path().to_owned(),
        started.request_sha256,
        started.nonce,
        None,
    );
    if let Some(error) = &started.launch_ownership_uncertain {
        return Err(format!(
            "nightly recovery launch authorization was indeterminate: {error}"
        ));
    }
    let mut gate =
        match receive_external_supervisor_connection(&gate_receiver, "recovery launch gate") {
            Ok(gate) => gate,
            Err(error) => {
                let exit_deadline = Instant::now()
                    .checked_add(NIGHTLY_SUPERVISOR_START_TIMEOUT)
                    .unwrap_or_else(Instant::now);
                let exit = match started.exit.wait_until(exit_deadline) {
                    ExternalSupervisorExitState::Exited(status) => {
                        format!("exited({:?})", status.code())
                    }
                    ExternalSupervisorExitState::DeadlineExpired => "deadline-expired".to_owned(),
                    ExternalSupervisorExitState::Failed(error) => format!("wait-failed({error})"),
                };
                let terminal = read_bounded_file(
                    &started.session.path().join("terminal.receipt"),
                    NIGHTLY_SUPERVISOR_TERMINAL_LIMIT,
                )
                .and_then(|bytes| {
                    decode_external_supervisor_terminal(
                        &bytes,
                        started.request_sha256,
                        started.nonce,
                    )
                })
                .map_or_else(
                    |error| format!("unavailable({error})"),
                    |terminal| terminal.detail,
                );
                return Err(format!("{error}; supervisor={exit}; terminal={terminal}"));
            }
        };
    finalizer.retain_target_release(
        gate.try_clone()
            .map_err(|error| format!("cannot retain nightly recovery gate: {error}"))?,
    );
    read_supervisor_handshake(
        &mut gate,
        ExternalSupervisorMessage::Started,
        started.request_sha256,
        started.nonce,
    )?;
    Ok(ExternalSupervisorRecoveryStart {
        started,
        finalizer,
        gate,
        phase_started,
    })
}

#[cfg(unix)]
fn verify_external_supervisor_finalizer_for_integration(root: &Path) -> Result<(), String> {
    let gate = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| format!("cannot bind nightly finalizer verifier gate: {error}"))?;
    let gate_address = gate
        .local_addr()
        .map_err(|error| format!("cannot inspect nightly finalizer verifier gate: {error}"))?;
    let std::net::SocketAddr::V4(gate_address) = gate_address else {
        return Err("nightly finalizer verifier gate is not IPv4".to_owned());
    };
    let gate_receiver = submit_external_supervisor_accept(gate)?;
    let total = NIGHTLY_SUPERVISOR_START_TIMEOUT.saturating_mul(4);
    let phase_started = Instant::now();
    let started = start_external_nightly_supervisor_with_policy(
        root,
        ExternalSupervisorPlan::NightlyCoreData,
        phase_started,
        phase_started
            .checked_add(total)
            .ok_or_else(|| "nightly finalizer verifier deadline overflowed".to_owned())?,
        &ExternalSupervisorStartPolicy {
            total,
            cleanup_reserve: NIGHTLY_SUPERVISOR_START_TIMEOUT.saturating_mul(2),
            report_reserve: NIGHTLY_SUPERVISOR_START_TIMEOUT,
            terminal_observer: None,
            launch_gate: Some(gate_address),
            fixture_command: true,
            fixture_control: ExternalSupervisorFixtureControl::Normal,
            session_parent: std::env::temp_dir(),
        },
    )?;
    let mut finalizer = ExternalSupervisorVerifierFinalizer::new(
        started.pid(),
        started.session.path().to_owned(),
        started.request_sha256,
        started.nonce,
        None,
    );
    let mut gate = receive_external_supervisor_connection(&gate_receiver, "finalizer launch gate")?;
    finalizer.retain_target_release(
        gate.try_clone()
            .map_err(|error| format!("cannot retain nightly finalizer gate: {error}"))?,
    );
    read_supervisor_handshake(
        &mut gate,
        ExternalSupervisorMessage::Started,
        started.request_sha256,
        started.nonce,
    )?;
    let mut owned_pids = [0_u8; size_of::<u32>() * 2];
    gate.read_exact(&mut owned_pids)
        .map_err(|error| format!("cannot read nightly finalizer process ids: {error}"))?;
    let target_pid = u32::from_be_bytes(
        owned_pids[..size_of::<u32>()]
            .try_into()
            .map_err(|_| "nightly finalizer target pid width drifted".to_owned())?,
    );
    let descendant_pid = u32::from_be_bytes(
        owned_pids[size_of::<u32>()..]
            .try_into()
            .map_err(|_| "nightly finalizer descendant pid width drifted".to_owned())?,
    );
    finalizer.retain_owned_pids([target_pid, descendant_pid]);
    finalizer.close()?;
    if !matches!(
        started.exit.wait_until(
            Instant::now()
                .checked_add(NIGHTLY_SUPERVISOR_START_TIMEOUT)
                .unwrap_or_else(Instant::now)
        ),
        ExternalSupervisorExitState::Exited(_)
    ) {
        return Err("nightly verifier finalizer did not retain the supervisor exit".to_owned());
    }
    if !matches!(
        fs::symlink_metadata(started.session.path()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ) {
        return Err("nightly verifier finalizer retained its session".to_owned());
    }
    Ok(())
}

/// Verifies reporter-exit ownership transfer to the production Nightly supervisor.
///
/// # Errors
///
/// Returns an error when the reporter gates target launch, durable terminal receipt,
/// or exact session cleanup differ from the external-owner contract.
#[cfg(unix)]
#[doc(hidden)]
pub(crate) fn verify_external_nightly_supervisor_for_integration() -> Result<(), String> {
    let root = fs::canonicalize(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| "cannot locate nightly supervisor verifier workspace".to_owned())?,
    )
    .map_err(|error| format!("cannot canonicalize nightly supervisor verifier: {error}"))?;
    let executable = fs::canonicalize(
        std::env::current_exe()
            .map_err(|error| format!("cannot locate nightly supervisor verifier: {error}"))?,
    )
    .map_err(|error| format!("cannot canonicalize nightly supervisor verifier: {error}"))?;
    verify_external_supervisor_exit_receipt_for_integration(&executable)?;
    verify_external_supervisor_control_recovery_case(
        &root,
        ExternalSupervisorFixtureControl::CloseBeforeTerminal,
        ExternalSupervisorMessage::Go,
        true,
    )?;
    verify_external_supervisor_control_recovery_case(
        &root,
        ExternalSupervisorFixtureControl::FailBeforeTerminal,
        ExternalSupervisorMessage::Ready,
        false,
    )?;
    verify_external_supervisor_finalizer_for_integration(&root)?;
    verify_external_supervisor_reporter_fixture(&root, &executable)
}

#[cfg(unix)]
fn verify_external_supervisor_reporter_fixture(
    root: &Path,
    executable: &Path,
) -> Result<(), String> {
    let endpoints = external_supervisor_reporter_endpoints()?;
    let fixture = start_external_supervisor_reporter_fixture(root, executable, endpoints)?;
    finish_external_supervisor_reporter_fixture(fixture)
}

#[cfg(unix)]
struct ExternalSupervisorReporterFixture {
    observer: TcpListener,
    finalizer: ExternalSupervisorVerifierFinalizer,
    gate_stream: TcpStream,
    session_path: PathBuf,
    supervisor_pid: u32,
    request_sha256: Digest,
    nonce: Digest,
    target_pid: u32,
    descendant_pid: u32,
}

#[cfg(unix)]
fn start_external_supervisor_reporter_fixture(
    root: &Path,
    executable: &Path,
    endpoints: ExternalSupervisorReporterEndpoints,
) -> Result<ExternalSupervisorReporterFixture, String> {
    let ExternalSupervisorReporterEndpoints {
        observer,
        observer_address,
        session_receiver,
        gate_address,
        gate_receiver,
    } = endpoints;
    let reporter = CommandSpec::new(executable, NIGHTLY_SUPERVISOR_START_TIMEOUT).arguments([
        std::ffi::OsString::from("__nightly-supervisor-reporter-fixture"),
        root.as_os_str().to_owned(),
        std::ffi::OsString::from(observer_address.ip().to_string()),
        std::ffi::OsString::from(observer_address.port().to_string()),
        std::ffi::OsString::from(gate_address.ip().to_string()),
        std::ffi::OsString::from(gate_address.port().to_string()),
    ]);
    let (reporter_result, reporter_receiver) = mpsc::sync_channel(1);
    let reporter_worker = std::thread::Builder::new()
        .name("hell-nightly-reporter-exit-verifier".to_owned())
        .spawn(move || {
            let _ = reporter_result.send(reporter.run());
        })
        .map_err(|error| format!("cannot start nightly reporter verifier worker: {error}"))?;
    let mut session_stream =
        receive_external_supervisor_connection(&session_receiver, "session receipt")?;
    let (session_path, supervisor_pid, request_sha256, nonce) =
        read_external_supervisor_session(&mut session_stream)?;
    let mut finalizer = ExternalSupervisorVerifierFinalizer::new(
        supervisor_pid,
        session_path.clone(),
        request_sha256,
        nonce,
        Some(session_stream),
    );
    let mut gate_stream = receive_external_supervisor_connection(&gate_receiver, "launch gate")?;
    finalizer.retain_target_release(
        gate_stream
            .try_clone()
            .map_err(|error| format!("cannot retain nightly target release gate: {error}"))?,
    );
    read_supervisor_handshake(
        &mut gate_stream,
        ExternalSupervisorMessage::Started,
        request_sha256,
        nonce,
    )?;
    let mut owned_pids = [0_u8; size_of::<u32>() * 2];
    gate_stream
        .read_exact(&mut owned_pids)
        .map_err(|error| format!("cannot read nightly owned process ids: {error}"))?;
    let target_pid = u32::from_be_bytes(
        owned_pids[..size_of::<u32>()]
            .try_into()
            .map_err(|_| "nightly target pid width drifted".to_owned())?,
    );
    let descendant_pid = u32::from_be_bytes(
        owned_pids[size_of::<u32>()..]
            .try_into()
            .map_err(|_| "nightly descendant pid width drifted".to_owned())?,
    );
    finalizer.retain_owned_pids([target_pid, descendant_pid]);
    finalizer.release_reporter()?;
    let reporter = reporter_receiver
        .recv_timeout(NIGHTLY_SUPERVISOR_START_TIMEOUT)
        .map_err(|error| format!("nightly reporter exit exceeded its deadline: {error}"))?
        .map_err(|error| format!("cannot execute nightly supervisor reporter fixture: {error}"))?;
    reporter_worker
        .join()
        .map_err(|_| "nightly reporter verifier worker panicked".to_owned())?;
    if !reporter.status.success() || reporter.timed_out {
        return Err(format!(
            "nightly supervisor reporter did not exit cleanly: status={:?}, timedOut={}",
            reporter.status.code(),
            reporter.timed_out
        ));
    }
    Ok(ExternalSupervisorReporterFixture {
        observer,
        finalizer,
        gate_stream,
        session_path,
        supervisor_pid,
        request_sha256,
        nonce,
        target_pid,
        descendant_pid,
    })
}

#[cfg(unix)]
fn finish_external_supervisor_reporter_fixture(
    fixture: ExternalSupervisorReporterFixture,
) -> Result<(), String> {
    let ExternalSupervisorReporterFixture {
        observer,
        mut finalizer,
        mut gate_stream,
        session_path,
        supervisor_pid,
        request_sha256,
        nonce,
        target_pid,
        descendant_pid,
    } = fixture;
    write_supervisor_handshake(
        &mut gate_stream,
        ExternalSupervisorMessage::Go,
        request_sha256,
        nonce,
    )?;
    let terminal_receiver = submit_external_supervisor_accept(observer)?;
    let mut terminal_stream = terminal_receiver
        .recv_timeout(Duration::from_mins(5))
        .map_err(|error| format!("nightly terminal receipt exceeded its deadline: {error}"))?
        .map_err(|error| format!("cannot accept nightly terminal receipt: {error}"))?;
    read_supervisor_handshake(
        &mut terminal_stream,
        ExternalSupervisorMessage::Terminal,
        request_sha256,
        nonce,
    )?;
    for (label, pid) in [("target", target_pid), ("descendant", descendant_pid)] {
        let pid =
            i32::try_from(pid).map_err(|_| format!("nightly {label} pid is not representable"))?;
        match nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None) {
            Err(nix::errno::Errno::ESRCH) => {}
            Err(error) => return Err(format!("cannot attest nightly {label} absence: {error}")),
            Ok(()) => return Err(format!("nightly {label} remains after terminal cleanup")),
        }
    }
    if supervisor_pid == 0 {
        return Err("nightly supervisor receipt has an invalid pid".to_owned());
    }
    let terminal_deadline = Instant::now()
        .checked_add(Duration::from_mins(5))
        .ok_or_else(|| "nightly terminal payload deadline overflowed".to_owned())?;
    let terminal_payload =
        read_supervisor_terminal_payload_until(&mut terminal_stream, terminal_deadline)?;
    let terminal_file = read_bounded_file(
        &session_path.join("terminal.receipt"),
        NIGHTLY_SUPERVISOR_TERMINAL_LIMIT,
    )?;
    if terminal_file != terminal_payload {
        return Err("nightly terminal file differs from authenticated payload".to_owned());
    }
    let terminal = decode_external_supervisor_terminal(&terminal_payload, request_sha256, nonce)?;
    if !terminal.execution.success || !terminal.cleanup.terminal {
        return Err(format!(
            "nightly supervisor fixture terminal differs: success={}, cleanupTerminal={}, detail={}",
            terminal.execution.success, terminal.cleanup.terminal, terminal.detail
        ));
    }
    write_supervisor_handshake(
        &mut terminal_stream,
        ExternalSupervisorMessage::Go,
        request_sha256,
        nonce,
    )?;
    read_supervisor_handshake(
        &mut terminal_stream,
        ExternalSupervisorMessage::Ready,
        request_sha256,
        nonce,
    )?;
    if !wait_supervisor_eof_until(&mut terminal_stream, terminal_deadline)? {
        return Err(
            "nightly supervisor did not close its observer before the exit deadline".to_owned(),
        );
    }
    if supervisor_pid == 0 {
        return Err("nightly supervisor exit receipt has an invalid pid".to_owned());
    }
    match fs::symlink_metadata(&session_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            finalizer.disarm();
            Ok(())
        }
        Err(error) => Err(format!(
            "cannot attest nightly supervisor session absence: {error}"
        )),
        Ok(_) => Err("nightly supervisor session remains after receipt-bound cleanup".to_owned()),
    }
}

#[cfg(unix)]
struct ExternalSupervisorReporterEndpoints {
    observer: TcpListener,
    observer_address: SocketAddrV4,
    session_receiver: mpsc::Receiver<std::io::Result<TcpStream>>,
    gate_address: SocketAddrV4,
    gate_receiver: mpsc::Receiver<std::io::Result<TcpStream>>,
}

#[cfg(unix)]
fn external_supervisor_reporter_endpoints() -> Result<ExternalSupervisorReporterEndpoints, String> {
    let observer = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| format!("cannot bind nightly supervisor verifier observer: {error}"))?;
    let observer_address = observer
        .local_addr()
        .map_err(|error| format!("cannot inspect nightly supervisor verifier observer: {error}"))?;
    let std::net::SocketAddr::V4(observer_address) = observer_address else {
        return Err("nightly supervisor verifier observer is not IPv4".to_owned());
    };
    let session_receiver = submit_external_supervisor_accept(
        observer
            .try_clone()
            .map_err(|error| format!("cannot clone nightly session observer: {error}"))?,
    )?;
    let gate = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| format!("cannot bind nightly supervisor verifier gate: {error}"))?;
    let gate_address = gate
        .local_addr()
        .map_err(|error| format!("cannot inspect nightly supervisor verifier gate: {error}"))?;
    let std::net::SocketAddr::V4(gate_address) = gate_address else {
        return Err("nightly supervisor verifier gate is not IPv4".to_owned());
    };
    let gate_receiver = submit_external_supervisor_accept(gate)?;
    Ok(ExternalSupervisorReporterEndpoints {
        observer,
        observer_address,
        session_receiver,
        gate_address,
        gate_receiver,
    })
}

pub(crate) fn failures_directory(report: &Path) -> PathBuf {
    report
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("failures")
}

pub(crate) fn policy_suite(root: &Path, report: &mut Report) -> Result<(), FailureKind> {
    let started = Instant::now();
    let _ = crate::policy::take_repository_inventory_evidence();
    let repository = crate::policy::check_repository(root);
    if let Some(evidence) = crate::policy::take_repository_inventory_evidence() {
        report.evidence("repository-inventory", evidence);
    }
    let result =
        repository.and_then(|()| compatibility::release_conformance_policy(root).map(|_| ()));
    let passed = result.is_ok();
    report.check("release-assurance-policy", started.elapsed(), result);
    passed.then_some(()).ok_or(FailureKind::Policy)
}

fn portability_policy_suite(
    root: &Path,
    report: &mut Report,
    deadline: Instant,
) -> Result<(), FailureKind> {
    let started = Instant::now();
    let _ = crate::policy::take_repository_inventory_evidence();
    let repository = run_before_portability_deadline(deadline, "repository policy", || {
        crate::policy::check_repository(root)
    });
    if let Some(evidence) = crate::policy::take_repository_inventory_evidence() {
        report.evidence("repository-inventory", evidence);
    }
    let result = repository
        .and_then(|()| {
            run_before_portability_deadline(deadline, "conformance policy", || {
                compatibility::release_conformance_policy(root).map(|_| ())
            })
        })
        .and_then(|()| require_portability_deadline(deadline, "policy completion"));
    let passed = result.is_ok();
    report.check("release-assurance-policy", started.elapsed(), result);
    passed.then_some(()).ok_or(FailureKind::Policy)
}

fn run_before_portability_deadline<T>(
    deadline: Instant,
    phase: &str,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    require_portability_deadline(deadline, phase)?;
    operation()
}

fn require_portability_deadline(deadline: Instant, phase: &str) -> Result<(), String> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(format!(
            "portability absolute suite deadline expired before {phase}"
        ))
    }
}

pub(crate) fn verify(root: &Path, report: &mut Report, failures: &Path) -> Result<(), FailureKind> {
    policy_suite(root, report)?;
    run_cargo_command(
        root,
        report,
        "workspace-tests",
        &[
            "test",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
        ],
        WORKSPACE_TEST_TIMEOUT,
    )?;
    finish_verify(root, report, failures)
}

fn finish_verify(root: &Path, report: &mut Report, failures: &Path) -> Result<(), FailureKind> {
    run_cargo_command(
        root,
        report,
        "candidate-build",
        &["build", "--workspace", "--all-features", "--locked"],
        Duration::from_hours(1),
    )?;
    fixture_gate(root, report, failures)
}

pub(crate) fn portability(
    root: &Path,
    report: &mut Report,
    failures: &Path,
) -> Result<(), FailureKind> {
    let suite_started = Instant::now();
    let suite_deadline = suite_started
        .checked_add(PORTABILITY_SUITE_TIMEOUT)
        .ok_or_else(|| {
            report.check(
                "portability-deadline",
                Duration::ZERO,
                Err("portability suite deadline overflowed".to_owned()),
            );
            FailureKind::Policy
        })?;
    let child_deadline = suite_deadline
        .checked_sub(PORTABILITY_CLEANUP_RESERVE)
        .ok_or_else(|| {
            report.check(
                "portability-deadline",
                Duration::ZERO,
                Err("portability cleanup reserve exceeds suite deadline".to_owned()),
            );
            FailureKind::Policy
        })?;
    checkpoint_portability_phase(
        report,
        "release-assurance-policy",
        suite_started,
        suite_deadline,
    )?;
    portability_policy_suite(root, report, child_deadline)?;
    checkpoint_portability_phase_complete(report)?;
    let workspace_arguments = portable_workspace_test_arguments();
    let workspace_result = run_portability_cargo_command(
        root,
        report,
        "portable-workspace-tests",
        &workspace_arguments,
        suite_started,
        child_deadline,
        suite_deadline,
    );
    #[cfg(windows)]
    let workspace_result = preserve_workspace_result_with_diagnostics(workspace_result, || {
        for (name, arguments) in windows_hell_testkit_diagnostic_commands() {
            let now = Instant::now();
            let diagnostic_deadline = now
                .checked_add(WINDOWS_HELL_TESTKIT_DIAGNOSTIC_TIMEOUT)
                .unwrap_or(suite_deadline)
                .min(suite_deadline);
            let _ = run_portability_cargo_command(
                root,
                report,
                name,
                &arguments,
                suite_started,
                diagnostic_deadline,
                suite_deadline,
            );
        }
    });
    workspace_result?;
    #[cfg(target_os = "macos")]
    run_macos_staged_native_toolchain_partition(
        root,
        report,
        suite_started,
        child_deadline,
        suite_deadline,
    )?;
    checkpoint_portability_phase(report, "fixture-inventory", suite_started, suite_deadline)?;
    portability_fixture_gate(root, report, failures, suite_deadline)
}

#[cfg(target_os = "macos")]
fn run_macos_staged_native_toolchain_partition(
    root: &Path,
    report: &mut Report,
    suite_started: Instant,
    execution_deadline: Instant,
    completion_deadline: Instant,
) -> Result<(), FailureKind> {
    run_macos_staged_native_toolchain_partition_with(
        root,
        report,
        suite_started,
        execution_deadline,
        completion_deadline,
        |adapter, execution_deadline, completion_deadline, phase_sender| {
            crate::command::verify_staged_native_toolchain_until(
                &adapter,
                execution_deadline,
                completion_deadline,
                phase_sender,
            )
        },
    )
}

#[cfg(target_os = "macos")]
fn run_macos_staged_native_toolchain_partition_with<F>(
    root: &Path,
    report: &mut Report,
    suite_started: Instant,
    execution_deadline: Instant,
    completion_deadline: Instant,
    verify: F,
) -> Result<(), FailureKind>
where
    F: FnOnce(
            PathBuf,
            Instant,
            Instant,
            mpsc::SyncSender<crate::command::StagedNativeToolchainProgress>,
        ) -> Result<(), String>
        + Send
        + 'static,
{
    let started = Instant::now();
    checkpoint_macos_staged_native_prelaunch(report, suite_started, execution_deadline)?;
    let worker = launch_macos_staged_native_worker(
        root,
        report,
        started,
        suite_started,
        execution_deadline,
        completion_deadline,
        verify,
    )?;
    let mut progress = MacosStagedNativeProgress::prelaunch(suite_started);
    let mut next_checkpoint = Instant::now()
        .checked_add(PORTABILITY_PROGRESS_INTERVAL)
        .unwrap_or(completion_deadline)
        .min(completion_deadline);
    let result = loop {
        while let Ok(subphase) = worker.phase_receiver.try_recv() {
            observe_macos_staged_native_phase(
                &mut progress,
                report,
                suite_started,
                execution_deadline,
                subphase,
            );
        }
        match worker.terminal_receiver.try_recv() {
            Ok(result) => {
                while let Ok(subphase) = worker.phase_receiver.try_recv() {
                    observe_macos_staged_native_phase(
                        &mut progress,
                        report,
                        suite_started,
                        execution_deadline,
                        subphase,
                    );
                }
                let worker_state =
                    worker.retain_terminal(report, &progress, completion_deadline, "completed");
                break if worker_state == "completed" {
                    result
                } else {
                    Err("macOS staged-toolchain worker panicked".to_owned())
                };
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                let worker_state = worker.retain_terminal(
                    report,
                    &progress,
                    completion_deadline,
                    "receipt-disconnected",
                );
                break Err(format!(
                    "macOS staged-toolchain terminal receipt {worker_state}"
                ));
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if Instant::now() >= completion_deadline {
            worker.retain_terminal(report, &progress, completion_deadline, "completed");
            break Err(
                "macOS staged-toolchain worker exceeded its absolute completion deadline"
                    .to_owned(),
            );
        }
        if Instant::now() >= next_checkpoint {
            if progress.checkpoint_error.is_none()
                && let Err(error) = checkpoint_macos_staged_native_transition(
                    report,
                    suite_started,
                    execution_deadline,
                    progress.sequence,
                    progress.last_transition_elapsed,
                    progress.last_subphase.as_deref(),
                )
            {
                progress.checkpoint_error = Some(error);
            }
            next_checkpoint = Instant::now()
                .checked_add(PORTABILITY_PROGRESS_INTERVAL)
                .unwrap_or(completion_deadline)
                .min(completion_deadline);
        }
        let wait = completion_deadline
            .saturating_duration_since(Instant::now())
            .min(PORTABILITY_PROGRESS_DRAIN_INTERVAL);
        if let Ok(subphase) = worker.phase_receiver.recv_timeout(wait) {
            observe_macos_staged_native_phase(
                &mut progress,
                report,
                suite_started,
                execution_deadline,
                subphase,
            );
        }
    };
    finish_macos_staged_native_result(report, started, progress, result)
}

#[cfg(target_os = "macos")]
fn finish_macos_staged_native_result(
    report: &mut Report,
    started: Instant,
    progress: MacosStagedNativeProgress,
    result: Result<(), String>,
) -> Result<(), FailureKind> {
    report.check(
        "macos-staged-native-toolchain",
        started.elapsed(),
        result.clone(),
    );
    let checkpoint_failed = progress.checkpoint_error.is_some();
    if let Some(error) = progress.checkpoint_error {
        report.check("portability-report-checkpoint", Duration::ZERO, Err(error));
    }
    checkpoint_portability_phase_complete(report)?;
    if checkpoint_failed {
        Err(FailureKind::Fixture)
    } else {
        result.map_err(|_| FailureKind::Child)
    }
}

#[cfg(target_os = "macos")]
fn checkpoint_macos_staged_native_prelaunch(
    report: &mut Report,
    suite_started: Instant,
    execution_deadline: Instant,
) -> Result<(), FailureKind> {
    checkpoint_macos_staged_native_transition(
        report,
        suite_started,
        execution_deadline,
        0,
        Some(suite_started.elapsed()),
        Some("prelaunch"),
    )
    .map_err(|error| {
        report.check("portability-report-checkpoint", Duration::ZERO, Err(error));
        FailureKind::Fixture
    })
}

#[cfg(target_os = "macos")]
struct MacosStagedNativeWorker {
    phase_receiver: mpsc::Receiver<crate::command::StagedNativeToolchainProgress>,
    terminal_receiver: mpsc::Receiver<Result<(), String>>,
    worker_receipt: AttributedWorkerReceipt,
    worker_receipt_id: u64,
}

#[cfg(target_os = "macos")]
impl MacosStagedNativeWorker {
    fn retain_terminal(
        &self,
        report: &mut Report,
        progress: &MacosStagedNativeProgress,
        deadline: Instant,
        completed_state: &'static str,
    ) -> &'static str {
        let worker_state = match self.worker_receipt.wait_until(deadline) {
            AttributedWorkerState::Completed => completed_state,
            AttributedWorkerState::Panicked => "panicked",
            AttributedWorkerState::Owned => "retained",
            AttributedWorkerState::Rejected => "launch-failed",
        };
        retain_macos_staged_native_terminal(
            report,
            progress.sequence,
            progress.last_transition_elapsed,
            progress.last_subphase.as_deref(),
            progress.manifest_passes,
            self.worker_receipt_id,
            worker_state,
        );
        worker_state
    }
}

#[cfg(target_os = "macos")]
fn launch_macos_staged_native_worker<F>(
    root: &Path,
    report: &mut Report,
    started: Instant,
    suite_started: Instant,
    execution_deadline: Instant,
    completion_deadline: Instant,
    verify: F,
) -> Result<MacosStagedNativeWorker, FailureKind>
where
    F: FnOnce(
            PathBuf,
            Instant,
            Instant,
            mpsc::SyncSender<crate::command::StagedNativeToolchainProgress>,
        ) -> Result<(), String>
        + Send
        + 'static,
{
    const PHASE: &str = "macos-staged-native-toolchain";
    const PHASE_QUEUE_CAPACITY: usize = 32;
    let sequence = PORTABILITY_PARTITION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let adapter = root.join("target").join(format!(
        "hell-ci-portability-staged-native-toolchain-{}-{sequence}",
        std::process::id()
    ));
    let worker_sender = macos_staged_worker_sender().map_err(|error| {
        report.check(PHASE, started.elapsed(), Err(error));
        FailureKind::Child
    })?;
    let permit = PortabilityWorkerPermit::acquire().map_err(|error| {
        report.check(PHASE, started.elapsed(), Err(error));
        FailureKind::Child
    })?;
    let worker_receipt_id = permit.id;
    let worker_receipt = AttributedWorkerReceipt::new(worker_receipt_id);
    let (phase_sender, phase_receiver) = mpsc::sync_channel(PHASE_QUEUE_CAPACITY);
    let (terminal_sender, terminal_receiver) = mpsc::sync_channel(1);
    if worker_sender
        .send(MacosStagedWorkerTask {
            operation: Box::new(move || {
                verify(
                    adapter,
                    execution_deadline,
                    completion_deadline,
                    phase_sender,
                )
            }),
            terminal: terminal_sender,
            receipt: worker_receipt.clone(),
            permit,
        })
        .is_err()
    {
        worker_receipt.finish(AttributedWorkerState::Rejected);
        retain_macos_staged_native_terminal(
            report,
            0,
            Some(suite_started.elapsed()),
            Some("prelaunch"),
            None,
            worker_receipt_id,
            "launch-failed",
        );
        report.check(
            PHASE,
            started.elapsed(),
            Err("macOS staged-toolchain executor disconnected before launch".to_owned()),
        );
        checkpoint_portability_phase_complete(report)?;
        return Err(FailureKind::Child);
    }
    Ok(MacosStagedNativeWorker {
        phase_receiver,
        terminal_receiver,
        worker_receipt,
        worker_receipt_id,
    })
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct MacosStagedNativeProgress {
    sequence: u64,
    last_transition_elapsed: Option<Duration>,
    last_subphase: Option<String>,
    checkpoint_error: Option<String>,
    manifest_passes: Option<crate::command::StagedNativeManifestPassCounts>,
}

#[cfg(target_os = "macos")]
impl MacosStagedNativeProgress {
    fn prelaunch(suite_started: Instant) -> Self {
        Self {
            last_transition_elapsed: Some(suite_started.elapsed()),
            last_subphase: Some("prelaunch".to_owned()),
            ..Self::default()
        }
    }
}

#[cfg(target_os = "macos")]
fn observe_macos_staged_native_phase(
    progress: &mut MacosStagedNativeProgress,
    report: &mut Report,
    suite_started: Instant,
    execution_deadline: Instant,
    receipt: crate::command::StagedNativeToolchainProgress,
) {
    let subphase = match receipt {
        crate::command::StagedNativeToolchainProgress::Phase(subphase) => subphase,
        crate::command::StagedNativeToolchainProgress::ManifestPasses(passes) => {
            progress.manifest_passes = Some(passes);
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "hell-ci-progress suite=portability phase=macos-staged-native-toolchain target=release_environment case={} event=manifest-passes sourceInventory={} sourcePostflight={} stagedFinal={} queryPreflight={} queryPostflight={}",
                MACOS_STAGED_NATIVE_TOOLCHAIN_CASE,
                passes.source_inventory,
                passes.source_postflight,
                passes.staged_final,
                passes.query_preflight,
                passes.query_postflight,
            )
            .and_then(|()| stderr.flush());
            report.evidence(
                "macos-staged-native-manifest-passes",
                JsonValue::Object(BTreeMap::from([
                    (
                        "queryPostflight".to_owned(),
                        JsonValue::Number(u64::from(passes.query_postflight)),
                    ),
                    (
                        "queryPreflight".to_owned(),
                        JsonValue::Number(u64::from(passes.query_preflight)),
                    ),
                    (
                        "sourceInventory".to_owned(),
                        JsonValue::Number(u64::from(passes.source_inventory)),
                    ),
                    (
                        "sourcePostflight".to_owned(),
                        JsonValue::Number(u64::from(passes.source_postflight)),
                    ),
                    (
                        "stagedFinal".to_owned(),
                        JsonValue::Number(u64::from(passes.staged_final)),
                    ),
                ])),
            );
            "manifest-pass-receipt".to_owned()
        }
    };
    progress.sequence += 1;
    progress.last_transition_elapsed = Some(suite_started.elapsed());
    progress.last_subphase = Some(subphase);
    if progress.checkpoint_error.is_none()
        && let Err(error) = checkpoint_macos_staged_native_transition(
            report,
            suite_started,
            execution_deadline,
            progress.sequence,
            progress.last_transition_elapsed,
            progress.last_subphase.as_deref(),
        )
    {
        progress.checkpoint_error = Some(error);
    }
}

#[cfg(target_os = "macos")]
fn checkpoint_macos_staged_native_transition(
    report: &mut Report,
    suite_started: Instant,
    execution_deadline: Instant,
    sequence: u64,
    transition_elapsed: Option<Duration>,
    subphase: Option<&str>,
) -> Result<(), String> {
    let elapsed = suite_started.elapsed();
    let remaining = execution_deadline.saturating_duration_since(Instant::now());
    let subphase = subphase.map(sanitize_portability_attribution);
    let mut stderr = std::io::stderr().lock();
    writeln!(
        stderr,
        "hell-ci-progress suite=portability phase=macos-staged-native-toolchain target=release_environment case={} caseState=active subphase={} sequence={sequence} event=running elapsedMillis={} remainingMillis={}",
        MACOS_STAGED_NATIVE_TOOLCHAIN_CASE,
        subphase.as_deref().unwrap_or("unknown"),
        elapsed.as_millis(),
        remaining.as_millis(),
    )
    .and_then(|()| stderr.flush())
    .map_err(|error| format!("cannot publish macOS staged-toolchain transition: {error}"))?;
    report
        .checkpoint_phase_attribution(
            "macos-staged-native-toolchain",
            elapsed,
            remaining,
            ActivePhaseAttribution {
                sequence,
                transition_elapsed,
                target: Some("release_environment".to_owned()),
                case: Some(MACOS_STAGED_NATIVE_TOOLCHAIN_CASE.to_owned()),
                case_state: Some("active".to_owned()),
                subphase,
            },
        )
        .map_err(|error| format!("cannot persist macOS staged-toolchain transition: {error}"))
}

#[cfg(target_os = "macos")]
fn retain_macos_staged_native_terminal(
    report: &mut Report,
    sequence: u64,
    transition_elapsed: Option<Duration>,
    subphase: Option<&str>,
    manifest_passes: Option<crate::command::StagedNativeManifestPassCounts>,
    worker_receipt_id: u64,
    worker_state: &str,
) {
    let case_state = match worker_state {
        "completed" => PortabilityCaseState::Completed,
        "launch-failed" => PortabilityCaseState::LaunchFailed,
        "panicked" => PortabilityCaseState::Panicked,
        "retained" => PortabilityCaseState::Retained,
        _ => PortabilityCaseState::ReceiptDisconnected,
    };
    retain_portability_terminal_attribution(
        report,
        "portability",
        "macos-staged-native-toolchain",
        &PortabilityChildProgress {
            sequence,
            target: Some("release_environment".to_owned()),
            case: Some(MACOS_STAGED_NATIVE_TOOLCHAIN_CASE.to_owned()),
            case_state: Some(case_state),
            subphase: subphase.map(str::to_owned),
            last_transition_elapsed: transition_elapsed,
            ..PortabilityChildProgress::default()
        },
        hell_testkit::SupervisedProgressLoss {
            chunks: 0,
            bytes: 0,
        },
        Some(worker_receipt_id),
        worker_state,
    );
    if let Some(passes) = manifest_passes {
        report.evidence(
            "portability-terminal-manifest-passes",
            JsonValue::Object(BTreeMap::from([
                (
                    "phase".to_owned(),
                    JsonValue::String("macos-staged-native-toolchain".to_owned()),
                ),
                (
                    "queryPostflight".to_owned(),
                    JsonValue::Number(u64::from(passes.query_postflight)),
                ),
                (
                    "queryPreflight".to_owned(),
                    JsonValue::Number(u64::from(passes.query_preflight)),
                ),
                (
                    "sourceInventory".to_owned(),
                    JsonValue::Number(u64::from(passes.source_inventory)),
                ),
                (
                    "sourcePostflight".to_owned(),
                    JsonValue::Number(u64::from(passes.source_postflight)),
                ),
                (
                    "stagedFinal".to_owned(),
                    JsonValue::Number(u64::from(passes.staged_final)),
                ),
                (
                    "workerState".to_owned(),
                    JsonValue::String(worker_state.to_owned()),
                ),
            ])),
        );
    }
}

#[cfg(target_os = "macos")]
fn verify_macos_staged_native_partition_for_integration() -> Result<(), String> {
    let sequence = PORTABILITY_PARTITION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "hell-portability-staged-partition-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&root)
        .and_then(|()| fs::create_dir(root.join("target")))
        .map_err(|error| format!("cannot create macOS partition fixture: {error}"))?;
    let result = (|| {
        let mut report = Report::new("macos-staged-partition-verifier");
        let started = Instant::now();
        let execution_deadline = started
            .checked_add(Duration::from_secs(1))
            .ok_or_else(|| "macOS partition execution deadline overflowed".to_owned())?;
        let completion_deadline = started
            .checked_add(Duration::from_secs(2))
            .ok_or_else(|| "macOS partition completion deadline overflowed".to_owned())?;
        run_macos_staged_native_toolchain_partition_with(
            &root,
            &mut report,
            started,
            execution_deadline,
            completion_deadline,
            |_, _, _, phase_sender| {
                phase_sender
                    .send(crate::command::StagedNativeToolchainProgress::Phase(
                        "acquisition".to_owned(),
                    ))
                    .and_then(|()| {
                        phase_sender.send(crate::command::StagedNativeToolchainProgress::Phase(
                            "cleanup".to_owned(),
                        ))
                    })
                    .and_then(|()| {
                        phase_sender.send(
                            crate::command::StagedNativeToolchainProgress::ManifestPasses(
                                crate::command::StagedNativeManifestPassCounts {
                                    source_inventory: 1,
                                    source_postflight: 1,
                                    staged_final: 1,
                                    query_preflight: 1,
                                    query_postflight: 1,
                                },
                            ),
                        )
                    })
                    .map_err(|error| format!("cannot send partition fixture phase: {error}"))
            },
        )
        .map_err(|kind| format!("macOS partition success fixture failed: {kind:?}"))?;
        let evidence = report.to_json();
        if !evidence.contains("\"phase\":\"macos-staged-native-toolchain\"")
            || !evidence.contains(MACOS_STAGED_NATIVE_TOOLCHAIN_CASE)
            || !evidence.contains("\"sequence\":3")
            || !evidence.contains("\"subphase\":\"manifest-pass-receipt\"")
            || !evidence.contains("\"workerState\":\"completed\"")
            || !evidence.contains("\"sourceInventory\":1")
            || !evidence.contains("\"queryPostflight\":1")
            || !evidence.contains("portability-terminal-manifest-passes")
        {
            return Err("macOS partition terminal evidence lost typed chronology".to_owned());
        }

        verify_retained_macos_partition(&root)
    })();
    let cleanup = fs::remove_dir_all(&root)
        .map_err(|error| format!("cannot remove macOS partition fixture: {error}"));
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(format!("{primary}; {cleanup}")),
    }
}

#[cfg(target_os = "macos")]
fn verify_retained_macos_partition(root: &Path) -> Result<(), String> {
    let tracker = portability_worker_tracker();
    let baseline = *tracker
        .active
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (release_sender, release_receiver) = mpsc::sync_channel(0);
    let mut report = Report::new("macos-staged-partition-retained-verifier");
    let started = Instant::now();
    let execution = started
        .checked_add(Duration::from_millis(50))
        .ok_or_else(|| "retained partition execution deadline overflowed".to_owned())?;
    let completion = started
        .checked_add(Duration::from_millis(150))
        .ok_or_else(|| "retained partition completion deadline overflowed".to_owned())?;
    let retained = run_macos_staged_native_toolchain_partition_with(
        root,
        &mut report,
        started,
        execution,
        completion,
        move |_, _, _, phase_sender| {
            phase_sender
                .send(crate::command::StagedNativeToolchainProgress::Phase(
                    "blocked-fixture".to_owned(),
                ))
                .map_err(|error| format!("cannot send blocked partition phase: {error}"))?;
            release_receiver
                .recv()
                .map_err(|error| format!("cannot release blocked partition fixture: {error}"))
        },
    );
    if retained != Err(FailureKind::Child)
        || !report.to_json().contains("\"workerState\":\"retained\"")
    {
        return Err("macOS partition did not retain timed-out worker ownership".to_owned());
    }
    release_sender
        .send(())
        .map_err(|error| format!("cannot release retained partition worker: {error}"))?;
    let active = tracker
        .active
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (active, timeout) = tracker
        .idle
        .wait_timeout_while(active, Duration::from_secs(1), |active| *active > baseline)
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if timeout.timed_out() || *active > baseline {
        return Err("retained macOS partition worker did not reach eventual idle".to_owned());
    }
    Ok(())
}

fn checkpoint_portability_phase(
    report: &mut Report,
    phase: &str,
    suite_started: Instant,
    deadline: Instant,
) -> Result<(), FailureKind> {
    checkpoint_attributed_phase(report, "portability", phase, suite_started, deadline)
}

fn checkpoint_attributed_phase(
    report: &mut Report,
    suite: &str,
    phase: &str,
    suite_started: Instant,
    deadline: Instant,
) -> Result<(), FailureKind> {
    let elapsed = suite_started.elapsed();
    let remaining = deadline.saturating_duration_since(Instant::now());
    emit_attributed_progress(suite, phase, "started", elapsed, remaining);
    report
        .checkpoint_phase(phase, elapsed, remaining)
        .map_err(|error| {
            report.check(
                format!("{suite}-report-checkpoint"),
                Duration::ZERO,
                Err(format!("cannot write active {suite} phase: {error}")),
            );
            FailureKind::Fixture
        })
}

fn checkpoint_attributed_phase_with_progress(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    progress: &PortabilityChildProgress,
) -> Result<(), FailureKind> {
    if Instant::now() >= context.envelope.report_completion_deadline {
        report.check(
            format!("{}-report-checkpoint", context.suite),
            Duration::ZERO,
            Err(format!(
                "{} report deadline expired before checkpoint",
                context.suite
            )),
        );
        return Err(FailureKind::Fixture);
    }
    let elapsed = context.suite_started.elapsed();
    let execution_remaining = context
        .envelope
        .execution
        .saturating_duration_since(Instant::now());
    let cleanup_remaining = context
        .envelope
        .child_completion_deadline
        .saturating_duration_since(Instant::now());
    let report_remaining = context
        .envelope
        .report_completion_deadline
        .saturating_duration_since(Instant::now());
    emit_attributed_progress_with_deadlines(context, "started", progress);
    report
        .checkpoint_phase_attribution_deadlines(
            context.name,
            elapsed,
            progress.attribution(),
            execution_remaining,
            cleanup_remaining,
            report_remaining,
        )
        .map_err(|error| {
            report.check(
                format!("{}-report-checkpoint", context.suite),
                Duration::ZERO,
                Err(format!(
                    "cannot write attributed {} phase: {error}",
                    context.suite
                )),
            );
            FailureKind::Fixture
        })?;
    if Instant::now() > context.envelope.report_completion_deadline {
        report.check(
            format!("{}-report-checkpoint", context.suite),
            Duration::ZERO,
            Err(format!(
                "{} checkpoint crossed its absolute report deadline",
                context.suite
            )),
        );
        return Err(FailureKind::Fixture);
    }
    Ok(())
}

fn checkpoint_portability_phase_complete(report: &mut Report) -> Result<(), FailureKind> {
    checkpoint_attributed_phase_complete(report, "portability", None)
}

fn checkpoint_attributed_phase_complete(
    report: &mut Report,
    suite: &str,
    deadline: Option<Instant>,
) -> Result<(), FailureKind> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        report.check(
            format!("{suite}-report-checkpoint"),
            Duration::ZERO,
            Err(format!(
                "{suite} report deadline expired before terminal checkpoint"
            )),
        );
        return Err(FailureKind::Fixture);
    }
    report.checkpoint_phase_complete().map_err(|error| {
        report.check(
            format!("{suite}-report-checkpoint"),
            Duration::ZERO,
            Err(format!("cannot write completed {suite} phase: {error}")),
        );
        FailureKind::Fixture
    })?;
    if deadline.is_some_and(|deadline| Instant::now() > deadline) {
        report.check(
            format!("{suite}-report-checkpoint"),
            Duration::ZERO,
            Err(format!(
                "{suite} terminal checkpoint crossed its absolute report deadline"
            )),
        );
        return Err(FailureKind::Fixture);
    }
    Ok(())
}

fn fail_attributed_prelaunch<T>(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    progress: &mut PortabilityChildProgress,
    worker_receipt_id: Option<u64>,
    state: PortabilityCaseState,
    reason: String,
) -> Result<T, FailureKind> {
    progress.record_terminal(context.name, state);
    emit_attributed_progress_with_deadlines(context, "terminal", progress);
    let checkpoint_failed = if let Err(error) = report.checkpoint_phase_attribution_deadlines(
        context.name,
        context.suite_started.elapsed(),
        progress.attribution(),
        context
            .envelope
            .execution
            .saturating_duration_since(Instant::now()),
        context
            .envelope
            .child_completion_deadline
            .saturating_duration_since(Instant::now()),
        context
            .envelope
            .report_completion_deadline
            .saturating_duration_since(Instant::now()),
    ) {
        report.check(
            format!("{}-report-checkpoint", context.suite),
            Duration::ZERO,
            Err(format!(
                "cannot persist terminal {} phase: {error}",
                context.suite
            )),
        );
        true
    } else {
        false
    };
    retain_portability_terminal_attribution(
        report,
        context.suite,
        context.name,
        progress,
        hell_testkit::SupervisedProgressLoss {
            chunks: 0,
            bytes: 0,
        },
        worker_receipt_id,
        state.as_str(),
    );
    retain_portability_capture_unavailable_with_reason(
        report,
        context.suite,
        context.name,
        &reason,
    );
    report.check(context.name, context.suite_started.elapsed(), Err(reason));
    if checkpoint_failed {
        return Err(FailureKind::Fixture);
    }
    checkpoint_attributed_phase_complete(
        report,
        context.suite,
        Some(context.envelope.report_completion_deadline),
    )?;
    Err(FailureKind::Child)
}

fn emit_attributed_progress(
    suite: &str,
    phase: &str,
    event: &str,
    elapsed: Duration,
    remaining: Duration,
) {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "hell-ci-progress suite={suite} phase={phase} event={event} elapsedMillis={} remainingMillis={}",
        elapsed.as_millis(),
        remaining.as_millis()
    );
    let _ = stderr.flush();
}

fn emit_attributed_progress_with_deadlines(
    context: AttributedRunContext<'_>,
    event: &str,
    progress: &PortabilityChildProgress,
) {
    let attribution = progress.attribution();
    let now = Instant::now();
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(
        stderr,
        "hell-ci-progress suite={} phase={} event={event} elapsedMillis={} executionRemainingMillis={} cleanupRemainingMillis={} reportRemainingMillis={} sequence={} target={} case={} caseState={} subphase={}",
        context.suite,
        context.name,
        context.suite_started.elapsed().as_millis(),
        context
            .envelope
            .execution
            .saturating_duration_since(now)
            .as_millis(),
        context
            .envelope
            .child_completion_deadline
            .saturating_duration_since(now)
            .as_millis(),
        context
            .envelope
            .report_completion_deadline
            .saturating_duration_since(now)
            .as_millis(),
        attribution.sequence,
        attribution.target.as_deref().unwrap_or("-"),
        attribution.case.as_deref().unwrap_or("-"),
        attribution.case_state.as_deref().unwrap_or("-"),
        attribution.subphase.as_deref().unwrap_or("-"),
    );
    let _ = stderr.flush();
}

fn run_portability_cargo_command(
    root: &Path,
    report: &mut Report,
    name: &str,
    arguments: &[&str],
    suite_started: Instant,
    child_deadline: Instant,
    completion_deadline: Instant,
) -> Result<(), FailureKind> {
    run_attributed_cargo_command(
        root,
        report,
        arguments,
        AttributedRunContext {
            name,
            suite: "portability",
            suite_started,
            envelope: SupervisionEnvelope {
                execution: child_deadline,
                child_completion_deadline: completion_deadline,
                report_completion_deadline: completion_deadline,
            },
        },
        None,
    )
}

fn run_attributed_cargo_command(
    root: &Path,
    report: &mut Report,
    arguments: &[&str],
    context: AttributedRunContext<'_>,
    seed: Option<(&str, &str, &str)>,
) -> Result<(), FailureKind> {
    run_attributed_command(report, context, seed, |timeout| {
        CommandSpec::cargo(timeout)
            .arguments(arguments.iter().copied())
            .current_directory(root)
    })
}

fn run_attributed_command(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    seed: Option<(&str, &str, &str)>,
    build_spec: impl FnOnce(Duration) -> CommandSpec,
) -> Result<(), FailureKind> {
    let name = context.name;
    let suite = context.suite;
    let suite_started = context.suite_started;
    let child_deadline = context.envelope.execution;
    let child_completion_deadline = context.envelope.child_completion_deadline;
    let report_completion_deadline = context.envelope.report_completion_deadline;
    let mut child_progress = seed.map_or_else(PortabilityChildProgress::default, |seed| {
        PortabilityChildProgress::seeded(suite, seed.0, seed.1, seed.2)
    });
    child_progress.suite = suite;
    let AttributedCommandWorker {
        spec,
        command_started,
        worker_receipt_id,
        worker_receipt,
        progress_receiver,
        progress_loss,
        terminal_receiver,
    } = launch_attributed_command_worker(report, context, &mut child_progress, build_spec)?;
    let mut checkpoint_error = None;
    let result = wait_for_attributed_command_worker(
        report,
        context,
        &mut child_progress,
        &progress_receiver,
        &progress_loss,
        &terminal_receiver,
        &mut checkpoint_error,
    );
    drain_portability_progress(&progress_receiver, &mut child_progress, name);
    child_progress.retain_partial_line_evidence(report, name);
    retain_attributed_worker_receipt(
        report,
        suite,
        name,
        &worker_receipt,
        cleanup_observation_deadline(
            terminal_receipt_deadline(child_completion_deadline, report_completion_deadline),
            report_completion_deadline,
        ),
    );
    let (worker_state, case_state) = attributed_worker_terminal_state(&result);
    child_progress.record_terminal(name, case_state);
    if checkpoint_error.is_none()
        && let Err(error) = report.checkpoint_phase_attribution_deadlines(
            name,
            suite_started.elapsed(),
            child_progress.attribution(),
            child_deadline.saturating_duration_since(Instant::now()),
            child_completion_deadline.saturating_duration_since(Instant::now()),
            report_completion_deadline.saturating_duration_since(Instant::now()),
        )
    {
        checkpoint_error = Some(error.to_string());
    }
    retain_portability_terminal_attribution(
        report,
        suite,
        name,
        &child_progress,
        progress_loss.snapshot(),
        Some(worker_receipt_id),
        worker_state,
    );
    let result = resolve_attributed_worker_outcome(report, context, command_started, result)?;
    retain_portability_terminal_capture(
        report,
        suite,
        name,
        &result,
        cleanup_observation_deadline(
            terminal_receipt_deadline(child_completion_deadline, report_completion_deadline),
            report_completion_deadline,
        ),
    );
    let result = match result {
        Ok(result) => {
            report.command(name, &spec, &result);
            Ok(result)
        }
        Err(error) => {
            report.command_error(name, &spec, command_started.elapsed(), &error);
            Err(error)
        }
    };
    emit_attributed_progress_with_deadlines(context, "terminal", &child_progress);
    if let Some(ref error) = checkpoint_error {
        report.check(
            format!("{suite}-report-checkpoint"),
            Duration::ZERO,
            Err(format!("cannot update {suite} progress: {error}")),
        );
    }
    checkpoint_attributed_phase_complete(report, suite, Some(report_completion_deadline))?;
    let result = result.map_err(|_| FailureKind::Child)?;
    if result.status.success() && !result.timed_out && checkpoint_error.is_none() {
        Ok(())
    } else {
        Err(FailureKind::Child)
    }
}

fn retain_attributed_worker_receipt(
    report: &mut Report,
    suite: &str,
    phase: &str,
    receipt: &AttributedWorkerReceipt,
    deadline: Instant,
) {
    let state = match receipt.wait_until(deadline) {
        AttributedWorkerState::Owned => "owned",
        AttributedWorkerState::Completed => "completed",
        AttributedWorkerState::Panicked => "panicked",
        AttributedWorkerState::Rejected => "rejected",
    };
    report.evidence(
        format!("{suite}-worker-receipt"),
        JsonValue::Object(BTreeMap::from([
            ("phase".to_owned(), JsonValue::String(phase.to_owned())),
            ("workerReceiptId".to_owned(), JsonValue::Number(receipt.id)),
            (
                "workerState".to_owned(),
                JsonValue::String(state.to_owned()),
            ),
        ])),
    );
}

fn attributed_worker_terminal_state(
    result: &AttributedCommandOutcome,
) -> (&'static str, PortabilityCaseState) {
    match result {
        PortabilityWorkerOutcome::Complete(Ok(result)) if result.timed_out => {
            ("completed", PortabilityCaseState::TimedOutCleaned)
        }
        PortabilityWorkerOutcome::Complete(Ok(result)) if !result.status.success() => {
            ("failed", PortabilityCaseState::Failed)
        }
        PortabilityWorkerOutcome::Complete(Ok(_)) => ("completed", PortabilityCaseState::Completed),
        PortabilityWorkerOutcome::Complete(Err(error))
            if error.retained_cleanup_receipt().is_some() =>
        {
            ("cleanup-retained", PortabilityCaseState::Retained)
        }
        PortabilityWorkerOutcome::Complete(Err(_)) => ("failed", PortabilityCaseState::Failed),
        PortabilityWorkerOutcome::CompletionDeadlineExpired => {
            ("retained", PortabilityCaseState::Retained)
        }
        PortabilityWorkerOutcome::ReceiptDisconnected => (
            "receipt-disconnected",
            PortabilityCaseState::ReceiptDisconnected,
        ),
        PortabilityWorkerOutcome::Panicked => ("panicked", PortabilityCaseState::Panicked),
    }
}

fn resolve_attributed_worker_outcome(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    command_started: Instant,
    outcome: AttributedCommandOutcome,
) -> Result<AttributedCommandResult, FailureKind> {
    let reason = match outcome {
        PortabilityWorkerOutcome::Complete(result) => return Ok(result),
        PortabilityWorkerOutcome::CompletionDeadlineExpired => {
            format!(
                "{} command exceeded its absolute completion deadline",
                context.suite
            )
        }
        PortabilityWorkerOutcome::ReceiptDisconnected => {
            format!("{} command terminal receipt disconnected", context.suite)
        }
        PortabilityWorkerOutcome::Panicked => {
            format!("{} command worker panicked", context.suite)
        }
    };
    retain_portability_capture_unavailable(report, context.suite, context.name);
    report.check(context.name, command_started.elapsed(), Err(reason));
    checkpoint_attributed_phase_complete(
        report,
        context.suite,
        Some(context.envelope.report_completion_deadline),
    )?;
    Err(FailureKind::Child)
}

fn wait_for_attributed_command_worker(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    child_progress: &mut PortabilityChildProgress,
    progress_receiver: &mpsc::Receiver<hell_testkit::SupervisedProgressChunk>,
    progress_loss: &hell_testkit::SupervisedProgressLossReceipt,
    terminal_receiver: &mpsc::Receiver<AttributedWorkerTerminal>,
    checkpoint_error: &mut Option<String>,
) -> AttributedCommandOutcome {
    let child_deadline = context.envelope.execution;
    let child_completion_deadline = context.envelope.child_completion_deadline;
    let report_completion_deadline = context.envelope.report_completion_deadline;
    let mut next_checkpoint = Instant::now()
        .checked_add(PORTABILITY_PROGRESS_INTERVAL)
        .unwrap_or(child_completion_deadline)
        .min(child_completion_deadline);
    loop {
        drain_portability_progress(progress_receiver, child_progress, context.name);
        let remaining = child_completion_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            child_progress.emit_summary(context.name, progress_loss.snapshot());
            child_progress.record_attribution(
                context.name,
                PortabilityAttributionEvent::Subphase("awaiting-terminal-receipt".to_owned()),
            );
            if let Err(error) = report.checkpoint_phase_attribution_deadlines(
                context.name,
                context.suite_started.elapsed(),
                child_progress.attribution(),
                Duration::ZERO,
                Duration::ZERO,
                report_completion_deadline.saturating_duration_since(Instant::now()),
            ) {
                *checkpoint_error = Some(error.to_string());
                report.check(
                    format!("{}-report-checkpoint", context.suite),
                    Duration::ZERO,
                    Err(format!("cannot persist cleanup transition: {error}")),
                );
            }
            return match receive_portability_terminal(
                terminal_receiver,
                terminal_receipt_deadline(child_completion_deadline, report_completion_deadline),
            ) {
                PortabilityTerminal::Complete(AttributedWorkerTerminal::Complete(result)) => {
                    PortabilityWorkerOutcome::Complete(result)
                }
                PortabilityTerminal::Complete(AttributedWorkerTerminal::Panicked) => {
                    PortabilityWorkerOutcome::Panicked
                }
                PortabilityTerminal::Disconnected => PortabilityWorkerOutcome::ReceiptDisconnected,
                PortabilityTerminal::Pending => PortabilityWorkerOutcome::CompletionDeadlineExpired,
            };
        }
        match receive_portability_terminal(terminal_receiver, child_completion_deadline) {
            PortabilityTerminal::Complete(AttributedWorkerTerminal::Complete(result)) => {
                drain_portability_progress(progress_receiver, child_progress, context.name);
                child_progress.emit_summary(context.name, progress_loss.snapshot());
                return PortabilityWorkerOutcome::Complete(result);
            }
            PortabilityTerminal::Complete(AttributedWorkerTerminal::Panicked) => {
                child_progress.emit_summary(context.name, progress_loss.snapshot());
                return PortabilityWorkerOutcome::Panicked;
            }
            PortabilityTerminal::Disconnected => {
                child_progress.emit_summary(context.name, progress_loss.snapshot());
                return PortabilityWorkerOutcome::ReceiptDisconnected;
            }
            PortabilityTerminal::Pending if Instant::now() >= next_checkpoint => {
                emit_attributed_progress_with_deadlines(context, "running", child_progress);
                if checkpoint_error.is_none()
                    && let Err(error) = report.checkpoint_phase_attribution_deadlines(
                        context.name,
                        context.suite_started.elapsed(),
                        child_progress.attribution(),
                        child_deadline.saturating_duration_since(Instant::now()),
                        child_completion_deadline.saturating_duration_since(Instant::now()),
                        report_completion_deadline.saturating_duration_since(Instant::now()),
                    )
                {
                    *checkpoint_error = Some(error.to_string());
                }
                next_checkpoint = Instant::now()
                    .checked_add(PORTABILITY_PROGRESS_INTERVAL)
                    .unwrap_or(child_completion_deadline)
                    .min(child_completion_deadline);
            }
            PortabilityTerminal::Pending => {}
        }
    }
}

struct AttributedCommandWorker {
    spec: CommandSpec,
    command_started: Instant,
    worker_receipt_id: u64,
    worker_receipt: AttributedWorkerReceipt,
    progress_receiver: mpsc::Receiver<hell_testkit::SupervisedProgressChunk>,
    progress_loss: hell_testkit::SupervisedProgressLossReceipt,
    terminal_receiver: mpsc::Receiver<AttributedWorkerTerminal>,
}

fn launch_attributed_command_worker(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    child_progress: &mut PortabilityChildProgress,
    build_spec: impl FnOnce(Duration) -> CommandSpec,
) -> Result<AttributedCommandWorker, FailureKind> {
    let suite = context.suite;
    let child_deadline = context.envelope.execution;
    let child_completion_deadline = context.envelope.child_completion_deadline;
    let timeout = child_deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        if let Err(error) =
            checkpoint_attributed_phase_with_progress(report, context, child_progress)
        {
            report.check(
                format!("{suite}-report-checkpoint"),
                Duration::ZERO,
                Err(format!("cannot persist prelaunch {suite} phase: {error:?}")),
            );
        }
        return fail_attributed_prelaunch(
            report,
            context,
            child_progress,
            None,
            PortabilityCaseState::LaunchFailed,
            format!("{suite} child deadline expired before launch"),
        );
    }
    checkpoint_attributed_phase_with_progress(report, context, child_progress)?;
    let spec = build_spec(timeout);
    let command_started = Instant::now();
    let worker_sender = match attributed_worker_sender() {
        Ok(sender) => sender,
        Err(error) => {
            return fail_attributed_prelaunch(
                report,
                context,
                child_progress,
                None,
                PortabilityCaseState::LaunchFailed,
                error,
            );
        }
    };
    let worker_permit = match PortabilityWorkerPermit::acquire() {
        Ok(permit) => permit,
        Err(error) => {
            return fail_attributed_prelaunch(
                report,
                context,
                child_progress,
                None,
                PortabilityCaseState::LaunchFailed,
                error,
            );
        }
    };
    let worker_receipt_id = worker_permit.id;
    let worker_receipt = AttributedWorkerReceipt::new(worker_receipt_id);
    let (progress, progress_receiver) =
        SupervisedProgressObserver::bounded(PORTABILITY_PROGRESS_QUEUE_CAPACITY);
    let progress_loss = progress.loss_receipt();
    let (terminal_sender, terminal_receiver) = mpsc::sync_channel(1);
    if worker_sender
        .send(AttributedWorkerTask {
            spec: spec.clone(),
            execution_deadline: child_deadline,
            child_completion_deadline,
            progress,
            terminal: terminal_sender,
            receipt: worker_receipt.clone(),
            permit: worker_permit,
        })
        .is_err()
    {
        worker_receipt.finish(AttributedWorkerState::Rejected);
        return fail_attributed_prelaunch(
            report,
            context,
            child_progress,
            Some(worker_receipt_id),
            PortabilityCaseState::LaunchFailed,
            "attributed command executor disconnected before launch".to_owned(),
        );
    }
    Ok(AttributedCommandWorker {
        spec,
        command_started,
        worker_receipt_id,
        worker_receipt,
        progress_receiver,
        progress_loss,
        terminal_receiver,
    })
}

fn retain_portability_terminal_attribution(
    report: &mut Report,
    suite: &str,
    phase: &str,
    progress: &PortabilityChildProgress,
    loss: hell_testkit::SupervisedProgressLoss,
    worker_receipt_id: Option<u64>,
    worker_state: &str,
) {
    let attribution = progress.attribution();
    let (failed_case, failed_case_unavailable) =
        portability_failed_case_evidence(progress, loss, worker_state);
    report.evidence(
        format!("{suite}-terminal-attribution"),
        JsonValue::Object(BTreeMap::from([
            (
                "case".to_owned(),
                attribution.case.map_or(JsonValue::Null, JsonValue::String),
            ),
            (
                "caseState".to_owned(),
                attribution
                    .case_state
                    .map_or(JsonValue::Null, JsonValue::String),
            ),
            ("droppedBytes".to_owned(), JsonValue::Number(loss.bytes)),
            ("droppedChunks".to_owned(), JsonValue::Number(loss.chunks)),
            ("failedCase".to_owned(), failed_case),
            ("failedCaseUnavailable".to_owned(), failed_case_unavailable),
            ("phase".to_owned(), JsonValue::String(phase.to_owned())),
            (
                "sequence".to_owned(),
                JsonValue::Number(attribution.sequence),
            ),
            (
                "stderrObservedBytes".to_owned(),
                JsonValue::Number(progress.stderr_observed),
            ),
            (
                "stderrRelayedBytes".to_owned(),
                JsonValue::Number(u64::try_from(progress.stderr_relayed).unwrap_or(u64::MAX)),
            ),
            (
                "stdoutObservedBytes".to_owned(),
                JsonValue::Number(progress.stdout_observed),
            ),
            (
                "stdoutRelayedBytes".to_owned(),
                JsonValue::Number(u64::try_from(progress.stdout_relayed).unwrap_or(u64::MAX)),
            ),
            (
                "subphase".to_owned(),
                attribution
                    .subphase
                    .map_or(JsonValue::Null, JsonValue::String),
            ),
            (
                "target".to_owned(),
                attribution
                    .target
                    .map_or(JsonValue::Null, JsonValue::String),
            ),
            (
                "transitionElapsedMillis".to_owned(),
                attribution
                    .transition_elapsed
                    .map_or(JsonValue::Null, |elapsed| {
                        JsonValue::Number(u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
                    }),
            ),
            (
                "workerReceiptId".to_owned(),
                worker_receipt_id.map_or(JsonValue::Null, JsonValue::Number),
            ),
            (
                "workerState".to_owned(),
                JsonValue::String(worker_state.to_owned()),
            ),
        ])),
    );
}

fn portability_failed_case_evidence(
    progress: &PortabilityChildProgress,
    loss: hell_testkit::SupervisedProgressLoss,
    worker_state: &str,
) -> (JsonValue, JsonValue) {
    let failed_case = (worker_state == "failed")
        .then_some(progress.failed_case.as_ref())
        .flatten()
        .map_or(JsonValue::Null, |failed| {
            JsonValue::Object(BTreeMap::from([
                ("case".to_owned(), JsonValue::String(failed.case.clone())),
                ("sequence".to_owned(), JsonValue::Number(failed.sequence)),
                (
                    "stream".to_owned(),
                    JsonValue::String(failed.stream.clone()),
                ),
                (
                    "target".to_owned(),
                    failed
                        .target
                        .clone()
                        .map_or(JsonValue::Null, JsonValue::String),
                ),
            ]))
        });
    let unavailable = if progress.failed_case.is_none() && worker_state == "failed" {
        failed_case_unavailable_reason(progress, loss, progress.failed_case.is_some())
            .map_or(JsonValue::Null, JsonValue::String)
    } else {
        JsonValue::Null
    };
    (failed_case, unavailable)
}

fn retain_portability_terminal_capture(
    report: &mut Report,
    suite: &str,
    phase: &str,
    result: &Result<crate::command::CommandResult, crate::command::CommandRunError>,
    observation_deadline: Instant,
) {
    let capture = match result {
        Ok(result) => Some(result),
        Err(error) => error.completed(),
    };
    let mut evidence = BTreeMap::from([("phase".to_owned(), JsonValue::String(phase.to_owned()))]);
    match capture {
        Some(capture) => retain_completed_portability_capture(&mut evidence, capture),
        None => {
            evidence.insert(
                "captureState".to_owned(),
                JsonValue::String("unavailable".to_owned()),
            );
        }
    }
    if let Err(error) = result {
        retain_portability_cleanup_receipt(&mut evidence, error, observation_deadline);
        if let Some(receipt) = error.supervised_io_receipt() {
            let snapshot = receipt.wait_until(observation_deadline);
            retain_supervised_io_snapshot(&mut evidence, &snapshot);
        }
        if let Some(receipt) = error.candidate_quiescence_receipt() {
            match receipt.state() {
                hell_testkit::CandidateQuiescenceState::Owned => {
                    evidence.insert(
                        "candidateQuiescenceState".to_owned(),
                        JsonValue::String("owned".to_owned()),
                    );
                }
                hell_testkit::CandidateQuiescenceState::Completed => {
                    evidence.insert(
                        "candidateQuiescenceState".to_owned(),
                        JsonValue::String("completed".to_owned()),
                    );
                }
                hell_testkit::CandidateQuiescenceState::Failed(error) => {
                    evidence.insert(
                        "candidateQuiescenceState".to_owned(),
                        JsonValue::String("failed".to_owned()),
                    );
                    evidence.insert(
                        "candidateQuiescenceError".to_owned(),
                        JsonValue::String(error),
                    );
                }
            }
        }
    }
    report.evidence(
        format!("{suite}-terminal-capture"),
        JsonValue::Object(evidence),
    );
}

fn retain_completed_portability_capture(
    evidence: &mut BTreeMap<String, JsonValue>,
    capture: &crate::command::CommandResult,
) {
    evidence.insert(
        "captureState".to_owned(),
        JsonValue::String("complete".to_owned()),
    );
    evidence.insert(
        "stdoutBytes".to_owned(),
        JsonValue::Number(capture.stdout_bytes),
    );
    evidence.insert(
        "stdoutSha256".to_owned(),
        JsonValue::String(capture.stdout_sha256.hex()),
    );
    evidence.insert(
        "stderrBytes".to_owned(),
        JsonValue::Number(capture.stderr_bytes),
    );
    evidence.insert(
        "stderrSha256".to_owned(),
        JsonValue::String(capture.stderr_sha256.hex()),
    );
    evidence.insert(
        "stdoutTruncated".to_owned(),
        JsonValue::Bool(capture.stdout_truncated),
    );
    evidence.insert(
        "stderrTruncated".to_owned(),
        JsonValue::Bool(capture.stderr_truncated),
    );
    evidence.insert(
        "cleanupReceiptId".to_owned(),
        capture
            .termination
            .cleanup_id
            .map_or(JsonValue::Null, JsonValue::Number),
    );
    evidence.insert(
        "cleanupState".to_owned(),
        JsonValue::String("completed".to_owned()),
    );
    evidence.insert("lifecycleIdle".to_owned(), JsonValue::Bool(true));
    evidence.insert(
        "terminationForced".to_owned(),
        JsonValue::Bool(capture.termination.forced),
    );
    evidence.insert(
        "terminationReaped".to_owned(),
        JsonValue::Bool(capture.termination.reaped),
    );
    evidence.insert(
        "processGroupTerminationRequested".to_owned(),
        JsonValue::Bool(capture.termination.forced),
    );
    evidence.insert(
        "leaderReaped".to_owned(),
        JsonValue::Bool(capture.termination.reaped),
    );
    evidence.insert(
        "candidateQuiescenceComplete".to_owned(),
        JsonValue::Bool(capture.termination.candidate_quiescence_complete),
    );
}

fn retain_portability_cleanup_receipt(
    evidence: &mut BTreeMap<String, JsonValue>,
    error: &crate::command::CommandRunError,
    observation_deadline: Instant,
) {
    let Some(receipt) = error.retained_cleanup_receipt() else {
        return;
    };
    let snapshot = receipt.wait_until(observation_deadline);
    evidence.insert(
        "cleanupReceiptId".to_owned(),
        JsonValue::Number(receipt.id()),
    );
    match snapshot.state {
        hell_testkit::RetainedTerminationState::Owned => {
            evidence.insert(
                "cleanupState".to_owned(),
                JsonValue::String("owned".to_owned()),
            );
        }
        hell_testkit::RetainedTerminationState::Completed(termination) => {
            evidence.insert(
                "cleanupState".to_owned(),
                JsonValue::String("completed".to_owned()),
            );
            evidence.insert(
                "terminationForced".to_owned(),
                JsonValue::Bool(termination.forced),
            );
            evidence.insert(
                "terminationReaped".to_owned(),
                JsonValue::Bool(termination.reaped),
            );
        }
        hell_testkit::RetainedTerminationState::Failed(cleanup) => {
            evidence.insert(
                "cleanupState".to_owned(),
                JsonValue::String("failed".to_owned()),
            );
            evidence.insert("cleanupError".to_owned(), JsonValue::String(cleanup));
        }
    }
    evidence.insert(
        "lifecycleIdle".to_owned(),
        JsonValue::Bool(snapshot.lifecycle_idle),
    );
}

fn retain_supervised_io_snapshot(
    evidence: &mut BTreeMap<String, JsonValue>,
    snapshot: &hell_testkit::SupervisedIoSnapshot,
) {
    for (name, task) in [
        ("stdout", &snapshot.stdout),
        ("stderr", &snapshot.stderr),
        ("stdin", &snapshot.stdin),
    ] {
        evidence.insert(
            format!("{name}TaskState"),
            JsonValue::String(task.state.as_str().to_owned()),
        );
        if let Some(bytes) = task.bytes {
            evidence.insert(format!("{name}TaskBytes"), JsonValue::Number(bytes));
        }
        if let Some(digest) = task.sha256 {
            evidence.insert(format!("{name}TaskSha256"), JsonValue::String(digest.hex()));
        }
        if let Some(truncated) = task.truncated {
            evidence.insert(format!("{name}TaskTruncated"), JsonValue::Bool(truncated));
        }
        if let Some(error) = &task.error {
            evidence.insert(format!("{name}TaskError"), JsonValue::String(error.clone()));
        }
    }
}

fn retain_portability_capture_unavailable(report: &mut Report, suite: &str, phase: &str) {
    retain_portability_capture_unavailable_with_reason(
        report,
        suite,
        phase,
        "terminal capture unavailable",
    );
}

fn retain_portability_capture_unavailable_with_reason(
    report: &mut Report,
    suite: &str,
    phase: &str,
    reason: &str,
) {
    report.evidence(
        format!("{suite}-terminal-capture"),
        JsonValue::Object(BTreeMap::from([
            (
                "captureState".to_owned(),
                JsonValue::String("unavailable".to_owned()),
            ),
            ("phase".to_owned(), JsonValue::String(phase.to_owned())),
            ("reason".to_owned(), JsonValue::String(reason.to_owned())),
        ])),
    );
}

enum PortabilityTerminal<T> {
    Complete(T),
    Pending,
    Disconnected,
}

fn receive_portability_terminal<T>(
    receiver: &mpsc::Receiver<T>,
    completion_deadline: Instant,
) -> PortabilityTerminal<T> {
    let wait = completion_deadline
        .saturating_duration_since(Instant::now())
        .min(PORTABILITY_PROGRESS_DRAIN_INTERVAL);
    match receiver.recv_timeout(wait) {
        Ok(result) => PortabilityTerminal::Complete(result),
        Err(mpsc::RecvTimeoutError::Timeout) => PortabilityTerminal::Pending,
        Err(mpsc::RecvTimeoutError::Disconnected) => PortabilityTerminal::Disconnected,
    }
}

fn drain_portability_progress(
    receiver: &mpsc::Receiver<hell_testkit::SupervisedProgressChunk>,
    progress: &mut PortabilityChildProgress,
    phase: &str,
) {
    for _ in 0..PORTABILITY_PROGRESS_QUEUE_CAPACITY {
        let Ok(chunk) = receiver.try_recv() else {
            break;
        };
        progress.observe(phase, chunk.stream, &chunk.bytes);
    }
}

#[cfg(windows)]
#[derive(Clone, Copy)]
enum WindowsHellTestkitDiagnosticTarget {
    Library(&'static str),
    Integration {
        binary: &'static str,
        test: &'static str,
    },
}

#[cfg(windows)]
const WINDOWS_HELL_TESTKIT_DIAGNOSTIC_CASES: &[(&str, WindowsHellTestkitDiagnosticTarget)] = &[
    (
        "windows-hell-testkit-unmapped-stack-environment",
        WindowsHellTestkitDiagnosticTarget::Library(
            "windows_restricted_environment_tests::unmapped_stack_launch_receives_revalidated_path_and_system_root",
        ),
    ),
    (
        "windows-hell-testkit-mapped-cargo-environment",
        WindowsHellTestkitDiagnosticTarget::Library(
            "windows_restricted_environment_tests::mapped_cargo_launch_rewrites_path_and_keeps_system_root",
        ),
    ),
    (
        "windows-hell-testkit-ord-coverage",
        WindowsHellTestkitDiagnosticTarget::Integration {
            binary: "ord_coverage",
            test: "ord_targets_require_both_boolean_paths_for_every_registry_instance",
        },
    ),
    (
        "windows-hell-testkit-monad-traversal-coverage",
        WindowsHellTestkitDiagnosticTarget::Library(
            "evidence_catalog_tests::monad_traversals_require_both_paths_for_every_direct_instance",
        ),
    ),
];

#[cfg(windows)]
fn windows_hell_testkit_diagnostic_commands() -> Vec<(&'static str, Vec<&'static str>)> {
    WINDOWS_HELL_TESTKIT_DIAGNOSTIC_CASES
        .iter()
        .map(|&(name, target)| {
            let mut arguments = vec!["test", "--package", "hell-testkit"];
            let test = match target {
                WindowsHellTestkitDiagnosticTarget::Library(test) => {
                    arguments.push("--lib");
                    test
                }
                WindowsHellTestkitDiagnosticTarget::Integration { binary, test } => {
                    arguments.extend(["--test", binary]);
                    test
                }
            };
            arguments.extend([
                "--all-features",
                "--locked",
                test,
                "--",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ]);
            (name, arguments)
        })
        .collect()
}

#[cfg(windows)]
pub(crate) fn verify_windows_hell_testkit_diagnostics_for_integration() -> Result<(), String> {
    let commands = windows_hell_testkit_diagnostic_commands();
    let expected = vec![
        (
            "windows-hell-testkit-unmapped-stack-environment",
            vec![
                "test",
                "--package",
                "hell-testkit",
                "--lib",
                "--all-features",
                "--locked",
                "windows_restricted_environment_tests::unmapped_stack_launch_receives_revalidated_path_and_system_root",
                "--",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ],
        ),
        (
            "windows-hell-testkit-mapped-cargo-environment",
            vec![
                "test",
                "--package",
                "hell-testkit",
                "--lib",
                "--all-features",
                "--locked",
                "windows_restricted_environment_tests::mapped_cargo_launch_rewrites_path_and_keeps_system_root",
                "--",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ],
        ),
        (
            "windows-hell-testkit-ord-coverage",
            vec![
                "test",
                "--package",
                "hell-testkit",
                "--test",
                "ord_coverage",
                "--all-features",
                "--locked",
                "ord_targets_require_both_boolean_paths_for_every_registry_instance",
                "--",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ],
        ),
        (
            "windows-hell-testkit-monad-traversal-coverage",
            vec![
                "test",
                "--package",
                "hell-testkit",
                "--lib",
                "--all-features",
                "--locked",
                "evidence_catalog_tests::monad_traversals_require_both_paths_for_every_direct_instance",
                "--",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ],
        ),
    ];
    if commands != expected {
        return Err(format!(
            "Windows hell-testkit diagnostic commands differ: {commands:?}"
        ));
    }

    let workspace = portable_workspace_test_arguments();
    if workspace.contains(&"--") || workspace.contains(&"--skip") {
        return Err("portable workspace diagnostics skip authoritative coverage".to_owned());
    }
    let mut diagnostics = 0;
    if preserve_workspace_result_with_diagnostics(Ok(()), || diagnostics += 1) != Ok(())
        || diagnostics != 0
    {
        return Err("passing workspace coverage duplicated diagnostics".to_owned());
    }
    if preserve_workspace_result_with_diagnostics(Err(FailureKind::Child), || {
        diagnostics += commands.len();
    }) != Err(FailureKind::Child)
        || diagnostics != WINDOWS_HELL_TESTKIT_DIAGNOSTIC_CASES.len()
    {
        return Err("workspace failure diagnostics changed the authoritative result".to_owned());
    }
    if WINDOWS_HELL_TESTKIT_DIAGNOSTIC_TIMEOUT != PORTABILITY_CLEANUP_RESERVE {
        return Err(
            "Windows diagnostic deadline differs from the shared cleanup reserve".to_owned(),
        );
    }
    let launched = std::cell::Cell::new(false);
    if run_before_portability_deadline(Instant::now(), "expired Windows diagnostic", || {
        launched.set(true);
        Ok(())
    })
    .is_ok()
        || launched.get()
    {
        return Err("expired Windows diagnostics launched late work".to_owned());
    }
    Ok(())
}

#[cfg(windows)]
fn preserve_workspace_result_with_diagnostics(
    workspace_result: Result<(), FailureKind>,
    diagnostics: impl FnOnce(),
) -> Result<(), FailureKind> {
    if workspace_result.is_err() {
        diagnostics();
    }
    workspace_result
}

fn portable_workspace_base_arguments() -> Vec<&'static str> {
    vec![
        "test",
        "--workspace",
        "--all-targets",
        "--all-features",
        "--locked",
    ]
}

#[cfg(target_os = "macos")]
fn portable_workspace_test_arguments() -> Vec<&'static str> {
    let mut arguments = portable_workspace_base_arguments();
    arguments.extend(["--", "--skip", MACOS_STAGED_NATIVE_TOOLCHAIN_CASE]);
    arguments
}

#[cfg(not(target_os = "macos"))]
fn portable_workspace_test_arguments() -> Vec<&'static str> {
    portable_workspace_base_arguments()
}

pub(crate) fn release_verify(
    root: &Path,
    report: &mut Report,
    failures: &Path,
) -> Result<(), FailureKind> {
    policy_suite(root, report)?;
    fixture_gate(root, report, failures)
}

pub(crate) fn release_portability(
    root: &Path,
    report: &mut Report,
    failures: &Path,
) -> Result<(), FailureKind> {
    policy_suite(root, report)?;
    fixture_gate(root, report, failures)
}

pub(crate) fn dependency_attestation(
    root: &Path,
    output: &Path,
    report: &mut Report,
) -> Result<(), FailureKind> {
    let started = Instant::now();
    let result = git_commit(root)
        .and_then(|candidate| dependency_attestation_for(root, output, &candidate, "nightly.yml"));
    let passed = result.is_ok();
    report.check("dependency-attestation", started.elapsed(), result);
    passed.then_some(()).ok_or(FailureKind::Fixture)
}

fn git_commit(root: &Path) -> Result<String, String> {
    let result = CommandSpec::new("git", Duration::from_secs(30))
        .git_safe_directory(root)
        .arguments(["rev-parse", "HEAD"])
        .current_directory(root)
        .run()
        .map_err(|error| format!("cannot resolve dependency checkout: {error}"))?;
    if !result.status.success() || result.timed_out {
        return Err("dependency checkout identity command failed".to_owned());
    }
    let commit = std::str::from_utf8(&result.stdout)
        .map_err(|_| "dependency checkout identity is not UTF-8".to_owned())?
        .trim()
        .to_owned();
    require_git_sha(&commit, "dependency checkout")?;
    Ok(commit)
}

pub(crate) fn release_dependency_attestation(
    root: &Path,
    output: &Path,
    candidate_sha: &str,
) -> Result<(), String> {
    dependency_attestation_for(root, output, candidate_sha, "release.yml")
}

fn dependency_attestation_for(
    root: &Path,
    output: &Path,
    candidate_sha: &str,
    workflow: &str,
) -> Result<(), String> {
    require_git_sha(candidate_sha, "dependency candidate SHA")?;
    let lock = root.join("Cargo.lock");
    let digest = sha256_file(&lock)
        .map_err(|error| format!("cannot hash {}: {error}", lock.display()))?
        .hex();
    let document = JsonValue::Object(BTreeMap::from([
        (
            "candidateSourceCommit".to_owned(),
            JsonValue::String(candidate_sha.to_owned()),
        ),
        ("cargoLockSha256".to_owned(), JsonValue::String(digest)),
        (
            "denyPolicySha256".to_owned(),
            JsonValue::String(
                sha256_file(&root.join("deny.toml"))
                    .map_err(|error| format!("cannot hash deny.toml: {error}"))?
                    .hex(),
            ),
        ),
        ("result".to_owned(), JsonValue::String("passed".to_owned())),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
        (
            "workflow".to_owned(),
            JsonValue::String(workflow.to_owned()),
        ),
    ]));
    let bytes = canonical_json_bytes(&document)?;
    crate::release::manifest::write_atomic(output, &bytes)?;
    let name = output
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "dependency attestation output name is not UTF-8".to_owned())?;
    crate::release::manifest::write_atomic(
        &output.with_extension("sha256"),
        format!("{}  {name}\n", sha256_bytes(&bytes).hex()).as_bytes(),
    )
}

#[cfg(any(unix, windows))]
fn external_supervisor_terminal_evidence(
    plan: ExternalSupervisorPlan,
    terminal: &ExternalSupervisorTerminal,
    request_sha256: Digest,
) -> JsonValue {
    let mut evidence = BTreeMap::from([
        (
            "detail".to_owned(),
            JsonValue::String(terminal.detail.clone()),
        ),
        (
            "attribution".to_owned(),
            external_supervisor_attribution_evidence(terminal),
        ),
        (
            "failedCase".to_owned(),
            external_supervisor_failed_case_evidence(terminal),
        ),
        (
            "failedCaseUnavailable".to_owned(),
            terminal
                .failed_case_unavailable
                .clone()
                .map_or(JsonValue::Null, JsonValue::String),
        ),
        (
            "droppedProgressBytes".to_owned(),
            JsonValue::Number(terminal.dropped_bytes),
        ),
        (
            "droppedProgressChunks".to_owned(),
            JsonValue::Number(terminal.dropped_chunks),
        ),
        (
            "exitCode".to_owned(),
            terminal
                .exit_code
                .map_or(JsonValue::Null, |code| JsonValue::String(code.to_string())),
        ),
        ("plan".to_owned(), JsonValue::String(plan.name().to_owned())),
        (
            "requestSha256".to_owned(),
            JsonValue::String(request_sha256.hex()),
        ),
        (
            "stderrBytes".to_owned(),
            JsonValue::Number(terminal.stderr_bytes),
        ),
        (
            "captureState".to_owned(),
            JsonValue::String(
                if terminal.capture.available {
                    "available"
                } else {
                    "unavailable"
                }
                .to_owned(),
            ),
        ),
        (
            "stdoutObservedBytes".to_owned(),
            JsonValue::Number(terminal.stdout_bytes),
        ),
        ("stdoutRelayedBytes".to_owned(), JsonValue::Number(0)),
        (
            "stderrObservedBytes".to_owned(),
            JsonValue::Number(terminal.stderr_bytes),
        ),
        ("stderrRelayedBytes".to_owned(), JsonValue::Number(0)),
        (
            "relayPolicy".to_owned(),
            JsonValue::String("attribution-only-bounded-nonblocking".to_owned()),
        ),
        (
            "stderrSha256".to_owned(),
            JsonValue::String(terminal.stderr_sha256.hex()),
        ),
        (
            "stderrTruncated".to_owned(),
            JsonValue::Bool(terminal.capture.stderr_truncated),
        ),
        (
            "stdoutBytes".to_owned(),
            JsonValue::Number(terminal.stdout_bytes),
        ),
        (
            "stdoutSha256".to_owned(),
            JsonValue::String(terminal.stdout_sha256.hex()),
        ),
        (
            "stdoutTruncated".to_owned(),
            JsonValue::Bool(terminal.capture.stdout_truncated),
        ),
        (
            "success".to_owned(),
            JsonValue::Bool(terminal.execution.success),
        ),
        (
            "timedOut".to_owned(),
            JsonValue::Bool(terminal.execution.timed_out),
        ),
    ]);
    evidence.extend(external_supervisor_cleanup_evidence(terminal));
    JsonValue::Object(evidence)
}

#[cfg(any(unix, windows))]
fn external_supervisor_cleanup_evidence(
    terminal: &ExternalSupervisorTerminal,
) -> BTreeMap<String, JsonValue> {
    BTreeMap::from([
        (
            "cleanupTerminal".to_owned(),
            JsonValue::Bool(terminal.cleanup.terminal),
        ),
        (
            "cleanupState".to_owned(),
            JsonValue::String(terminal.cleanup_state.clone()),
        ),
        (
            "cleanupError".to_owned(),
            terminal
                .cleanup_error
                .clone()
                .map_or(JsonValue::Null, JsonValue::String),
        ),
        (
            "cleanupFailures".to_owned(),
            JsonValue::Array(
                terminal
                    .cleanup_failures
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        ),
        (
            "cleanupId".to_owned(),
            terminal
                .cleanup_id
                .map_or(JsonValue::Null, JsonValue::Number),
        ),
        (
            "processGroupTerminationRequested".to_owned(),
            JsonValue::Bool(terminal.cleanup.termination_requested),
        ),
        (
            "containmentScope".to_owned(),
            JsonValue::String(
                if cfg!(windows) {
                    "supervisor-owned-kill-on-close-job-plus-leader-reap"
                } else {
                    "process-group-termination-request-plus-leader-reap"
                }
                .to_owned(),
            ),
        ),
        (
            "leaderReaped".to_owned(),
            JsonValue::Bool(terminal.cleanup.leader_reaped),
        ),
        (
            "candidateQuiescenceComplete".to_owned(),
            JsonValue::Bool(terminal.candidate_quiescence_complete),
        ),
    ])
}

#[cfg(any(unix, windows))]
fn external_supervisor_attribution_evidence(terminal: &ExternalSupervisorTerminal) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        (
            "case".to_owned(),
            terminal
                .attribution
                .case
                .clone()
                .map_or(JsonValue::Null, JsonValue::String),
        ),
        (
            "caseState".to_owned(),
            terminal
                .attribution
                .case_state
                .clone()
                .map_or(JsonValue::Null, JsonValue::String),
        ),
        (
            "sequence".to_owned(),
            JsonValue::Number(terminal.attribution.sequence),
        ),
        (
            "transitionElapsedMillis".to_owned(),
            terminal
                .attribution
                .transition_elapsed
                .map_or(JsonValue::Null, |elapsed| {
                    JsonValue::Number(u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
                }),
        ),
        (
            "subphase".to_owned(),
            terminal
                .attribution
                .subphase
                .clone()
                .map_or(JsonValue::Null, JsonValue::String),
        ),
        (
            "target".to_owned(),
            terminal
                .attribution
                .target
                .clone()
                .map_or(JsonValue::Null, JsonValue::String),
        ),
    ]))
}

#[cfg(any(unix, windows))]
fn external_supervisor_failed_case_evidence(terminal: &ExternalSupervisorTerminal) -> JsonValue {
    terminal
        .failed_case
        .as_ref()
        .map_or(JsonValue::Null, |failed| {
            JsonValue::Object(BTreeMap::from([
                ("case".to_owned(), JsonValue::String(failed.case.clone())),
                ("sequence".to_owned(), JsonValue::Number(failed.sequence)),
                (
                    "stream".to_owned(),
                    JsonValue::String(failed.stream.clone()),
                ),
                (
                    "target".to_owned(),
                    failed
                        .target
                        .clone()
                        .map_or(JsonValue::Null, JsonValue::String),
                ),
                (
                    "transitionElapsedMillis".to_owned(),
                    failed
                        .transition_elapsed
                        .map_or(JsonValue::Null, |elapsed| {
                            JsonValue::Number(
                                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                            )
                        }),
                ),
            ]))
        })
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WindowsFileReceipt {
    volume: u64,
    index: u64,
    size: u64,
    attributes: u32,
}

#[cfg(windows)]
fn windows_file_receipt(file: &fs::File) -> Result<WindowsFileReceipt, String> {
    use std::hash::{Hash as _, Hasher as _};

    let identity = same_file::Handle::from_file(
        file.try_clone()
            .map_err(|error| format!("cannot clone Windows supervisor file handle: {error}"))?,
    )
    .map_err(|error| format!("cannot bind Windows supervisor file identity: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect Windows supervisor file: {error}"))?;
    let mut volume = std::hash::DefaultHasher::new();
    identity.hash(&mut volume);
    let mut index = std::hash::DefaultHasher::new();
    "hell-windows-file-id-v1".hash(&mut index);
    identity.hash(&mut index);
    Ok(WindowsFileReceipt {
        volume: volume.finish(),
        index: index.finish(),
        size: metadata.len(),
        attributes: metadata.file_attributes(),
    })
}

#[cfg(windows)]
fn windows_open_receipt(path: &Path, directory: bool) -> Result<fs::File, String> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    };

    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        };
    fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(flags)
        .open(path)
        .map_err(|error| format!("cannot retain {}: {error}", path.display()))
}

#[cfg(windows)]
fn windows_bind_path(
    path: &Path,
    directory: bool,
) -> Result<(fs::File, WindowsFileReceipt), String> {
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let file = windows_open_receipt(path, directory)?;
    let receipt = windows_file_receipt(&file)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.is_dir() != directory
        || windows_file_receipt(&file)? != receipt
    {
        return Err(format!(
            "Windows supervisor path authority differs: {}",
            path.display()
        ));
    }
    Ok((file, receipt))
}

#[cfg(windows)]
fn windows_bind_shared_late_receipt(path: &Path) -> Result<(fs::File, WindowsFileReceipt), String> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };

    let file = fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| format!("cannot retain {}: {error}", path.display()))?;
    let receipt = windows_file_receipt(&file)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !metadata.is_file()
        || windows_file_receipt(&file)? != receipt
    {
        return Err(format!(
            "Windows late receipt path authority differs: {}",
            path.display()
        ));
    }
    Ok((file, receipt))
}

#[cfg(windows)]
struct WindowsPartialSessionAuthority<'a> {
    parent_path: &'a Path,
    parent: &'a fs::File,
    parent_receipt: WindowsFileReceipt,
    root_path: &'a Path,
    root: fs::File,
    root_receipt: WindowsFileReceipt,
}

#[cfg(windows)]
fn cleanup_partial_windows_supervisor_session(
    authority: WindowsPartialSessionAuthority<'_>,
    request: Option<(PathBuf, fs::File, WindowsFileReceipt)>,
    deadline: Instant,
) -> Result<(), String> {
    if Instant::now() >= deadline
        || windows_file_receipt(authority.parent)? != authority.parent_receipt
        || windows_bind_path(authority.parent_path, true)?.1 != authority.parent_receipt
        || windows_file_receipt(&authority.root)? != authority.root_receipt
        || windows_bind_path(authority.root_path, true)?.1 != authority.root_receipt
    {
        return Err("partial Windows supervisor session authority changed".to_owned());
    }
    if let Some((request_path, request, request_receipt)) = request {
        if windows_file_receipt(&request)? != request_receipt {
            return Err("partial Windows supervisor ownership receipt changed".to_owned());
        }
        drop(request);
        if Instant::now() >= deadline
            || windows_bind_path(&request_path, false)?.1 != request_receipt
        {
            return Err("partial Windows supervisor ownership path changed".to_owned());
        }
        fs::remove_file(&request_path).map_err(|error| {
            format!("cannot remove partial Windows supervisor ownership receipt: {error}")
        })?;
    }
    if Instant::now() >= deadline
        || windows_file_receipt(authority.parent)? != authority.parent_receipt
        || windows_bind_path(authority.parent_path, true)?.1 != authority.parent_receipt
        || windows_file_receipt(&authority.root)? != authority.root_receipt
        || windows_bind_path(authority.root_path, true)?.1 != authority.root_receipt
    {
        return Err("partial Windows supervisor root changed before cleanup".to_owned());
    }
    drop(authority.root);
    fs::remove_dir(authority.root_path)
        .map_err(|error| format!("cannot remove partial Windows supervisor session: {error}"))
}

#[cfg(windows)]
struct WindowsSupervisorSession {
    parent_path: PathBuf,
    root_path: PathBuf,
    request_path: PathBuf,
    request_digest_path: PathBuf,
    authority_manifest_path: PathBuf,
    late_receipt_path: PathBuf,
    parent: fs::File,
    root: fs::File,
    request: fs::File,
    request_digest: Option<fs::File>,
    authority_manifest: Option<fs::File>,
    late_receipt: Option<fs::File>,
    parent_receipt: WindowsFileReceipt,
    root_receipt: WindowsFileReceipt,
    request_receipt: WindowsFileReceipt,
    request_digest_receipt: Option<WindowsFileReceipt>,
    authority_manifest_receipt: Option<WindowsFileReceipt>,
    late_receipt_receipt: Option<WindowsFileReceipt>,
}

#[cfg(windows)]
struct WindowsLateReceiptAuthority {
    parent_path: PathBuf,
    session_path: PathBuf,
    late_receipt_path: PathBuf,
    parent: fs::File,
    late_receipt: fs::File,
    parent_receipt: WindowsFileReceipt,
    session_receipt: WindowsFileReceipt,
    late_receipt_receipt: WindowsFileReceipt,
}

#[cfg(windows)]
impl WindowsSupervisorSession {
    fn create(parent: &Path, request_bytes: &[u8], deadline: Instant) -> Result<Self, String> {
        let parent = fs::canonicalize(parent)
            .map_err(|error| format!("cannot canonicalize Windows supervisor parent: {error}"))?;
        let (parent_handle, parent_receipt) = windows_bind_path(&parent, true)?;
        for _ in 0..32 {
            if Instant::now() >= deadline {
                return Err(
                    "Windows supervisor session allocation exceeded its deadline".to_owned(),
                );
            }
            let mut random = [0_u8; 16];
            getrandom::getrandom(&mut random)
                .map_err(|error| format!("cannot allocate Windows supervisor nonce: {error}"))?;
            let candidate = parent.join(format!(
                "nightly-supervisor-{}",
                sha256_bytes(&random).hex()
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    let (root, root_receipt) = windows_bind_path(&candidate, true).map_err(|error| {
                        format!(
                            "{error}; newly created Windows supervisor session could not be safely bound and was retained at {}",
                            candidate.display()
                        )
                    })?;
                    let parent_revalidation = windows_bind_path(&parent, true)
                        .map(|(_, receipt)| receipt == parent_receipt);
                    if !matches!(parent_revalidation, Ok(true)) {
                        let primary = parent_revalidation.err().unwrap_or_else(|| {
                            "Windows supervisor parent changed during allocation".to_owned()
                        });
                        let cleanup = cleanup_partial_windows_supervisor_session(
                            WindowsPartialSessionAuthority {
                                parent_path: &parent,
                                parent: &parent_handle,
                                parent_receipt,
                                root_path: &candidate,
                                root,
                                root_receipt,
                            },
                            None,
                            deadline,
                        );
                        return Err(match cleanup {
                            Ok(()) => primary,
                            Err(cleanup) => {
                                format!("{primary}; additionally, cleanup failed: {cleanup}")
                            }
                        });
                    }
                    let request_path = candidate.join("ownership.receipt");
                    let request_setup = (|| {
                        use windows_sys::Win32::Storage::FileSystem::{
                            FILE_SHARE_READ, FILE_SHARE_WRITE,
                        };

                        let mut request = fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .create_new(true)
                            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                            .open(&request_path)
                            .map_err(|error| {
                                format!(
                                    "cannot create Windows supervisor ownership receipt: {error}"
                                )
                            })?;
                        let initial_receipt = windows_file_receipt(&request)?;
                        request.write_all(request_bytes).map_err(|error| {
                            format!("cannot write Windows supervisor ownership receipt: {error}")
                        })?;
                        request.sync_all().map_err(|error| {
                            format!("cannot sync Windows supervisor ownership receipt: {error}")
                        })?;
                        let request_receipt = windows_file_receipt(&request)?;
                        let expected_request_receipt = WindowsFileReceipt {
                            size: u64::try_from(request_bytes.len()).unwrap_or(u64::MAX),
                            ..initial_receipt
                        };
                        if request_receipt != expected_request_receipt {
                            return Err(
                                "Windows supervisor ownership receipt changed during creation"
                                    .to_owned(),
                            );
                        }
                        drop(request);
                        let (request, retained_receipt) = windows_bind_path(&request_path, false)?;
                        if retained_receipt != request_receipt {
                            return Err(
                                "Windows supervisor ownership receipt changed while sealing"
                                    .to_owned(),
                            );
                        }
                        Ok((request, request_receipt))
                    })();
                    let (request, request_receipt) = match request_setup {
                        Ok(request) => request,
                        Err(primary) => {
                            let cleanup = cleanup_partial_windows_supervisor_session(
                                WindowsPartialSessionAuthority {
                                    parent_path: &parent,
                                    parent: &parent_handle,
                                    parent_receipt,
                                    root_path: &candidate,
                                    root,
                                    root_receipt,
                                },
                                windows_bind_path(&request_path, false)
                                    .ok()
                                    .map(|(file, receipt)| (request_path.clone(), file, receipt)),
                                deadline,
                            );
                            return Err(match cleanup {
                                Ok(()) => primary,
                                Err(cleanup) => {
                                    format!("{primary}; additionally, cleanup failed: {cleanup}")
                                }
                            });
                        }
                    };
                    return Ok(Self {
                        parent_path: parent.clone(),
                        root_path: candidate.clone(),
                        request_path,
                        request_digest_path: candidate.join("request.digest"),
                        authority_manifest_path: candidate.join("authority.manifest"),
                        late_receipt_path: parent.join(format!(
                            "{}.late.receipt",
                            candidate
                                .file_name()
                                .and_then(|name| name.to_str())
                                .ok_or_else(|| {
                                    "Windows supervisor session name is not UTF-8".to_owned()
                                })?
                        )),
                        parent: parent_handle,
                        root,
                        request,
                        request_digest: None,
                        authority_manifest: None,
                        late_receipt: None,
                        parent_receipt,
                        root_receipt,
                        request_receipt,
                        request_digest_receipt: None,
                        authority_manifest_receipt: None,
                        late_receipt_receipt: None,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!("cannot create Windows supervisor session: {error}"));
                }
            }
        }
        Err("Windows supervisor session collision budget exhausted".to_owned())
    }

    fn revalidate(&self) -> Result<(), String> {
        if windows_file_receipt(&self.parent)? != self.parent_receipt
            || windows_file_receipt(&self.root)? != self.root_receipt
            || windows_file_receipt(&self.request)? != self.request_receipt
            || windows_bind_path(&self.parent_path, true)?.1 != self.parent_receipt
            || windows_bind_path(&self.root_path, true)?.1 != self.root_receipt
            || windows_bind_path(&self.request_path, false)?.1 != self.request_receipt
        {
            return Err("Windows supervisor session receipt changed".to_owned());
        }
        if let (Some(request_digest), Some(request_digest_receipt)) =
            (&self.request_digest, self.request_digest_receipt)
            && (windows_file_receipt(request_digest)? != request_digest_receipt
                || windows_bind_path(&self.request_digest_path, false)?.1 != request_digest_receipt)
        {
            return Err("Windows supervisor request digest receipt changed".to_owned());
        }
        if let (Some(manifest), Some(receipt)) =
            (&self.authority_manifest, self.authority_manifest_receipt)
            && (windows_file_receipt(manifest)? != receipt
                || windows_bind_path(&self.authority_manifest_path, false)?.1 != receipt)
        {
            return Err("Windows supervisor authority manifest changed".to_owned());
        }
        if let (Some(late_receipt), Some(receipt)) = (&self.late_receipt, self.late_receipt_receipt)
            && (windows_file_receipt(late_receipt)? != receipt
                || windows_bind_shared_late_receipt(&self.late_receipt_path)?.1 != receipt)
        {
            return Err("Windows supervisor late receipt changed".to_owned());
        }
        Ok(())
    }

    fn create_late_receipt(&mut self, deadline: Instant) -> Result<WindowsFileReceipt, String> {
        if self.late_receipt.is_some() || Instant::now() >= deadline {
            return Err("Windows supervisor late receipt cannot be created".to_owned());
        }
        self.revalidate()?;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(
                windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                    | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
            )
            .open(&self.late_receipt_path)
            .map_err(|error| format!("cannot create Windows late supervisor receipt: {error}"))?;
        let receipt = windows_file_receipt(&file)?;
        if receipt.size != 0 {
            return Err("Windows late supervisor receipt was not empty".to_owned());
        }
        self.late_receipt = Some(file);
        self.late_receipt_receipt = Some(receipt);
        Ok(receipt)
    }

    fn seal_authority_manifest(
        &mut self,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(WindowsFileReceipt, Digest), String> {
        if bytes.is_empty() || bytes.len() > 16 * 1024 * 1024 || Instant::now() >= deadline {
            return Err("Windows supervisor authority manifest exceeds its bound".to_owned());
        }
        self.revalidate()?;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(
                windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                    | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
            )
            .open(&self.authority_manifest_path)
            .map_err(|error| format!("cannot create Windows authority manifest: {error}"))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("cannot persist Windows authority manifest: {error}"))?;
        let receipt = windows_file_receipt(&file)?;
        if receipt.size != u64::try_from(bytes.len()).unwrap_or(u64::MAX) {
            return Err("Windows authority manifest changed while sealing".to_owned());
        }
        drop(file);
        let (file, retained_receipt) = windows_bind_path(&self.authority_manifest_path, false)?;
        if retained_receipt != receipt {
            return Err("Windows authority manifest changed while sealing".to_owned());
        }
        self.authority_manifest = Some(file);
        self.authority_manifest_receipt = Some(receipt);
        Ok((receipt, sha256_bytes(bytes)))
    }

    fn seal_request_digest(&mut self, digest: Digest, deadline: Instant) -> Result<(), String> {
        if self.request_digest.is_some() || Instant::now() >= deadline {
            return Err("Windows supervisor request digest cannot be sealed".to_owned());
        }
        self.revalidate()?;
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(
                windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                    | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
            )
            .open(&self.request_digest_path)
            .map_err(|error| format!("cannot create Windows request digest receipt: {error}"))?;
        file.write_all(&digest.0)
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("cannot persist Windows request digest receipt: {error}"))?;
        let receipt = windows_file_receipt(&file)?;
        drop(file);
        let (file, retained_receipt) = windows_bind_path(&self.request_digest_path, false)?;
        if retained_receipt != receipt {
            return Err("Windows request digest receipt changed while sealing".to_owned());
        }
        self.request_digest = Some(file);
        self.request_digest_receipt = Some(receipt);
        Ok(())
    }

    fn retain_read_only_receipts(&mut self) -> Result<(), String> {
        self.revalidate()?;
        let (request, request_receipt) = windows_bind_path(&self.request_path, false)?;
        if request_receipt != self.request_receipt {
            return Err("Windows supervisor ownership receipt changed before transfer".to_owned());
        }
        let (request_digest, request_digest_receipt) =
            windows_bind_path(&self.request_digest_path, false)?;
        if Some(request_digest_receipt) != self.request_digest_receipt {
            return Err("Windows supervisor request digest changed before transfer".to_owned());
        }
        self.request = request;
        self.request_digest = Some(request_digest);
        if let Some(expected) = self.authority_manifest_receipt {
            let (manifest, receipt) = windows_bind_path(&self.authority_manifest_path, false)?;
            if receipt != expected {
                return Err(
                    "Windows supervisor authority manifest changed before transfer".to_owned(),
                );
            }
            self.authority_manifest = Some(manifest);
        }
        self.revalidate()
    }

    fn close(self, terminal_imported: bool, deadline: Instant) -> Result<(), String> {
        if Instant::now() >= deadline {
            return Err("Windows supervisor session cleanup deadline expired".to_owned());
        }
        self.revalidate()?;
        if !terminal_imported {
            return Err(format!(
                "Windows supervisor session retained until its terminal receipt is imported: {}",
                self.root_path.display()
            ));
        }
        reset_windows_supervisor_session(&self.root_path, deadline)?;
        run_windows_supervisor_icacls(&self.late_receipt_path, &["/reset"], deadline)?;
        self.revalidate()?;
        drop(self.request);
        drop(self.request_digest);
        drop(self.authority_manifest);
        drop(self.late_receipt);
        let mut allowed = 0_usize;
        for entry in fs::read_dir(&self.root_path)
            .map_err(|error| format!("cannot enumerate Windows supervisor session: {error}"))?
        {
            if Instant::now() >= deadline {
                return Err(
                    "Windows supervisor session enumeration exceeded its cleanup deadline"
                        .to_owned(),
                );
            }
            let entry = entry.map_err(|error| {
                format!("cannot read Windows supervisor session entry: {error}")
            })?;
            allowed = allowed.saturating_add(1);
            if allowed > 9 {
                return Err("Windows supervisor session inventory exceeds its bound".to_owned());
            }
            let name = entry.file_name();
            if name != "ownership.receipt"
                && name != "started.receipt"
                && name != "terminal.receipt"
                && name != "workspace.receipt"
                && name != "abnormal.receipt"
                && name != "request.digest"
                && name != "authority.manifest"
                && name != "cleanup.receipt"
                && name != "cleanup.commit"
            {
                return Err("Windows supervisor session contains an unexpected entry".to_owned());
            }
            let (guard, receipt) = windows_bind_path(&entry.path(), false)?;
            drop(guard);
            if Instant::now() >= deadline
                || windows_file_receipt(&self.parent)? != self.parent_receipt
                || windows_file_receipt(&self.root)? != self.root_receipt
                || windows_bind_path(&self.parent_path, true)?.1 != self.parent_receipt
                || windows_bind_path(&self.root_path, true)?.1 != self.root_receipt
                || windows_bind_path(&entry.path(), false)?.1 != receipt
            {
                return Err("Windows supervisor receipt changed before cleanup".to_owned());
            }
            fs::remove_file(entry.path())
                .map_err(|error| format!("cannot remove Windows supervisor receipt: {error}"))?;
        }
        if Instant::now() >= deadline
            || windows_file_receipt(&self.parent)? != self.parent_receipt
            || windows_file_receipt(&self.root)? != self.root_receipt
            || windows_bind_path(&self.parent_path, true)?.1 != self.parent_receipt
            || windows_bind_path(&self.root_path, true)?.1 != self.root_receipt
        {
            return Err("Windows supervisor session changed before root cleanup".to_owned());
        }
        drop(self.root);
        fs::remove_dir(&self.root_path)
            .map_err(|error| format!("cannot remove Windows supervisor session: {error}"))?;
        if Instant::now() >= deadline
            || windows_file_receipt(&self.parent)? != self.parent_receipt
            || windows_bind_path(&self.parent_path, true)?.1 != self.parent_receipt
            || windows_bind_shared_late_receipt(&self.late_receipt_path)?.1
                != self
                    .late_receipt_receipt
                    .ok_or_else(|| "Windows supervisor late receipt is absent".to_owned())?
        {
            return Err("Windows supervisor late receipt changed before cleanup".to_owned());
        }
        fs::remove_file(&self.late_receipt_path)
            .map_err(|error| format!("cannot remove Windows late supervisor receipt: {error}"))
    }

    fn transfer_session_cleanup(self) -> Result<WindowsLateReceiptAuthority, String> {
        self.revalidate()?;
        let late_receipt = self
            .late_receipt
            .ok_or_else(|| "Windows supervisor late receipt is absent".to_owned())?;
        let late_receipt_receipt = self
            .late_receipt_receipt
            .ok_or_else(|| "Windows supervisor late receipt identity is absent".to_owned())?;
        Ok(WindowsLateReceiptAuthority {
            parent_path: self.parent_path,
            session_path: self.root_path,
            late_receipt_path: self.late_receipt_path,
            parent: self.parent,
            late_receipt,
            parent_receipt: self.parent_receipt,
            session_receipt: self.root_receipt,
            late_receipt_receipt,
        })
    }
}

#[cfg(windows)]
impl WindowsLateReceiptAuthority {
    fn close(self, deadline: Instant) -> Result<(), String> {
        if Instant::now() >= deadline
            || windows_file_receipt(&self.parent)? != self.parent_receipt
            || windows_bind_path(&self.parent_path, true)?.1 != self.parent_receipt
            || windows_file_receipt(&self.late_receipt)? != self.late_receipt_receipt
            || windows_bind_shared_late_receipt(&self.late_receipt_path)?.1
                != self.late_receipt_receipt
        {
            return Err("Windows late receipt authority changed before cleanup".to_owned());
        }
        match fs::symlink_metadata(&self.session_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!("cannot attest Windows session cleanup: {error}"));
            }
            Ok(_) => {
                if windows_bind_path(&self.session_path, true)?.1 != self.session_receipt {
                    return Err(
                        "Windows session changed while awaiting external cleanup".to_owned()
                    );
                }
                return Err("Windows session remains after external cleanup".to_owned());
            }
        }
        run_windows_supervisor_icacls(&self.late_receipt_path, &["/reset"], deadline)?;
        if windows_file_receipt(&self.late_receipt)? != self.late_receipt_receipt {
            return Err("Windows late receipt changed during DACL reset".to_owned());
        }
        drop(self.late_receipt);
        fs::remove_file(&self.late_receipt_path)
            .map_err(|error| format!("cannot remove Windows late receipt: {error}"))
    }
}

#[cfg(windows)]
fn windows_supervisor_nonce() -> Result<Digest, String> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| format!("cannot create Windows supervisor nonce: {error}"))?;
    Ok(Digest(bytes))
}

#[cfg(windows)]
fn windows_supervisor_os_digest(value: &std::ffi::OsStr) -> Digest {
    use std::os::windows::ffi::OsStrExt as _;

    let mut bytes = Vec::new();
    for word in value.encode_wide() {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    sha256_bytes(&bytes)
}

#[cfg(windows)]
fn windows_supervisor_os_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt as _;

    value.encode_wide().flat_map(u16::to_le_bytes).collect()
}

#[cfg(windows)]
fn windows_supervisor_os_from_bytes(bytes: &[u8]) -> Result<std::ffi::OsString, String> {
    use std::os::windows::ffi::OsStringExt as _;

    let width = size_of::<u16>();
    if !bytes.len().is_multiple_of(width) {
        return Err("Windows supervisor request token has a partial wide character".to_owned());
    }
    let words = bytes
        .chunks_exact(width)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    Ok(std::ffi::OsString::from_wide(&words))
}

#[cfg(windows)]
fn windows_supervisor_frame(
    phase: u8,
    request_sha256: Digest,
    nonce: Digest,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut frame = Vec::with_capacity(1 + 64 + payload.len());
    frame.push(phase);
    frame.extend_from_slice(&request_sha256.0);
    frame.extend_from_slice(&nonce.0);
    frame.extend_from_slice(payload);
    if frame.len() > NIGHTLY_SUPERVISOR_TERMINAL_LIMIT {
        return Err("Windows supervisor frame exceeds its global byte limit".to_owned());
    }
    Ok(frame)
}

#[cfg(windows)]
fn windows_validate_frame(
    frame: &[u8],
    phase: u8,
    request_sha256: Digest,
    nonce: Digest,
) -> Result<&[u8], String> {
    let digest_width = Digest::default().0.len();
    if frame.len() < 1 + digest_width * 2
        || frame[0] != phase
        || frame[1..1 + digest_width] != request_sha256.0
        || frame[1 + digest_width..1 + digest_width * 2] != nonce.0
    {
        return Err("Windows supervisor frame authority differs".to_owned());
    }
    Ok(&frame[1 + digest_width * 2..])
}

#[cfg(windows)]
struct WindowsSupervisorFixtureExitGuard {
    stream: TcpStream,
    request_sha256: Digest,
    nonce: Digest,
    exit_code: u32,
}

#[cfg(windows)]
impl WindowsSupervisorFixtureExitGuard {
    fn connect(
        address: SocketAddrV4,
        request_sha256: Digest,
        nonce: Digest,
        deadline: Instant,
    ) -> Result<Self, String> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("Windows supervisor exit-receipt deadline expired".to_owned());
        }
        let stream = TcpStream::connect_timeout(
            &std::net::SocketAddr::V4(address),
            remaining.min(NIGHTLY_SUPERVISOR_START_TIMEOUT),
        )
        .map_err(|error| format!("cannot connect Windows supervisor exit receipt: {error}"))?;
        stream
            .set_write_timeout(Some(remaining.min(NIGHTLY_SUPERVISOR_START_TIMEOUT)))
            .map_err(|error| format!("cannot bound Windows supervisor exit receipt: {error}"))?;
        Ok(Self {
            stream,
            request_sha256,
            nonce,
            exit_code: 1,
        })
    }

    fn mark_success(&mut self) {
        self.exit_code = 0;
    }
}

#[cfg(windows)]
impl Drop for WindowsSupervisorFixtureExitGuard {
    fn drop(&mut self) {
        let mut payload = Vec::with_capacity(size_of::<u32>() * 2);
        payload.extend_from_slice(&std::process::id().to_be_bytes());
        payload.extend_from_slice(&self.exit_code.to_be_bytes());
        if let Ok(frame) = windows_supervisor_frame(14, self.request_sha256, self.nonce, &payload) {
            let _ = windows_write_inherited_frame(&mut self.stream, &frame);
        }
        std::process::exit(i32::try_from(self.exit_code).unwrap_or(1));
    }
}

#[cfg(windows)]
struct WindowsSupervisorProcess {
    process: firehazard::process::OwnedHandle,
    process_id: u32,
    supervisor_job: Option<firehazard::job::OwnedHandle>,
}

#[cfg(windows)]
impl WindowsSupervisorProcess {
    fn id(&self) -> u32 {
        self.process_id
    }

    fn try_wait(&self) -> Result<Option<u32>, String> {
        if firehazard::process::is_process_running(&self.process) {
            Ok(None)
        } else {
            firehazard::process::get_exit_code_process(&self.process)
                .map(Some)
                .map_err(|error| format!("cannot inspect Windows supervisor exit: {error:?}"))
        }
    }

    fn terminate_pretransfer(&self) -> Result<(), String> {
        firehazard::terminate_job_object(
            self.supervisor_job
                .as_ref()
                .ok_or_else(|| "Windows supervisor Job ownership already transferred".to_owned())?,
            1,
        )
        .map_err(|error| format!("cannot terminate Windows pretransfer supervisor Job: {error:?}"))
    }

    fn transfer(&mut self) -> Result<(), String> {
        let job = self
            .supervisor_job
            .take()
            .ok_or_else(|| "Windows supervisor Job ownership already transferred".to_owned())?;
        firehazard::set_information_job_object(
            &job,
            firehazard::job::object::ExtendedLimitInformation::default(),
        )
        .map_err(|error| {
            format!("cannot release Windows supervisor startup Job limit: {error:?}")
        })?;
        drop(job);
        Ok(())
    }
}

#[cfg(windows)]
struct WindowsExternalPrepared {
    child: WindowsSupervisorProcess,
    control: firehazard::io::WritePipe,
    observations: mpsc::Receiver<Result<Vec<u8>, String>>,
    observer_dropped: Arc<AtomicU64>,
    session: WindowsSupervisorSession,
    request_sha256: Digest,
    nonce: Digest,
    manifest_sha256: Digest,
    startup_cleanup_deadline: Instant,
    ownership_deadline: Instant,
    ownership_cleanup_deadline: Instant,
}

#[cfg(windows)]
struct WindowsExternalStarted {
    child: WindowsSupervisorProcess,
    control: firehazard::io::WritePipe,
    observations: mpsc::Receiver<Result<Vec<u8>, String>>,
    observer_dropped: Arc<AtomicU64>,
    session: WindowsSupervisorSession,
    request_sha256: Digest,
    nonce: Digest,
    started_sha256: Digest,
}

#[cfg(windows)]
struct WindowsExternalStartReceipt {
    child: WindowsSupervisorProcess,
    session: WindowsSupervisorSession,
    request_sha256: Digest,
    nonce: Digest,
}

#[cfg(windows)]
struct WindowsExternalStartFailure {
    detail: String,
    retained: Option<Box<WindowsExternalStartReceipt>>,
}

#[cfg(windows)]
struct WindowsAuthorityCleanupSuccessor {
    child: WindowsSupervisorProcess,
    control: firehazard::io::WritePipe,
    observations: mpsc::Receiver<Result<Vec<u8>, String>>,
    request_sha256: Digest,
    nonce: Digest,
}

#[cfg(windows)]
struct WindowsAuthorityCleanupStart<'a> {
    executable: &'a Path,
    manifest_path: &'a Path,
    manifest_sha256: Digest,
    commit_path: &'a Path,
    cleanup_path: &'a Path,
    session_path: &'a Path,
    session_receipt: WindowsFileReceipt,
    request_sha256: Digest,
    nonce: Digest,
    deadline: Instant,
}

#[cfg(windows)]
fn start_windows_authority_cleanup_successor(
    start: WindowsAuthorityCleanupStart<'_>,
) -> Result<WindowsAuthorityCleanupSuccessor, String> {
    let mut launch =
        spawn_windows_pipe_supervisor(start.executable, "windows-authority-cleanup-v1")?;
    let remaining = start
        .deadline
        .saturating_duration_since(Instant::now())
        .saturating_sub(NIGHTLY_SUPERVISOR_START_TIMEOUT);
    if remaining <= NIGHTLY_SUPERVISOR_START_TIMEOUT {
        return Err(
            "Windows authority cleanup successor has no retained cleanup budget".to_owned(),
        );
    }
    let mut fields = vec![
        start.manifest_path.as_os_str().to_owned(),
        std::ffi::OsString::from(start.manifest_sha256.hex()),
        start.commit_path.as_os_str().to_owned(),
        start.cleanup_path.as_os_str().to_owned(),
        start.session_path.as_os_str().to_owned(),
        std::ffi::OsString::from(start.request_sha256.hex()),
        std::ffi::OsString::from(start.nonce.hex()),
        std::ffi::OsString::from(
            u64::try_from(remaining.as_millis())
                .unwrap_or(u64::MAX)
                .to_string(),
        ),
    ];
    fields.extend(windows_receipt_fields(start.session_receipt));
    let token = hell_testkit::encode_windows_argv(&fields)
        .map_err(|error| format!("cannot encode Windows cleanup successor request: {error}"))?;
    windows_write_inherited_frame(&mut launch.control, &windows_supervisor_os_bytes(&token))?;
    let ready = launch
        .observations
        .recv_timeout(
            NIGHTLY_SUPERVISOR_START_TIMEOUT
                .min(start.deadline.saturating_duration_since(Instant::now())),
        )
        .map_err(|error| format!("cannot receive Windows cleanup successor Ready: {error}"))??;
    let payload = windows_validate_frame(&ready, 1, start.request_sha256, start.nonce)?;
    if payload != start.manifest_sha256.0 {
        return Err("Windows cleanup successor imported a different manifest".to_owned());
    }
    Ok(WindowsAuthorityCleanupSuccessor {
        child: launch.child,
        control: launch.control,
        observations: launch.observations,
        request_sha256: start.request_sha256,
        nonce: start.nonce,
    })
}

#[cfg(windows)]
fn finish_windows_authority_cleanup_successor(
    mut successor: WindowsAuthorityCleanupSuccessor,
    deadline: Instant,
) -> Result<(WindowsAuthorityCleanupSuccessor, Option<String>), String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let cleanup = windows_supervisor_frame(
        8,
        successor.request_sha256,
        successor.nonce,
        &u64::try_from(remaining.as_millis())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    )?;
    windows_write_inherited_frame(&mut successor.control, &cleanup)?;
    let receipt = successor
        .observations
        .recv_timeout(remaining)
        .map_err(|error| format!("cannot receive Windows authority cleanup receipt: {error}"))??;
    let payload = windows_validate_frame(&receipt, 9, successor.request_sha256, successor.nonce)?;
    let detail = String::from_utf8(payload.to_vec())
        .map_err(|_| "Windows authority cleanup receipt is not UTF-8".to_owned())?;
    let failure = (detail != "completed")
        .then(|| format!("Windows authority cleanup successor failed: {detail}"));
    Ok((successor, failure))
}

#[cfg(windows)]
fn await_windows_session_cleanup_successor_exit(
    child: &WindowsSupervisorProcess,
    observations: &mpsc::Receiver<Result<Vec<u8>, String>>,
    request_sha256: Digest,
    nonce: Digest,
    deadline: Instant,
) -> Result<(), String> {
    let receipt = observations
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|error| format!("cannot receive Windows session cleanup receipt: {error}"))??;
    let detail =
        windows_validate_frame(&receipt, 13, request_sha256, nonce).and_then(|payload| {
            String::from_utf8(payload.to_vec())
                .map_err(|_| "Windows session cleanup receipt is not UTF-8".to_owned())
        })?;
    let mut exit_code = None;
    while Instant::now() < deadline {
        if let Some(observed) = child.try_wait()? {
            exit_code = Some(observed);
            break;
        }
        std::thread::yield_now();
    }
    match (detail.as_str(), exit_code) {
        ("completed", Some(0)) => Ok(()),
        ("completed", Some(code)) => Err(format!(
            "Windows session cleanup successor exited with code {code}"
        )),
        ("completed", None) => Err(
            "Windows session cleanup successor retained exit ownership past its deadline"
                .to_owned(),
        ),
        (_, _) => Err(format!("Windows session cleanup failed: {detail}")),
    }
}

#[cfg(windows)]
fn run_windows_cleanup_exit_fixture(
    control: &mut impl std::io::Read,
    observations: &mut impl std::io::Write,
) -> Result<(), String> {
    let request = windows_read_inherited_frame(control)?
        .ok_or_else(|| "Windows cleanup-exit fixture closed before request".to_owned())?;
    let token = windows_supervisor_os_from_bytes(&request)?;
    let fields = hell_testkit::decode_windows_argv(&token)
        .map_err(|error| format!("cannot decode Windows cleanup-exit fixture: {error}"))?;
    let [mode, request_sha256, nonce] = fields.as_slice() else {
        return Err("Windows cleanup-exit fixture request width differs".to_owned());
    };
    let request_sha256 = Digest::from_hex(
        request_sha256
            .to_str()
            .ok_or_else(|| "Windows cleanup-exit request digest is not UTF-8".to_owned())?,
    )
    .map_err(|error| format!("Windows cleanup-exit request digest is invalid: {error}"))?;
    let nonce = Digest::from_hex(
        nonce
            .to_str()
            .ok_or_else(|| "Windows cleanup-exit nonce is not UTF-8".to_owned())?,
    )
    .map_err(|error| format!("Windows cleanup-exit nonce is invalid: {error}"))?;
    windows_write_inherited_frame(
        observations,
        &windows_supervisor_frame(1, request_sha256, nonce, &[])?,
    )?;
    windows_write_inherited_frame(
        observations,
        &windows_supervisor_frame(13, request_sha256, nonce, b"completed")?,
    )?;
    match mode.to_str() {
        Some("held") => {
            let _ = windows_read_inherited_frame(control)?;
            Ok(())
        }
        Some("nonzero") => Err("injected cleanup successor nonzero exit".to_owned()),
        _ => Err("Windows cleanup-exit fixture mode differs".to_owned()),
    }
}

#[cfg(windows)]
impl From<String> for WindowsExternalStartFailure {
    fn from(detail: String) -> Self {
        Self {
            detail,
            retained: None,
        }
    }
}

#[cfg(windows)]
fn close_unstarted_windows_supervisor_session(
    session: WindowsSupervisorSession,
    deadline: Instant,
    primary: String,
) -> WindowsExternalStartFailure {
    let cleanup = session.close(true, deadline);
    WindowsExternalStartFailure {
        detail: match cleanup {
            Ok(()) => primary,
            Err(cleanup) => format!("{primary}; additionally, session cleanup failed: {cleanup}"),
        },
        retained: None,
    }
}

#[cfg(windows)]
fn close_prelaunch_windows_supervisor(
    child: WindowsSupervisorProcess,
    session: WindowsSupervisorSession,
    request_sha256: Digest,
    nonce: Digest,
    deadline: Instant,
    primary: String,
) -> WindowsExternalStartFailure {
    let kill = child.terminate_pretransfer();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let cleanup = session.close(true, deadline);
                let detail = match (kill, cleanup) {
                    (Ok(()), Ok(())) => primary,
                    (Err(kill), Ok(())) => {
                        format!("{primary}; additionally, supervisor termination failed: {kill}")
                    }
                    (Ok(()), Err(cleanup)) => {
                        format!("{primary}; additionally, session cleanup failed: {cleanup}")
                    }
                    (Err(kill), Err(cleanup)) => format!(
                        "{primary}; additionally, supervisor termination failed: {kill}; session cleanup failed: {cleanup}"
                    ),
                };
                return WindowsExternalStartFailure {
                    detail,
                    retained: None,
                };
            }
            Ok(None) if Instant::now() < deadline => std::thread::yield_now(),
            Ok(None) => {
                return WindowsExternalStartFailure {
                    detail: format!(
                        "{primary}; Windows supervisor exit exceeded its prelaunch cleanup deadline"
                    ),
                    retained: Some(Box::new(WindowsExternalStartReceipt {
                        child,
                        session,
                        request_sha256,
                        nonce,
                    })),
                };
            }
            Err(error) => {
                return WindowsExternalStartFailure {
                    detail: format!("{primary}; cannot poll Windows supervisor exit: {error}"),
                    retained: Some(Box::new(WindowsExternalStartReceipt {
                        child,
                        session,
                        request_sha256,
                        nonce,
                    })),
                };
            }
        }
    }
}

#[cfg(windows)]
fn windows_receipt_fields(receipt: WindowsFileReceipt) -> [std::ffi::OsString; 4] {
    [
        receipt.volume.to_string().into(),
        receipt.index.to_string().into(),
        receipt.size.to_string().into(),
        receipt.attributes.to_string().into(),
    ]
}

#[cfg(windows)]
fn windows_parse_u64(value: &std::ffi::OsStr, field: &str) -> Result<u64, String> {
    value
        .to_str()
        .ok_or_else(|| format!("Windows supervisor {field} is not UTF-8"))?
        .parse()
        .map_err(|error| format!("Windows supervisor {field} is invalid: {error}"))
}

#[cfg(windows)]
fn windows_parse_receipt(
    fields: &[std::ffi::OsString],
    field: &str,
) -> Result<WindowsFileReceipt, String> {
    let [volume, index, size, attributes] = fields else {
        return Err(format!("Windows supervisor {field} receipt width differs"));
    };
    Ok(WindowsFileReceipt {
        volume: windows_parse_u64(volume, field)?,
        index: windows_parse_u64(index, field)?,
        size: windows_parse_u64(size, field)?,
        attributes: u32::try_from(windows_parse_u64(attributes, field)?)
            .map_err(|_| format!("Windows supervisor {field} attributes are too large"))?,
    })
}

#[cfg(windows)]
struct WindowsSupervisorRequestFields<'a> {
    plan: ExternalSupervisorPlan,
    root: (&'a Path, WindowsFileReceipt),
    writable_target: (&'a Path, WindowsFileReceipt),
    session: &'a WindowsSupervisorSession,
    late_receipt: WindowsFileReceipt,
    manifest_receipt: WindowsFileReceipt,
    manifest_sha256: Digest,
    nonce: Digest,
    envelope: SupervisionEnvelope,
    lifetime_deadline: Instant,
    fixture_gate: Option<SocketAddrV4>,
    fixture_exit_observer: Option<SocketAddrV4>,
}

#[cfg(windows)]
fn windows_supervisor_request_fields(
    request: WindowsSupervisorRequestFields<'_>,
) -> Result<Vec<std::ffi::OsString>, String> {
    let WindowsSupervisorRequestFields {
        plan,
        root,
        writable_target,
        session,
        late_receipt,
        manifest_receipt,
        manifest_sha256,
        nonce,
        envelope,
        lifetime_deadline,
        fixture_gate,
        fixture_exit_observer,
    } = request;
    let (root, root_receipt) = root;
    let (writable_target, writable_target_receipt) = writable_target;
    let anchor = Instant::now();
    let remaining_millis = |deadline: Instant| {
        u64::try_from(
            deadline
                .saturating_duration_since(anchor)
                .saturating_sub(NIGHTLY_SUPERVISOR_START_TIMEOUT)
                .as_millis(),
        )
        .unwrap_or(u64::MAX)
    };
    let fixture_gate = fixture_gate.unwrap_or_else(|| SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let fixture_exit_observer =
        fixture_exit_observer.unwrap_or_else(|| SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    let mut fields = vec![
        plan.code().to_string().into(),
        root.as_os_str().to_owned(),
        writable_target.as_os_str().to_owned(),
        session.root_path.as_os_str().to_owned(),
        session.request_path.as_os_str().to_owned(),
        session.late_receipt_path.as_os_str().to_owned(),
        nonce.hex().into(),
        remaining_millis(envelope.execution).to_string().into(),
        remaining_millis(envelope.child_completion_deadline)
            .to_string()
            .into(),
        remaining_millis(envelope.report_completion_deadline)
            .to_string()
            .into(),
        remaining_millis(lifetime_deadline).to_string().into(),
        u8::from(fixture_gate.port() != 0).to_string().into(),
        fixture_gate.ip().to_string().into(),
        fixture_gate.port().to_string().into(),
        u8::from(fixture_exit_observer.port() != 0)
            .to_string()
            .into(),
        fixture_exit_observer.ip().to_string().into(),
        fixture_exit_observer.port().to_string().into(),
    ];
    fields.extend(windows_receipt_fields(root_receipt));
    fields.extend(windows_receipt_fields(writable_target_receipt));
    fields.extend(windows_receipt_fields(session.root_receipt));
    fields.extend(windows_receipt_fields(session.request_receipt));
    fields.extend(windows_receipt_fields(late_receipt));
    fields.extend(windows_receipt_fields(manifest_receipt));
    fields.push(manifest_sha256.hex().into());
    Ok(fields)
}

#[cfg(windows)]
trait WindowsNightlySupervisorAuthority {
    fn staged_root(&self) -> &Path;

    fn manifest_entries(&self) -> Vec<crate::release::platform::NightlyWindowsManifestEntry>;

    fn prepare_cleanup_transfer(&mut self, deadline: Instant) -> Result<(), String>;

    fn commit_cleanup_transfer(&mut self);
}

#[cfg(windows)]
impl WindowsNightlySupervisorAuthority for crate::release::platform::NightlyWindowsLaunchAuthority {
    fn staged_root(&self) -> &Path {
        self.staged_root()
    }

    fn manifest_entries(&self) -> Vec<crate::release::platform::NightlyWindowsManifestEntry> {
        self.manifest_entries()
    }

    fn prepare_cleanup_transfer(&mut self, deadline: Instant) -> Result<(), String> {
        self.prepare_cleanup_transfer(deadline)
    }

    fn commit_cleanup_transfer(&mut self) {
        self.commit_cleanup_transfer();
    }
}

#[cfg(windows)]
fn encode_windows_nightly_authority_manifest(
    authority: Option<&dyn WindowsNightlySupervisorAuthority>,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let Some(authority) = authority else {
        let mut bytes = b"hell-windows-nightly-authority-v1\0".to_vec();
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        return Ok(bytes);
    };
    encode_windows_nightly_authority_manifest_parts(
        authority.staged_root(),
        authority.manifest_entries(),
        deadline,
    )
}

#[cfg(windows)]
fn encode_windows_nightly_authority_manifest_parts(
    authority_root: &Path,
    entries: Vec<crate::release::platform::NightlyWindowsManifestEntry>,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    if Instant::now() >= deadline {
        return Err("Windows authority manifest deadline expired before encoding".to_owned());
    }
    let mut bytes = b"hell-windows-nightly-authority-v1\0".to_vec();
    let root = windows_supervisor_os_bytes(authority_root.as_os_str());
    let (_root_guard, root_receipt) = windows_bind_path(authority_root, true)?;
    bytes.extend_from_slice(
        &u32::try_from(root.len())
            .map_err(|_| "Windows authority root is too long".to_owned())?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&root);
    for field in windows_receipt_fields(root_receipt) {
        bytes.extend_from_slice(&windows_parse_u64(&field, "manifest root")?.to_be_bytes());
    }
    bytes.extend_from_slice(
        &u32::try_from(entries.len())
            .map_err(|_| "Windows authority inventory is too large".to_owned())?
            .to_be_bytes(),
    );
    for entry in entries {
        if Instant::now() >= deadline {
            return Err("Windows authority manifest encoding exceeded its deadline".to_owned());
        }
        let entry_path = authority_root.join(&entry.relative);
        let (_entry_guard, receipt) = windows_bind_path(&entry_path, entry.directory)?;
        let relative = windows_supervisor_os_bytes(entry.relative.as_os_str());
        bytes.extend_from_slice(
            &u32::try_from(relative.len())
                .map_err(|_| "Windows authority relative path is too long".to_owned())?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&relative);
        bytes.push(u8::from(entry.directory));
        for field in windows_receipt_fields(receipt) {
            bytes.extend_from_slice(&windows_parse_u64(&field, "manifest entry")?.to_be_bytes());
        }
        if receipt.size != entry.size {
            return Err("Windows authority manifest size differs from staged receipt".to_owned());
        }
        bytes.extend_from_slice(&entry.sha256.unwrap_or_default().0);
        if bytes.len() > 16 * 1024 * 1024 {
            return Err("Windows authority manifest exceeds its byte bound".to_owned());
        }
    }
    Ok(bytes)
}

#[cfg(windows)]
struct ImportedWindowsNightlyAuthority {
    root: PathBuf,
    staged_cargo: Option<PathBuf>,
    staged_rustc: Option<PathBuf>,
    _root_guard: Option<fs::File>,
    _entry_guards: Vec<fs::File>,
    entries: Vec<(PathBuf, bool, WindowsFileReceipt, Option<Digest>)>,
}

#[cfg(windows)]
impl ImportedWindowsNightlyAuthority {
    fn revalidate_until(&self, deadline: Instant) -> Result<(), String> {
        if self.root.as_os_str().is_empty() {
            return Ok(());
        }
        let root_guard = self
            ._root_guard
            .as_ref()
            .ok_or_else(|| "Windows imported authority root guard is absent".to_owned())?;
        if Instant::now() >= deadline
            || windows_file_receipt(root_guard)? != windows_bind_path(&self.root, true)?.1
        {
            return Err("Windows imported authority root identity changed".to_owned());
        }
        for ((relative, directory, receipt, _), guard) in
            self.entries.iter().zip(&self._entry_guards)
        {
            if Instant::now() >= deadline
                || windows_file_receipt(guard)? != *receipt
                || windows_bind_path(&self.root.join(relative), *directory)?.1 != *receipt
            {
                return Err("Windows imported authority entry identity changed".to_owned());
            }
        }
        Ok(())
    }

    fn close_until(mut self, deadline: Instant) -> Result<(), String> {
        if self.root.as_os_str().is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("Windows imported authority cleanup deadline expired".to_owned());
        }
        reset_windows_supervisor_session(&self.root, deadline)?;
        self._entry_guards.clear();
        self._root_guard = None;
        for (relative, directory, receipt, _) in self.entries.iter().filter(|entry| !entry.1) {
            if Instant::now() >= deadline
                || windows_bind_path(&self.root.join(relative), *directory)?.1 != *receipt
            {
                return Err("imported Windows authority file changed before cleanup".to_owned());
            }
            fs::remove_file(self.root.join(relative))
                .map_err(|error| format!("cannot remove imported authority file: {error}"))?;
        }
        let mut directories = self
            .entries
            .iter()
            .filter(|(relative, directory, _, _)| *directory && !relative.as_os_str().is_empty())
            .collect::<Vec<_>>();
        directories
            .sort_by_key(|(relative, _, _, _)| std::cmp::Reverse(relative.components().count()));
        for (relative, _, receipt, _) in directories {
            if Instant::now() >= deadline
                || windows_bind_path(&self.root.join(relative), true)?.1 != *receipt
            {
                return Err(
                    "imported Windows authority directory changed before cleanup".to_owned(),
                );
            }
            fs::remove_dir(self.root.join(relative))
                .map_err(|error| format!("cannot remove imported authority directory: {error}"))?;
        }
        fs::remove_dir(&self.root)
            .map_err(|error| format!("cannot remove imported Windows authority root: {error}"))?;
        if Instant::now() >= deadline {
            return Err("Windows imported authority cleanup exceeded its deadline".to_owned());
        }
        match fs::symlink_metadata(&self.root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("cannot attest imported authority absence: {error}")),
            Ok(_) => Err("imported Windows authority remains after cleanup".to_owned()),
        }
    }
}

#[cfg(windows)]
const WINDOWS_REPORTER_FIXTURE_CARGO: &[u8] = b"sealed-fixture-cargo\n";
#[cfg(windows)]
const WINDOWS_REPORTER_FIXTURE_RUSTC: &[u8] = b"sealed-fixture-rustc\n";

#[cfg(windows)]
fn windows_reporter_fixture_manifest_entries()
-> Result<Vec<crate::release::platform::NightlyWindowsManifestEntry>, String> {
    Ok(vec![
        crate::release::platform::NightlyWindowsManifestEntry {
            relative: PathBuf::from("bin"),
            directory: true,
            size: 0,
            sha256: None,
        },
        crate::release::platform::NightlyWindowsManifestEntry {
            relative: PathBuf::from("bin/cargo.exe"),
            directory: false,
            size: u64::try_from(WINDOWS_REPORTER_FIXTURE_CARGO.len())
                .map_err(|_| "Windows fixture Cargo size is not representable".to_owned())?,
            sha256: Some(sha256_bytes(WINDOWS_REPORTER_FIXTURE_CARGO)),
        },
        crate::release::platform::NightlyWindowsManifestEntry {
            relative: PathBuf::from("bin/rustc.exe"),
            directory: false,
            size: u64::try_from(WINDOWS_REPORTER_FIXTURE_RUSTC.len())
                .map_err(|_| "Windows fixture rustc size is not representable".to_owned())?,
            sha256: Some(sha256_bytes(WINDOWS_REPORTER_FIXTURE_RUSTC)),
        },
    ])
}

#[cfg(windows)]
struct WindowsReporterFixtureAuthority {
    parent: PathBuf,
    parent_guard: fs::File,
    parent_receipt: WindowsFileReceipt,
    root: PathBuf,
    entries: Vec<crate::release::platform::NightlyWindowsManifestEntry>,
    imported: Option<ImportedWindowsNightlyAuthority>,
    transferred: bool,
}

#[cfg(windows)]
impl WindowsReporterFixtureAuthority {
    fn create_until(
        parent: &Path,
        deadline: Instant,
        cleanup_deadline: Instant,
    ) -> Result<Self, String> {
        if Instant::now() >= deadline || deadline >= cleanup_deadline {
            return Err(
                "Windows reporter fixture authority deadline expired before creation".to_owned(),
            );
        }
        let parent = fs::canonicalize(parent).map_err(|error| {
            format!("cannot canonicalize Windows fixture authority parent: {error}")
        })?;
        let (parent_guard, parent_receipt) = windows_bind_path(&parent, true)?;
        let mut nonce = [0_u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|error| format!("cannot allocate Windows fixture authority nonce: {error}"))?;
        let root = parent.join(format!(
            "nightly-supervisor-authority-{}-{}",
            std::process::id(),
            sha256_bytes(&nonce).hex()
        ));
        fs::create_dir(&root)
            .map_err(|error| format!("cannot create Windows fixture authority root: {error}"))?;
        let (root_guard, root_receipt) = match windows_bind_path(&root, true) {
            Ok(receipt) => receipt,
            Err(primary) => {
                return Err(format!(
                    "{primary}; Windows fixture authority root remains retained by kernel path authority because no no-follow receipt was acquired: {}",
                    root.display()
                ));
            }
        };
        let setup = (|| {
            let bin = root.join("bin");
            fs::create_dir(&bin)
                .map_err(|error| format!("cannot create Windows fixture authority bin: {error}"))?;
            let cargo = bin.join("cargo.exe");
            let rustc = bin.join("rustc.exe");
            for (path, bytes) in [
                (&cargo, WINDOWS_REPORTER_FIXTURE_CARGO),
                (&rustc, WINDOWS_REPORTER_FIXTURE_RUSTC),
            ] {
                if Instant::now() >= deadline {
                    return Err(
                        "Windows reporter fixture authority creation exceeded its deadline"
                            .to_owned(),
                    );
                }
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .and_then(|mut file| file.write_all(bytes))
                    .map_err(|error| {
                        format!(
                            "cannot create Windows fixture authority member {}: {error}",
                            path.display()
                        )
                    })?;
            }
            protect_windows_supervisor_session(&root, deadline)?;
            let entries = windows_reporter_fixture_manifest_entries()?;
            let manifest =
                encode_windows_nightly_authority_manifest_parts(&root, entries.clone(), deadline)?;
            let imported = import_authenticated_windows_nightly_authority_manifest(
                &manifest,
                sha256_bytes(&manifest),
                deadline,
            )?;
            Ok::<_, String>((entries, imported))
        })();
        let (entries, imported) = match setup {
            Ok(setup) => setup,
            Err(primary) => {
                let cleanup = cleanup_windows_reporter_fixture_authority_root(
                    &parent,
                    &parent_guard,
                    parent_receipt,
                    &root,
                    root_guard,
                    root_receipt,
                    cleanup_deadline,
                );
                return Err(
                    compose_windows_reporter_fixture_results(Err(primary), cleanup)
                        .expect_err("fixture setup failure must remain an error"),
                );
            }
        };
        if windows_file_receipt(&parent_guard)? != parent_receipt
            || windows_bind_path(&parent, true)?.1 != parent_receipt
            || windows_file_receipt(&root_guard)? != root_receipt
            || windows_bind_path(&root, true)?.1 != root_receipt
        {
            let primary = "Windows fixture authority identity changed during creation".to_owned();
            drop(imported);
            let cleanup = cleanup_windows_reporter_fixture_authority_root(
                &parent,
                &parent_guard,
                parent_receipt,
                &root,
                root_guard,
                root_receipt,
                cleanup_deadline,
            );
            return Err(
                compose_windows_reporter_fixture_results(Err(primary), cleanup)
                    .expect_err("fixture identity failure must remain an error"),
            );
        }
        drop(root_guard);
        Ok(Self {
            parent,
            parent_guard,
            parent_receipt,
            root,
            entries,
            imported: Some(imported),
            transferred: false,
        })
    }

    fn close_until(&mut self, deadline: Instant) -> Result<(), String> {
        if self.transferred {
            return Err("Windows fixture authority cleanup was already transferred".to_owned());
        }
        let imported = self
            .imported
            .take()
            .ok_or_else(|| "Windows fixture authority cleanup owner is absent".to_owned())?;
        let cleanup = imported.close_until(deadline);
        let parent = if Instant::now() >= deadline
            || windows_file_receipt(&self.parent_guard)? != self.parent_receipt
            || windows_bind_path(&self.parent, true)?.1 != self.parent_receipt
        {
            Err("Windows fixture authority parent changed during cleanup".to_owned())
        } else {
            Ok(())
        };
        let absence = match fs::symlink_metadata(&self.root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "cannot attest Windows fixture authority absence: {error}"
            )),
            Ok(_) => Err("Windows fixture authority remains after cleanup".to_owned()),
        };
        compose_windows_reporter_fixture_results(
            compose_windows_reporter_fixture_results(cleanup, parent),
            absence,
        )
    }

    fn finish_until(&mut self, deadline: Instant) -> Result<(), String> {
        if !self.transferred {
            return self.close_until(deadline);
        }
        if Instant::now() >= deadline
            || windows_file_receipt(&self.parent_guard)? != self.parent_receipt
            || windows_bind_path(&self.parent, true)?.1 != self.parent_receipt
        {
            return Err("Windows transferred fixture authority parent changed".to_owned());
        }
        match fs::symlink_metadata(&self.root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "cannot attest transferred Windows fixture authority absence: {error}"
            )),
            Ok(_) => Err("transferred Windows fixture authority remains".to_owned()),
        }
    }
}

#[cfg(windows)]
impl WindowsNightlySupervisorAuthority for WindowsReporterFixtureAuthority {
    fn staged_root(&self) -> &Path {
        &self.root
    }

    fn manifest_entries(&self) -> Vec<crate::release::platform::NightlyWindowsManifestEntry> {
        self.entries.clone()
    }

    fn prepare_cleanup_transfer(&mut self, deadline: Instant) -> Result<(), String> {
        let imported = self
            .imported
            .as_ref()
            .ok_or_else(|| "Windows fixture authority cleanup owner is absent".to_owned())?;
        if windows_file_receipt(&self.parent_guard)? != self.parent_receipt
            || windows_bind_path(&self.parent, true)?.1 != self.parent_receipt
        {
            return Err("Windows fixture authority parent changed before transfer".to_owned());
        }
        imported.revalidate_until(deadline)
    }

    fn commit_cleanup_transfer(&mut self) {
        self.imported = None;
        self.transferred = true;
    }
}

#[cfg(windows)]
struct WindowsReporterBorrowedAuthority {
    parent: PathBuf,
    parent_guard: fs::File,
    parent_receipt: WindowsFileReceipt,
    root: PathBuf,
    entries: Vec<crate::release::platform::NightlyWindowsManifestEntry>,
    imported: Option<ImportedWindowsNightlyAuthority>,
    transferred: bool,
}

#[cfg(windows)]
impl WindowsReporterBorrowedAuthority {
    fn bind_until(parent: &Path, root: &Path, deadline: Instant) -> Result<Self, String> {
        let parent = fs::canonicalize(parent).map_err(|error| {
            format!("cannot canonicalize Windows borrowed authority parent: {error}")
        })?;
        let root = fs::canonicalize(root).map_err(|error| {
            format!("cannot canonicalize Windows borrowed fixture authority: {error}")
        })?;
        if root.parent() != Some(parent.as_path()) || Instant::now() >= deadline {
            return Err("Windows borrowed fixture authority topology differs".to_owned());
        }
        let (parent_guard, parent_receipt) = windows_bind_path(&parent, true)?;
        let entries = windows_reporter_fixture_manifest_entries()?;
        let manifest =
            encode_windows_nightly_authority_manifest_parts(&root, entries.clone(), deadline)?;
        let imported = import_authenticated_windows_nightly_authority_manifest(
            &manifest,
            sha256_bytes(&manifest),
            deadline,
        )?;
        if windows_file_receipt(&parent_guard)? != parent_receipt
            || windows_bind_path(&parent, true)?.1 != parent_receipt
        {
            return Err("Windows borrowed authority parent changed during bind".to_owned());
        }
        Ok(Self {
            parent,
            parent_guard,
            parent_receipt,
            root,
            entries,
            imported: Some(imported),
            transferred: false,
        })
    }

    fn cleanup_transferred(&self) -> bool {
        self.transferred
    }
}

#[cfg(windows)]
impl WindowsNightlySupervisorAuthority for WindowsReporterBorrowedAuthority {
    fn staged_root(&self) -> &Path {
        &self.root
    }

    fn manifest_entries(&self) -> Vec<crate::release::platform::NightlyWindowsManifestEntry> {
        self.entries.clone()
    }

    fn prepare_cleanup_transfer(&mut self, deadline: Instant) -> Result<(), String> {
        if windows_file_receipt(&self.parent_guard)? != self.parent_receipt
            || windows_bind_path(&self.parent, true)?.1 != self.parent_receipt
        {
            return Err("Windows borrowed authority parent changed before transfer".to_owned());
        }
        self.imported
            .as_ref()
            .ok_or_else(|| "Windows borrowed authority receipt is absent".to_owned())?
            .revalidate_until(deadline)
    }

    fn commit_cleanup_transfer(&mut self) {
        self.imported = None;
        self.transferred = true;
    }
}

#[cfg(windows)]
fn cleanup_windows_reporter_fixture_authority_root(
    parent: &Path,
    parent_guard: &fs::File,
    parent_receipt: WindowsFileReceipt,
    root: &Path,
    root_guard: fs::File,
    root_receipt: WindowsFileReceipt,
    deadline: Instant,
) -> Result<(), String> {
    if Instant::now() >= deadline
        || windows_file_receipt(parent_guard)? != parent_receipt
        || windows_bind_path(parent, true)?.1 != parent_receipt
        || windows_file_receipt(&root_guard)? != root_receipt
        || windows_bind_path(root, true)?.1 != root_receipt
    {
        return Err("Windows fixture authority changed before setup cleanup".to_owned());
    }
    let mut failures = Vec::new();
    if let Err(error) = reset_windows_supervisor_session(root, deadline) {
        failures.push(error);
    }
    for relative in ["bin/cargo.exe", "bin/rustc.exe"] {
        let path = root.join(relative);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                if let Err(error) = fs::remove_file(&path) {
                    failures.push(format!(
                        "cannot remove Windows fixture authority member {relative}: {error}"
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => failures.push(format!(
                "Windows fixture authority member {relative} changed kind"
            )),
            Err(error) => failures.push(format!(
                "cannot inspect Windows fixture authority member {relative}: {error}"
            )),
        }
    }
    let bin = root.join("bin");
    match fs::symlink_metadata(&bin) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            if let Err(error) = fs::remove_dir(&bin) {
                failures.push(format!(
                    "cannot remove Windows fixture authority bin: {error}"
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => failures.push("Windows fixture authority bin changed kind".to_owned()),
        Err(error) => failures.push(format!(
            "cannot inspect Windows fixture authority bin: {error}"
        )),
    }
    drop(root_guard);
    if let Err(error) = fs::remove_dir(root) {
        failures.push(format!(
            "cannot remove Windows fixture authority root: {error}"
        ));
    }
    if !matches!(
        fs::symlink_metadata(root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ) {
        failures.push("Windows fixture authority root absence was not attested".to_owned());
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; additionally, "))
    }
}

#[cfg(windows)]
fn import_windows_nightly_authority_manifest(
    bytes: &[u8],
    deadline: Instant,
) -> Result<ImportedWindowsNightlyAuthority, String> {
    const MAGIC: &[u8] = b"hell-windows-nightly-authority-v1\0";
    const ENTRY_LIMIT: usize = 100_000;
    const DEPTH_LIMIT: usize = 128;
    let mut remaining = bytes
        .strip_prefix(MAGIC)
        .ok_or_else(|| "Windows authority manifest version differs".to_owned())?;
    let take_u32 = |remaining: &mut &[u8], label: &str| -> Result<u32, String> {
        let (field, tail) = remaining
            .split_at_checked(size_of::<u32>())
            .ok_or_else(|| format!("Windows authority manifest {label} is truncated"))?;
        *remaining = tail;
        Ok(u32::from_be_bytes(field.try_into().map_err(|_| {
            format!("Windows authority manifest {label} width differs")
        })?))
    };
    let take_u64 = |remaining: &mut &[u8], label: &str| -> Result<u64, String> {
        let (field, tail) = remaining
            .split_at_checked(size_of::<u64>())
            .ok_or_else(|| format!("Windows authority manifest {label} is truncated"))?;
        *remaining = tail;
        Ok(u64::from_be_bytes(field.try_into().map_err(|_| {
            format!("Windows authority manifest {label} width differs")
        })?))
    };
    let root_len = usize::try_from(take_u32(&mut remaining, "root length")?)
        .map_err(|_| "Windows authority root length is not representable".to_owned())?;
    if root_len == 0 {
        if !remaining.is_empty() {
            return Err("empty Windows authority manifest has trailing bytes".to_owned());
        }
        return Ok(ImportedWindowsNightlyAuthority {
            root: PathBuf::new(),
            staged_cargo: None,
            staged_rustc: None,
            _root_guard: None,
            _entry_guards: Vec::new(),
            entries: Vec::new(),
        });
    }
    let (root_bytes, tail) = remaining
        .split_at_checked(root_len)
        .ok_or_else(|| "Windows authority manifest root is truncated".to_owned())?;
    remaining = tail;
    let root = PathBuf::from(windows_supervisor_os_from_bytes(root_bytes)?);
    if !root.is_absolute() || fs::canonicalize(&root).ok().as_deref() != Some(root.as_path()) {
        return Err("Windows authority manifest root is not canonical".to_owned());
    }
    let root_receipt = WindowsFileReceipt {
        volume: take_u64(&mut remaining, "root volume")?,
        index: take_u64(&mut remaining, "root index")?,
        size: take_u64(&mut remaining, "root size")?,
        attributes: u32::try_from(take_u64(&mut remaining, "root attributes")?)
            .map_err(|_| "Windows authority root attributes are too large".to_owned())?,
    };
    let (root_guard, observed_root) = windows_bind_path(&root, true)?;
    if observed_root != root_receipt {
        return Err("Windows authority manifest root identity changed".to_owned());
    }
    let count = usize::try_from(take_u32(&mut remaining, "entry count")?)
        .map_err(|_| "Windows authority entry count is not representable".to_owned())?;
    if count == 0 || count > ENTRY_LIMIT {
        return Err("Windows authority entry count exceeds its bound".to_owned());
    }
    let mut guards = Vec::with_capacity(count);
    let mut expected = BTreeMap::from([(PathBuf::new(), true)]);
    let mut staged_cargo = None;
    let mut staged_rustc = None;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if Instant::now() >= deadline {
            return Err("Windows authority import exceeded its execution deadline".to_owned());
        }
        let path_len = usize::try_from(take_u32(&mut remaining, "path length")?)
            .map_err(|_| "Windows authority path length is not representable".to_owned())?;
        let (path_bytes, tail) = remaining
            .split_at_checked(path_len)
            .ok_or_else(|| "Windows authority path is truncated".to_owned())?;
        remaining = tail;
        let relative = PathBuf::from(windows_supervisor_os_from_bytes(path_bytes)?);
        let depth = relative.components().count();
        if relative.is_absolute()
            || depth > DEPTH_LIMIT
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
            || expected.contains_key(&relative)
        {
            return Err("Windows authority manifest contains a noncanonical path".to_owned());
        }
        let (kind, tail) = remaining
            .split_first()
            .ok_or_else(|| "Windows authority entry kind is truncated".to_owned())?;
        remaining = tail;
        let directory = match kind {
            0 => false,
            1 => true,
            _ => return Err("Windows authority entry kind is invalid".to_owned()),
        };
        let receipt = WindowsFileReceipt {
            volume: take_u64(&mut remaining, "entry volume")?,
            index: take_u64(&mut remaining, "entry index")?,
            size: take_u64(&mut remaining, "entry size")?,
            attributes: u32::try_from(take_u64(&mut remaining, "entry attributes")?)
                .map_err(|_| "Windows authority entry attributes are too large".to_owned())?,
        };
        let (digest, tail) = remaining
            .split_at_checked(Digest::default().0.len())
            .ok_or_else(|| "Windows authority entry digest is truncated".to_owned())?;
        remaining = tail;
        let path = root.join(&relative);
        let (guard, observed) = windows_bind_path(&path, directory)?;
        let expected_digest = if directory {
            if digest != Digest::default().0 {
                return Err("Windows authority directory carries a file digest".to_owned());
            }
            None
        } else {
            let expected_digest = Digest(
                digest
                    .try_into()
                    .map_err(|_| "Windows authority entry digest width differs".to_owned())?,
            );
            if expected_digest == Digest::default() {
                return Err("Windows authority file digest is absent".to_owned());
            }
            let observed_digest = hell_testkit::sha256_retained_windows_file_until(
                &guard, deadline,
            )
            .map_err(|error| format!("cannot hash retained Windows authority file: {error}"))?;
            if observed_digest != expected_digest {
                return Err("Windows authority file content changed".to_owned());
            }
            Some(expected_digest)
        };
        if observed != receipt || windows_file_receipt(&guard)? != receipt {
            return Err("Windows authority entry identity changed".to_owned());
        }
        if relative == Path::new("bin/cargo.exe") {
            staged_cargo = Some(path.clone());
        } else if relative == Path::new("bin/rustc.exe") {
            staged_rustc = Some(path.clone());
        }
        entries.push((relative.clone(), directory, receipt, expected_digest));
        expected.insert(relative, directory);
        guards.push(guard);
    }
    if !remaining.is_empty() {
        return Err("Windows authority manifest has trailing bytes".to_owned());
    }
    let observed = windows_toolchain_inventory_paths_for_supervisor(&root, deadline)?;
    if observed != expected {
        return Err("Windows authority manifest topology changed".to_owned());
    }
    Ok(ImportedWindowsNightlyAuthority {
        root,
        staged_cargo,
        staged_rustc,
        _root_guard: Some(root_guard),
        _entry_guards: guards,
        entries,
    })
}

#[cfg(windows)]
fn import_authenticated_windows_nightly_authority_manifest(
    bytes: &[u8],
    expected_sha256: Digest,
    deadline: Instant,
) -> Result<ImportedWindowsNightlyAuthority, String> {
    if sha256_bytes(bytes) != expected_sha256 {
        return Err("Windows authority manifest digest changed".to_owned());
    }
    import_windows_nightly_authority_manifest(bytes, deadline)
}

#[cfg(windows)]
fn windows_toolchain_inventory_paths_for_supervisor(
    root: &Path,
    deadline: Instant,
) -> Result<BTreeMap<PathBuf, bool>, String> {
    let mut inventory = BTreeMap::from([(PathBuf::new(), true)]);
    let mut pending = vec![PathBuf::new()];
    while let Some(parent) = pending.pop() {
        for entry in fs::read_dir(root.join(&parent))
            .map_err(|error| format!("cannot enumerate Windows authority import: {error}"))?
        {
            if Instant::now() >= deadline || inventory.len() >= 100_000 {
                return Err("Windows authority topology import exceeded its bound".to_owned());
            }
            let entry = entry
                .map_err(|error| format!("cannot inspect Windows authority import: {error}"))?;
            let relative = parent.join(entry.file_name());
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| format!("cannot inspect Windows authority import: {error}"))?;
            if metadata.file_type().is_symlink() || !(metadata.is_dir() || metadata.is_file()) {
                return Err("Windows authority import contains a redirected entry".to_owned());
            }
            inventory.insert(relative.clone(), metadata.is_dir());
            if metadata.is_dir() {
                pending.push(relative);
            }
        }
    }
    Ok(inventory)
}

#[cfg(windows)]
fn verify_windows_nightly_authority_manifest_for_integration(
    parent: &Path,
    deadline: Instant,
    cleanup_deadline: Instant,
) -> Result<(), String> {
    if deadline >= cleanup_deadline {
        return Err("Windows manifest verifier cleanup reserve is absent".to_owned());
    }
    let parent = fs::canonicalize(parent)
        .map_err(|error| format!("cannot canonicalize manifest verifier parent: {error}"))?;
    let (parent_guard, parent_receipt) = windows_bind_path(&parent, true)?;
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| format!("cannot allocate manifest verifier nonce: {error}"))?;
    let root = parent.join(format!(
        "nightly-authority-manifest-{}-{}",
        std::process::id(),
        sha256_bytes(&nonce).hex()
    ));
    fs::create_dir(&root)
        .map_err(|error| format!("cannot create manifest verifier root: {error}"))?;
    let (root_guard, root_receipt) = windows_bind_path(&root, true)?;
    let primary = (|| {
        let bin = root.join("bin");
        fs::create_dir(&bin)
            .map_err(|error| format!("cannot create manifest verifier bin: {error}"))?;
        let cargo = bin.join("cargo.exe");
        let rustc = bin.join("rustc.exe");
        let cargo_bytes = b"manifest-cargo\n";
        let rustc_bytes = b"manifest-rustc\n";
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&cargo)
            .and_then(|mut file| file.write_all(cargo_bytes))
            .map_err(|error| format!("cannot create manifest verifier cargo: {error}"))?;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&rustc)
            .and_then(|mut file| file.write_all(rustc_bytes))
            .map_err(|error| format!("cannot create manifest verifier rustc: {error}"))?;
        let entries = vec![
            crate::release::platform::NightlyWindowsManifestEntry {
                relative: PathBuf::from("bin"),
                directory: true,
                size: 0,
                sha256: None,
            },
            crate::release::platform::NightlyWindowsManifestEntry {
                relative: PathBuf::from("bin/cargo.exe"),
                directory: false,
                size: u64::try_from(cargo_bytes.len())
                    .map_err(|_| "manifest cargo size is not representable".to_owned())?,
                sha256: Some(sha256_bytes(cargo_bytes)),
            },
            crate::release::platform::NightlyWindowsManifestEntry {
                relative: PathBuf::from("bin/rustc.exe"),
                directory: false,
                size: u64::try_from(rustc_bytes.len())
                    .map_err(|_| "manifest rustc size is not representable".to_owned())?,
                sha256: Some(sha256_bytes(rustc_bytes)),
            },
        ];
        let manifest = encode_windows_nightly_authority_manifest_parts(&root, entries, deadline)?;
        let manifest_sha256 = sha256_bytes(&manifest);
        let imported = import_authenticated_windows_nightly_authority_manifest(
            &manifest,
            manifest_sha256,
            deadline,
        )?;
        if imported.staged_cargo.as_deref() != Some(cargo.as_path())
            || imported.staged_rustc.as_deref() != Some(rustc.as_path())
        {
            return Err("manifest verifier executable mapping differs".to_owned());
        }
        let wrapped = windows_write_restricted_supervisor_command(
            CommandSpec::cargo(Duration::from_secs(1)).current_directory(&parent),
            &parent,
            Some(&imported),
            deadline,
        )?;
        if Path::new(&wrapped.program) != cargo {
            return Err("manifest verifier did not launch the retained staged Cargo".to_owned());
        }
        if windows_write_restricted_supervisor_command(
            CommandSpec::cargo(Duration::from_secs(1)).current_directory(&parent),
            &parent,
            Some(&imported),
            Instant::now(),
        )
        .is_ok()
        {
            return Err("expired Windows restricted payload construction was accepted".to_owned());
        }
        drop(imported);

        let mutated_cargo = b"manifest-Cargo\n";
        if mutated_cargo.len() != cargo_bytes.len() {
            return Err("manifest verifier same-size mutation fixture differs".to_owned());
        }
        fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&cargo)
            .and_then(|mut file| file.write_all(mutated_cargo))
            .map_err(|error| format!("cannot mutate manifest verifier cargo: {error}"))?;
        if import_authenticated_windows_nightly_authority_manifest(
            &manifest,
            manifest_sha256,
            deadline,
        )
        .is_ok()
        {
            return Err("same-size Windows authority file mutation was accepted".to_owned());
        }
        fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&cargo)
            .and_then(|mut file| file.write_all(cargo_bytes))
            .map_err(|error| format!("cannot restore manifest verifier cargo: {error}"))?;

        let mut mutated = manifest.clone();
        let last = mutated
            .last_mut()
            .ok_or_else(|| "manifest verifier payload is empty".to_owned())?;
        *last ^= 1;
        if import_authenticated_windows_nightly_authority_manifest(
            &mutated,
            manifest_sha256,
            deadline,
        )
        .is_ok()
        {
            return Err("mutated Windows authority manifest was accepted".to_owned());
        }
        let truncated = manifest
            .get(..manifest.len().saturating_sub(1))
            .ok_or_else(|| "manifest verifier truncation underflowed".to_owned())?;
        if import_authenticated_windows_nightly_authority_manifest(
            truncated,
            sha256_bytes(truncated),
            deadline,
        )
        .is_ok()
        {
            return Err("truncated Windows authority manifest was accepted".to_owned());
        }
        let mut trailing = manifest.clone();
        trailing.push(0);
        if import_authenticated_windows_nightly_authority_manifest(
            &trailing,
            sha256_bytes(&trailing),
            deadline,
        )
        .is_ok()
        {
            return Err("Windows authority manifest trailing bytes were accepted".to_owned());
        }
        if import_authenticated_windows_nightly_authority_manifest(
            &manifest,
            manifest_sha256,
            Instant::now(),
        )
        .is_ok()
        {
            return Err("expired Windows authority import was accepted".to_owned());
        }
        let extra = bin.join("extra.exe");
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&extra)
            .and_then(|mut file| file.write_all(b"extra\n"))
            .map_err(|error| format!("cannot create extra manifest entry: {error}"))?;
        if import_authenticated_windows_nightly_authority_manifest(
            &manifest,
            manifest_sha256,
            deadline,
        )
        .is_ok()
        {
            return Err("extra Windows authority topology entry was accepted".to_owned());
        }
        fs::remove_file(&extra)
            .map_err(|error| format!("cannot remove extra manifest entry: {error}"))?;
        fs::remove_file(&rustc)
            .map_err(|error| format!("cannot remove manifest rustc entry: {error}"))?;
        if import_authenticated_windows_nightly_authority_manifest(
            &manifest,
            manifest_sha256,
            deadline,
        )
        .is_ok()
        {
            return Err("missing Windows authority topology entry was accepted".to_owned());
        }
        fs::remove_file(&cargo)
            .map_err(|error| format!("cannot remove manifest cargo entry: {error}"))?;
        fs::remove_dir(&bin).map_err(|error| format!("cannot remove manifest bin: {error}"))?;
        Ok(())
    })();
    let cleanup = (|| {
        if Instant::now() >= cleanup_deadline
            || windows_file_receipt(&parent_guard)? != parent_receipt
            || windows_bind_path(&parent, true)?.1 != parent_receipt
            || windows_file_receipt(&root_guard)? != root_receipt
            || windows_bind_path(&root, true)?.1 != root_receipt
        {
            return Err("manifest verifier ownership changed before cleanup".to_owned());
        }
        for relative in ["bin/extra.exe", "bin/rustc.exe", "bin/cargo.exe"] {
            if Instant::now() >= cleanup_deadline {
                return Err(
                    "Windows manifest verifier file cleanup exceeded its deadline".to_owned(),
                );
            }
            let path = root.join(relative);
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    let (guard, receipt) = windows_bind_path(&path, false)?;
                    if windows_file_receipt(&guard)? != receipt {
                        return Err("manifest verifier file changed before cleanup".to_owned());
                    }
                    drop(guard);
                    fs::remove_file(&path).map_err(|error| {
                        format!("cannot remove manifest verifier file {relative}: {error}")
                    })?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => return Err("manifest verifier cleanup entry is not a file".to_owned()),
                Err(error) => {
                    return Err(format!("cannot inspect manifest verifier cleanup: {error}"));
                }
            }
        }
        let bin = root.join("bin");
        if Instant::now() >= cleanup_deadline {
            return Err(
                "Windows manifest verifier directory cleanup exceeded its deadline".to_owned(),
            );
        }
        match fs::symlink_metadata(&bin) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                fs::remove_dir(&bin)
                    .map_err(|error| format!("cannot remove manifest verifier bin: {error}"))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err("manifest verifier bin is not a directory".to_owned()),
            Err(error) => {
                return Err(format!("cannot inspect manifest verifier bin: {error}"));
            }
        }
        drop(root_guard);
        fs::remove_dir(&root)
            .map_err(|error| format!("cannot remove manifest verifier root: {error}"))?;
        match fs::symlink_metadata(&root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("cannot attest manifest verifier absence: {error}")),
            Ok(_) => Err("manifest verifier root remains after cleanup".to_owned()),
        }
    })();
    match (primary, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(format!(
            "{primary}; additionally, manifest cleanup failed: {cleanup}"
        )),
    }
}

#[cfg(windows)]
struct WindowsPipeSupervisorLaunch {
    child: WindowsSupervisorProcess,
    control: firehazard::io::WritePipe,
    observations: mpsc::Receiver<Result<Vec<u8>, String>>,
    observer_dropped: Arc<AtomicU64>,
}

#[cfg(windows)]
fn windows_read_inherited_frame(
    reader: &mut impl std::io::Read,
) -> Result<Option<Vec<u8>>, String> {
    let mut length = [0_u8; size_of::<u32>()];
    match reader.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => {
            return Err(format!(
                "cannot read Windows supervisor pipe frame: {error}"
            ));
        }
    }
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| "Windows supervisor pipe frame length is not representable".to_owned())?;
    if length > NIGHTLY_SUPERVISOR_TERMINAL_LIMIT {
        return Err("Windows supervisor pipe frame exceeds its global byte limit".to_owned());
    }
    let mut frame = vec![0_u8; length];
    reader
        .read_exact(&mut frame)
        .map_err(|error| format!("cannot read Windows supervisor pipe frame body: {error}"))?;
    Ok(Some(frame))
}

#[cfg(windows)]
fn windows_write_inherited_frame(
    writer: &mut impl std::io::Write,
    frame: &[u8],
) -> Result<(), String> {
    if frame.len() > NIGHTLY_SUPERVISOR_TERMINAL_LIMIT {
        return Err("Windows supervisor pipe frame exceeds its global byte limit".to_owned());
    }
    let length = u32::try_from(frame.len())
        .map_err(|_| "Windows supervisor pipe frame length is not representable".to_owned())?;
    let mut encoded = Vec::with_capacity(size_of::<u32>() + frame.len());
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(frame);
    writer
        .write_all(&encoded)
        .and_then(|()| writer.flush())
        .map_err(|error| format!("cannot write Windows supervisor pipe frame: {error}"))
}

#[cfg(windows)]
fn spawn_windows_pipe_supervisor(
    executable: &Path,
    protocol: &str,
) -> Result<WindowsPipeSupervisorLaunch, String> {
    const STARTF_USE_STD_HANDLES: u32 = 0x0000_0100;

    let inheritable = firehazard::security::Attributes::new(None, true);
    let pipe_capacity =
        u32::try_from(NIGHTLY_SUPERVISOR_TERMINAL_LIMIT.saturating_add(size_of::<u32>()))
            .map_err(|_| "Windows supervisor pipe capacity is not representable".to_owned())?;
    let (control_read, control_write) =
        firehazard::io::create_pipe(Some(&inheritable), pipe_capacity)
            .map_err(|error| format!("cannot create Windows supervisor control pipe: {error:?}"))?;
    let (observation_read, observation_write) =
        firehazard::io::create_pipe(Some(&inheritable), pipe_capacity).map_err(|error| {
            format!("cannot create Windows supervisor observation pipe: {error:?}")
        })?;
    firehazard::handle::set_handle_information(
        &control_write,
        firehazard::handle::FLAG_INHERIT,
        (),
    )
    .map_err(|error| format!("cannot confine Windows supervisor control handle: {error:?}"))?;
    firehazard::handle::set_handle_information(
        &observation_read,
        firehazard::handle::FLAG_INHERIT,
        (),
    )
    .map_err(|error| format!("cannot confine Windows supervisor observation handle: {error:?}"))?;
    let null_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("NUL")
        .map(firehazard::io::File::from)
        .map_err(|error| format!("cannot open Windows supervisor null diagnostic sink: {error}"))?;
    firehazard::handle::set_handle_information(&null_file, (), firehazard::handle::FLAG_INHERIT)
        .map_err(|error| {
            format!("cannot make Windows supervisor null sink inheritable: {error:?}")
        })?;

    let supervisor_job = firehazard::create_job_object_w(None, ())
        .map_err(|error| format!("cannot create Windows supervisor Job: {error:?}"))?;
    let limits = firehazard::job::object::ExtendedLimitInformation {
        basic_limit_information: firehazard::job::object::BasicLimitInformation {
            limit_flags: firehazard::job::object::limit::KILL_ON_JOB_CLOSE,
            ..Default::default()
        },
        ..Default::default()
    };
    firehazard::set_information_job_object(&supervisor_job, limits)
        .map_err(|error| format!("cannot configure Windows supervisor Job: {error:?}"))?;
    let protocol_token = hell_testkit::encode_windows_argv(&[std::ffi::OsString::from(protocol)])
        .map_err(|error| {
        format!("cannot encode Windows supervisor protocol selector: {error}")
    })?;

    let inherited_handles = [
        (&control_read).into(),
        (&observation_write).into(),
        (&null_file).into(),
    ];
    let supervisor_jobs = [(&supervisor_job).into()];
    let attributes = [
        firehazard::process::ThreadAttributeRef::job_list(&supervisor_jobs),
        firehazard::process::ThreadAttributeRef::handle_list(&inherited_handles),
    ];
    let mut startup = firehazard::process::StartupInfoExW::default();
    startup.startup_info.flags = STARTF_USE_STD_HANDLES;
    startup.startup_info.std_input = Some((&control_read).into());
    startup.startup_info.std_output = Some((&observation_write).into());
    startup.startup_info.std_error = Some((&null_file).into());
    startup.attribute_list = Some(
        firehazard::process::ThreadAttributeList::try_from(attributes.as_slice())
            .map_err(|error| format!("cannot bind Windows supervisor handle list: {error:?}"))?,
    );
    let application = widestring::U16CString::from_os_str(executable.as_os_str())
        .map_err(|error| format!("Windows supervisor executable contains NUL: {error}"))?;
    let arguments = [
        std::ffi::OsString::from("__release-command-supervisor-v1"),
        protocol_token,
    ];
    let mut command_line = firehazard::process::argv_to_command_line_0(executable, arguments);
    let administrators = firehazard::convert_string_sid_to_sid_a("S-1-5-32-544")
        .map_err(|error| format!("cannot bind Windows Administrators SID: {error:?}"))?;
    let system = firehazard::convert_string_sid_to_sid_a("S-1-5-18")
        .map_err(|error| format!("cannot bind Windows System SID: {error:?}"))?;
    let restricted_code = firehazard::convert_string_sid_to_sid_a("S-1-5-12")
        .map_err(|error| format!("cannot bind Windows Restricted Code SID: {error:?}"))?;
    let owner_rights = firehazard::convert_string_sid_to_sid_a("S-1-3-4")
        .map_err(|error| format!("cannot bind Windows Owner Rights SID: {error:?}"))?;
    let mut process_acl = firehazard::acl::Builder::new(firehazard::acl::REVISION);
    process_acl
        .add_access_denied_ace(
            firehazard::acl::REVISION,
            firehazard::access::GENERIC_ALL.into(),
            &owner_rights,
        )
        .and_then(|acl| {
            acl.add_access_denied_ace(
                firehazard::acl::REVISION,
                firehazard::access::GENERIC_ALL.into(),
                &restricted_code,
            )
        })
        .and_then(|acl| {
            acl.add_access_allowed_ace(
                firehazard::acl::REVISION,
                firehazard::access::GENERIC_ALL.into(),
                &administrators,
            )
        })
        .and_then(|acl| {
            acl.add_access_allowed_ace(
                firehazard::acl::REVISION,
                firehazard::access::GENERIC_ALL.into(),
                &system,
            )
        })
        .and_then(firehazard::acl::Builder::finish)
        .map_err(|error| format!("cannot build Windows supervisor process ACL: {error:?}"))?;
    let process_security = firehazard::security::DescriptorBuilder::new()
        .owner(&*administrators, false)
        .and_then(|descriptor| descriptor.dacl(true, process_acl.as_acl_ptr(), false))
        .map(firehazard::security::DescriptorBuilder::finish)
        .map_err(|error| {
            format!("cannot build Windows supervisor process descriptor: {error:?}")
        })?;
    let process_attributes = firehazard::security::Attributes::new(Some(&process_security), false);
    let process = firehazard::create_process_w(
        application,
        Some(&mut command_line),
        Some(&process_attributes),
        None,
        true,
        firehazard::process::CREATE_BREAKAWAY_FROM_JOB
            | firehazard::process::CREATE_SUSPENDED
            | firehazard::process::EXTENDED_STARTUPINFO_PRESENT,
        firehazard::process::environment::Inherit,
        (),
        &startup,
    )
    .map_err(|error| format!("cannot create suspended breakaway Windows supervisor: {error:?}"))?;
    if !firehazard::is_process_in_job(&process.process, Some(&supervisor_job))
        .map_err(|error| format!("cannot attest Windows supervisor Job membership: {error:?}"))?
    {
        return Err("Windows supervisor is absent from its retained Job".to_owned());
    }
    drop(startup);
    drop(control_read);
    drop(observation_write);
    drop(null_file);

    let (observation_sender, observations) = mpsc::sync_channel(8);
    let observer_dropped = Arc::new(AtomicU64::new(0));
    let observer_drop_counter = Arc::clone(&observer_dropped);
    std::thread::Builder::new()
        .name("hell-windows-supervisor-observer".to_owned())
        .spawn(move || {
            let mut observation_read = observation_read;
            loop {
                match windows_read_inherited_frame(&mut observation_read) {
                    Ok(Some(frame)) => {
                        if frame.first() == Some(&6) {
                            match observation_sender.try_send(Ok(frame)) {
                                Ok(()) => {}
                                Err(mpsc::TrySendError::Full(_)) => {
                                    observer_drop_counter.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(mpsc::TrySendError::Disconnected(_)) => return,
                            }
                        } else if observation_sender.send(Ok(frame)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => return,
                    Err(error) => {
                        let _ = observation_sender.send(Err(error));
                        return;
                    }
                }
            }
        })
        .map_err(|error| format!("cannot start Windows supervisor observer: {error}"))?;
    firehazard::thread::resume_thread(&process.thread)
        .map_err(|error| format!("cannot resume Windows supervisor: {error:?}"))?;
    Ok(WindowsPipeSupervisorLaunch {
        child: WindowsSupervisorProcess {
            process: process.process,
            process_id: process.process_id,
            supervisor_job: Some(supervisor_job),
        },
        control: control_write,
        observations,
        observer_dropped,
    })
}

#[cfg(windows)]
fn prepare_windows_external_supervisor(
    root: &Path,
    session_parent: &Path,
    plan: ExternalSupervisorPlan,
    phase_started: Instant,
    envelope: SupervisionEnvelope,
    fixture_gate: Option<SocketAddrV4>,
    fixture_exit_observer: Option<SocketAddrV4>,
    authority: Option<&dyn WindowsNightlySupervisorAuthority>,
) -> Result<WindowsExternalPrepared, WindowsExternalStartFailure> {
    let startup_cleanup_deadline = phase_started
        .checked_add(NIGHTLY_SUPERVISOR_START_TIMEOUT)
        .unwrap_or(envelope.execution)
        .min(envelope.execution);
    let startup_deadline = startup_cleanup_deadline
        .checked_sub(NIGHTLY_SUPERVISOR_START_CLEANUP_RESERVE)
        .ok_or_else(|| "Windows supervisor startup cleanup reserve underflowed".to_owned())?;
    let root = fs::canonicalize(root)
        .map_err(|error| format!("cannot canonicalize Windows supervisor workspace: {error}"))?;
    let (_root, root_receipt) = windows_bind_path(&root, true)?;
    let writable_target =
        fs::canonicalize(release_candidate_target().unwrap_or_else(|| root.join("target")))
            .map_err(|error| {
                format!("cannot canonicalize Windows Nightly writable target: {error}")
            })?;
    let (_writable_target, writable_target_receipt) = windows_bind_path(&writable_target, true)?;
    let nonce = windows_supervisor_nonce()?;
    let mut seed_fields = vec![
        plan.code().to_string().into(),
        root.as_os_str().to_owned(),
        writable_target.as_os_str().to_owned(),
    ];
    seed_fields.extend(windows_receipt_fields(root_receipt));
    seed_fields.extend(windows_receipt_fields(writable_target_receipt));
    let seed = hell_testkit::encode_windows_argv(&seed_fields)
        .map_err(|error| format!("cannot encode Windows supervisor seed: {error}"))?;
    let seed_digest = windows_supervisor_os_digest(&seed);
    let mut session =
        WindowsSupervisorSession::create(session_parent, &seed_digest.0, startup_deadline)?;
    let prepared = (|| {
        let late_receipt = session.create_late_receipt(startup_deadline)?;
        let manifest = encode_windows_nightly_authority_manifest(authority, envelope.execution)?;
        let (manifest_receipt, manifest_sha256) =
            session.seal_authority_manifest(&manifest, startup_deadline)?;
        let fields = windows_supervisor_request_fields(WindowsSupervisorRequestFields {
            plan,
            root: (&root, root_receipt),
            writable_target: (&writable_target, writable_target_receipt),
            session: &session,
            late_receipt,
            manifest_receipt,
            manifest_sha256,
            nonce,
            envelope,
            lifetime_deadline: if let Some(followup) = plan.combined_followup()
                && authority.is_some()
            {
                envelope
                    .report_completion_deadline
                    .checked_add(followup.total())
                    .unwrap_or(envelope.report_completion_deadline)
            } else {
                envelope.report_completion_deadline
            },
            fixture_gate,
            fixture_exit_observer,
        })?;
        let token = hell_testkit::encode_windows_argv(&fields)
            .map_err(|error| format!("cannot encode Windows supervisor request: {error}"))?;
        let request_sha256 = windows_supervisor_os_digest(&token);
        session.seal_request_digest(request_sha256, startup_deadline)?;
        let executable =
            fs::canonicalize(std::env::current_exe().map_err(|error| {
                format!("cannot locate Windows supervisor executable: {error}")
            })?)
            .map_err(|error| {
                format!("cannot canonicalize Windows supervisor executable: {error}")
            })?;
        let (executable_guard, executable_receipt) = windows_bind_path(&executable, false)?;
        Ok::<_, String>((
            token,
            request_sha256,
            executable,
            executable_guard,
            executable_receipt,
            manifest_sha256,
        ))
    })();
    let (token, request_sha256, executable, executable_guard, executable_receipt, manifest_sha256) =
        match prepared {
            Ok(prepared) => prepared,
            Err(primary) => {
                return Err(close_unstarted_windows_supervisor_session(
                    session,
                    startup_cleanup_deadline,
                    primary,
                ));
            }
        };
    let launch = match spawn_windows_pipe_supervisor(&executable, "windows-inherited-pipe-v1") {
        Ok(launch) => launch,
        Err(error) => {
            return Err(close_unstarted_windows_supervisor_session(
                session,
                startup_cleanup_deadline,
                error,
            ));
        }
    };
    let WindowsPipeSupervisorLaunch {
        child,
        mut control,
        observations,
        observer_dropped,
    } = launch;
    let executable_stable = windows_file_receipt(&executable_guard).and_then(|retained| {
        windows_bind_path(&executable, false).map(|(_, path_receipt)| {
            retained == executable_receipt && path_receipt == executable_receipt
        })
    });
    if !matches!(executable_stable, Ok(true)) {
        return Err(close_prelaunch_windows_supervisor(
            child,
            session,
            request_sha256,
            nonce,
            startup_cleanup_deadline,
            executable_stable.err().unwrap_or_else(|| {
                "Windows supervisor executable changed across launch".to_owned()
            }),
        ));
    }
    if let Err(primary) =
        windows_write_inherited_frame(&mut control, &windows_supervisor_os_bytes(&token))
    {
        return Err(close_prelaunch_windows_supervisor(
            child,
            session,
            request_sha256,
            nonce,
            startup_cleanup_deadline,
            primary,
        ));
    }
    let receive_until = |deadline: Instant| {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("Windows supervisor observation exceeded its deadline".to_owned());
        }
        observations
            .recv_timeout(remaining)
            .map_err(|error| format!("cannot receive Windows supervisor observation: {error}"))?
    };
    let ready = match receive_until(startup_deadline) {
        Ok(ready) => ready,
        Err(primary) => {
            return Err(close_prelaunch_windows_supervisor(
                child,
                session,
                request_sha256,
                nonce,
                startup_cleanup_deadline,
                primary,
            ));
        }
    };
    if let Err(primary) = windows_validate_frame(&ready, 1, request_sha256, nonce) {
        return Err(close_prelaunch_windows_supervisor(
            child,
            session,
            request_sha256,
            nonce,
            startup_cleanup_deadline,
            primary,
        ));
    }
    if let Err(primary) = session.retain_read_only_receipts() {
        return Err(close_prelaunch_windows_supervisor(
            child,
            session,
            request_sha256,
            nonce,
            startup_cleanup_deadline,
            primary,
        ));
    }
    Ok(WindowsExternalPrepared {
        child,
        control,
        observations,
        observer_dropped,
        session,
        request_sha256,
        nonce,
        manifest_sha256,
        startup_cleanup_deadline,
        ownership_deadline: envelope.execution,
        ownership_cleanup_deadline: envelope.child_completion_deadline,
    })
}

#[cfg(windows)]
enum WindowsAuthorityTransferEvent {
    Imported(Digest),
    Committed,
}

#[cfg(windows)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum WindowsAuthorityTransferDecision {
    Continue,
    RetainBeforeCommit,
    RetainBeforeGo,
}

#[cfg(windows)]
fn transfer_windows_external_supervisor(
    prepared: WindowsExternalPrepared,
    mut authority_transfer: impl FnMut(
        WindowsAuthorityTransferEvent,
    ) -> Result<WindowsAuthorityTransferDecision, String>,
) -> Result<WindowsExternalStarted, WindowsExternalStartFailure> {
    let WindowsExternalPrepared {
        mut child,
        mut control,
        observations,
        observer_dropped,
        session,
        request_sha256,
        nonce,
        manifest_sha256,
        ownership_deadline,
        ownership_cleanup_deadline,
        ..
    } = prepared;
    let receive_until = |deadline: Instant| {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("Windows supervisor observation exceeded its deadline".to_owned());
        }
        observations
            .recv_timeout(remaining)
            .map_err(|error| format!("cannot receive Windows supervisor observation: {error}"))?
    };
    let imported = match receive_until(ownership_deadline) {
        Ok(imported) => imported,
        Err(error) => {
            return Err(WindowsExternalStartFailure {
                detail: format!(
                    "{error}; Windows supervisor accepted its request but did not publish authority import"
                ),
                retained: Some(Box::new(WindowsExternalStartReceipt {
                    child,
                    session,
                    request_sha256,
                    nonce,
                })),
            });
        }
    };
    let imported_payload = match windows_validate_frame(&imported, 7, request_sha256, nonce) {
        Ok(payload) => payload,
        Err(error) => {
            return Err(WindowsExternalStartFailure {
                detail: format!(
                    "{error}; Windows supervisor published an invalid authority import receipt"
                ),
                retained: Some(Box::new(WindowsExternalStartReceipt {
                    child,
                    session,
                    request_sha256,
                    nonce,
                })),
            });
        }
    };
    if imported_payload != manifest_sha256.0 {
        return Err(WindowsExternalStartFailure {
            detail: "Windows supervisor authority import digest differs".to_owned(),
            retained: Some(Box::new(WindowsExternalStartReceipt {
                child,
                session,
                request_sha256,
                nonce,
            })),
        });
    }
    match authority_transfer(WindowsAuthorityTransferEvent::Imported(manifest_sha256)) {
        Ok(WindowsAuthorityTransferDecision::Continue) => {}
        Ok(WindowsAuthorityTransferDecision::RetainBeforeCommit) => {
            return Err(WindowsExternalStartFailure {
                detail:
                    "Windows reporter fixture exited after authority import before cleanup commit"
                        .to_owned(),
                retained: Some(Box::new(WindowsExternalStartReceipt {
                    child,
                    session,
                    request_sha256,
                    nonce,
                })),
            });
        }
        Ok(WindowsAuthorityTransferDecision::RetainBeforeGo) => {
            return Err(close_prelaunch_windows_supervisor(
                child,
                session,
                request_sha256,
                nonce,
                ownership_cleanup_deadline,
                "Windows reporter fixture requested a postcommit exit before commit".to_owned(),
            ));
        }
        Err(primary) => {
            return Err(close_prelaunch_windows_supervisor(
                child,
                session,
                request_sha256,
                nonce,
                ownership_cleanup_deadline,
                primary,
            ));
        }
    }
    let commit = match windows_supervisor_frame(10, request_sha256, nonce, &[]) {
        Ok(commit) => commit,
        Err(primary) => {
            return Err(WindowsExternalStartFailure {
                detail: format!(
                    "{primary}; Windows cleanup ownership was irrevocably transferred before commit construction"
                ),
                retained: Some(Box::new(WindowsExternalStartReceipt {
                    child,
                    session,
                    request_sha256,
                    nonce,
                })),
            });
        }
    };
    if let Err(primary) = windows_write_inherited_frame(&mut control, &commit) {
        return Err(WindowsExternalStartFailure {
            detail: format!(
                "{primary}; Windows cleanup commit delivery was indeterminate after local transfer"
            ),
            retained: Some(Box::new(WindowsExternalStartReceipt {
                child,
                session,
                request_sha256,
                nonce,
            })),
        });
    }
    let committed = match receive_until(ownership_deadline) {
        Ok(committed) => committed,
        Err(error) => {
            return Err(WindowsExternalStartFailure {
                detail: format!("{error}; Windows cleanup commit was sent but not acknowledged"),
                retained: Some(Box::new(WindowsExternalStartReceipt {
                    child,
                    session,
                    request_sha256,
                    nonce,
                })),
            });
        }
    };
    if let Err(error) = windows_validate_frame(&committed, 11, request_sha256, nonce) {
        return Err(WindowsExternalStartFailure {
            detail: format!("{error}; Windows cleanup commit acknowledgement differed"),
            retained: Some(Box::new(WindowsExternalStartReceipt {
                child,
                session,
                request_sha256,
                nonce,
            })),
        });
    }
    match authority_transfer(WindowsAuthorityTransferEvent::Committed) {
        Ok(WindowsAuthorityTransferDecision::Continue) => {}
        Ok(WindowsAuthorityTransferDecision::RetainBeforeCommit) => {
            return Err(WindowsExternalStartFailure {
                detail: "Windows reporter fixture requested a precommit exit after commit"
                    .to_owned(),
                retained: Some(Box::new(WindowsExternalStartReceipt {
                    child,
                    session,
                    request_sha256,
                    nonce,
                })),
            });
        }
        Ok(WindowsAuthorityTransferDecision::RetainBeforeGo) => {
            return Err(WindowsExternalStartFailure {
                detail: "Windows reporter fixture exited after cleanup commit before Go".to_owned(),
                retained: Some(Box::new(WindowsExternalStartReceipt {
                    child,
                    session,
                    request_sha256,
                    nonce,
                })),
            });
        }
        Err(primary) => {
            return Err(WindowsExternalStartFailure {
                detail: format!(
                    "{primary}; Windows cleanup successor committed before local ownership state transition"
                ),
                retained: Some(Box::new(WindowsExternalStartReceipt {
                    child,
                    session,
                    request_sha256,
                    nonce,
                })),
            });
        }
    }
    let go = match windows_supervisor_frame(2, request_sha256, nonce, &[]) {
        Ok(go) => go,
        Err(primary) => {
            return Err(WindowsExternalStartFailure {
                detail: format!(
                    "{primary}; Windows cleanup ownership was transferred before Go construction"
                ),
                retained: Some(Box::new(WindowsExternalStartReceipt {
                    child,
                    session,
                    request_sha256,
                    nonce,
                })),
            });
        }
    };
    if let Err(primary) = windows_write_inherited_frame(&mut control, &go) {
        return Err(WindowsExternalStartFailure {
            detail: format!(
                "{primary}; Windows Go delivery was indeterminate after cleanup ownership transfer"
            ),
            retained: Some(Box::new(WindowsExternalStartReceipt {
                child,
                session,
                request_sha256,
                nonce,
            })),
        });
    }
    if let Err(primary) = child.transfer() {
        return Err(WindowsExternalStartFailure {
            detail: format!(
                "{primary}; Windows cleanup ownership was transferred before supervisor Job handoff"
            ),
            retained: Some(Box::new(WindowsExternalStartReceipt {
                child,
                session,
                request_sha256,
                nonce,
            })),
        });
    }
    let started = match receive_until(ownership_deadline) {
        Ok(started) => started,
        Err(error) => {
            return Err(WindowsExternalStartFailure {
                detail: format!(
                    "{error}; Windows supervisor accepted ownership but did not publish its start receipt"
                ),
                retained: Some(Box::new(WindowsExternalStartReceipt {
                    child,
                    session,
                    request_sha256,
                    nonce,
                })),
            });
        }
    };
    let started_payload = match windows_validate_frame(&started, 3, request_sha256, nonce) {
        Ok(payload) => payload,
        Err(error) => {
            return Err(WindowsExternalStartFailure {
                detail: format!(
                    "{error}; Windows supervisor accepted ownership but published an invalid start receipt"
                ),
                retained: Some(Box::new(WindowsExternalStartReceipt {
                    child,
                    session,
                    request_sha256,
                    nonce,
                })),
            });
        }
    };
    let digest_width = Digest::default().0.len();
    let started_sha256 = if started_payload.len() == digest_width {
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(started_payload);
        Digest(digest)
    } else {
        return Err(WindowsExternalStartFailure {
            detail: "Windows supervisor start receipt digest width differs".to_owned(),
            retained: Some(Box::new(WindowsExternalStartReceipt {
                child,
                session,
                request_sha256,
                nonce,
            })),
        });
    };
    let started_path = session.root_path.join("started.receipt");
    let started_receipt =
        windows_bind_path(&started_path, false).and_then(|(mut file, receipt)| {
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .map_err(|error| format!("cannot read Windows start receipt: {error}"))?;
            if sha256_bytes(&bytes) != started_sha256 || windows_file_receipt(&file)? != receipt {
                return Err(
                    "Windows start receipt differs from its authenticated digest".to_owned(),
                );
            }
            Ok(())
        });
    if let Err(error) = started_receipt {
        return Err(WindowsExternalStartFailure {
            detail: error,
            retained: Some(Box::new(WindowsExternalStartReceipt {
                child,
                session,
                request_sha256,
                nonce,
            })),
        });
    }
    Ok(WindowsExternalStarted {
        child,
        control,
        observations,
        observer_dropped,
        session,
        request_sha256,
        nonce,
        started_sha256,
    })
}

#[cfg(windows)]
fn close_prepared_windows_supervisor(
    prepared: WindowsExternalPrepared,
    primary: String,
) -> WindowsExternalStartFailure {
    close_prelaunch_windows_supervisor(
        prepared.child,
        prepared.session,
        prepared.request_sha256,
        prepared.nonce,
        prepared.startup_cleanup_deadline,
        primary,
    )
}

#[cfg(windows)]
fn persist_windows_supervisor_receipt(
    file: &mut fs::File,
    initial: WindowsFileReceipt,
    bytes: &[u8],
    label: &str,
) -> Result<(), String> {
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot persist Windows supervisor {label} receipt: {error}"))?;
    let final_receipt = windows_file_receipt(file)?;
    let expected = WindowsFileReceipt {
        size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        ..initial
    };
    if final_receipt != expected {
        return Err(format!(
            "Windows supervisor {label} receipt identity changed during publication"
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn persist_windows_supervisor_abnormal(
    file: &mut fs::File,
    initial: WindowsFileReceipt,
    request_sha256: Digest,
    nonce: Digest,
    detail: &str,
) -> Result<(), String> {
    let token = hell_testkit::encode_windows_argv(&[
        std::ffi::OsString::from("windows-supervisor-abnormal-v1"),
        std::ffi::OsString::from(request_sha256.hex()),
        std::ffi::OsString::from(nonce.hex()),
        std::ffi::OsString::from(bounded_external_supervisor_detail(detail)),
    ])
    .map_err(|error| format!("cannot encode Windows supervisor abnormal receipt: {error}"))?;
    let bytes = windows_supervisor_os_bytes(&token);
    if bytes.len() > NIGHTLY_SUPERVISOR_TERMINAL_LIMIT {
        return Err("Windows supervisor abnormal receipt exceeds its global byte limit".to_owned());
    }
    persist_windows_supervisor_receipt(file, initial, &bytes, "abnormal")
}

#[cfg(windows)]
fn read_windows_supervisor_receipt(path: &Path) -> Result<Vec<u8>, String> {
    let (mut file, receipt) = windows_bind_path(path, false)?;
    if receipt.size > u64::try_from(NIGHTLY_SUPERVISOR_TERMINAL_LIMIT).unwrap_or(u64::MAX) {
        return Err("Windows supervisor retained receipt exceeds its global byte limit".to_owned());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(receipt.size).unwrap_or(0));
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read Windows supervisor retained receipt: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != receipt.size
        || windows_file_receipt(&file)? != receipt
        || windows_bind_path(path, false)?.1 != receipt
    {
        return Err("Windows supervisor retained receipt changed while reading".to_owned());
    }
    Ok(bytes)
}

#[cfg(windows)]
fn decode_windows_supervisor_abnormal(
    bytes: &[u8],
    request_sha256: Digest,
    nonce: Digest,
) -> Result<String, String> {
    let token = windows_supervisor_os_from_bytes(bytes)?;
    let fields = hell_testkit::decode_windows_argv(&token)
        .map_err(|error| format!("cannot decode Windows supervisor abnormal receipt: {error}"))?;
    let [protocol, request, received_nonce, detail] = fields.as_slice() else {
        return Err("Windows supervisor abnormal receipt width differs".to_owned());
    };
    if protocol != "windows-supervisor-abnormal-v1"
        || request != &std::ffi::OsString::from(request_sha256.hex())
        || received_nonce != &std::ffi::OsString::from(nonce.hex())
    {
        return Err("Windows supervisor abnormal receipt authority differs".to_owned());
    }
    detail
        .to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| "Windows supervisor abnormal detail is not UTF-8".to_owned())
}

#[cfg(windows)]
enum WindowsLateSupervisorEvidence {
    Terminal(Box<ExternalSupervisorTerminal>),
    Abnormal(String),
    Cleanup(String),
}

#[cfg(windows)]
fn read_retained_windows_late_receipt(
    session: &WindowsSupervisorSession,
) -> Result<Vec<u8>, String> {
    let retained = session
        .late_receipt
        .as_ref()
        .ok_or_else(|| "Windows late supervisor receipt is absent".to_owned())?;
    let expected = session
        .late_receipt_receipt
        .ok_or_else(|| "Windows late supervisor receipt identity is absent".to_owned())?;
    let mut file = retained
        .try_clone()
        .map_err(|error| format!("cannot clone Windows late supervisor receipt: {error}"))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("cannot rewind Windows late supervisor receipt: {error}"))?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(NIGHTLY_SUPERVISOR_TERMINAL_LIMIT).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read Windows late supervisor receipt: {error}"))?;
    if bytes.len() > NIGHTLY_SUPERVISOR_TERMINAL_LIMIT
        || windows_file_receipt(retained)?
            != (WindowsFileReceipt {
                size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                ..expected
            })
        || windows_bind_shared_late_receipt(&session.late_receipt_path)?.1
            != windows_file_receipt(retained)?
    {
        return Err("Windows late supervisor receipt changed while reading".to_owned());
    }
    Ok(bytes)
}

#[cfg(windows)]
fn import_windows_late_supervisor_evidence(
    child: &WindowsSupervisorProcess,
    session: &WindowsSupervisorSession,
    request_sha256: Digest,
    nonce: Digest,
) -> Result<Option<WindowsLateSupervisorEvidence>, String> {
    if child.try_wait()?.is_none() {
        return Ok(None);
    }
    let late = read_retained_windows_late_receipt(session)?;
    if !late.is_empty() {
        if let Ok(terminal) = decode_external_supervisor_terminal(&late, request_sha256, nonce) {
            return Ok(Some(WindowsLateSupervisorEvidence::Terminal(Box::new(
                terminal,
            ))));
        }
        return decode_windows_supervisor_abnormal(&late, request_sha256, nonce)
            .map(WindowsLateSupervisorEvidence::Abnormal)
            .map(Some);
    }
    session.revalidate()?;
    let abnormal = read_windows_supervisor_receipt(&session.root_path.join("abnormal.receipt"))?;
    if !abnormal.is_empty() {
        return decode_windows_supervisor_abnormal(&abnormal, request_sha256, nonce)
            .map(WindowsLateSupervisorEvidence::Abnormal)
            .map(Some);
    }
    let terminal = read_windows_supervisor_receipt(&session.root_path.join("terminal.receipt"))?;
    if !terminal.is_empty() {
        return decode_external_supervisor_terminal(&terminal, request_sha256, nonce)
            .map(Box::new)
            .map(WindowsLateSupervisorEvidence::Terminal)
            .map(Some);
    }
    let commit = read_windows_supervisor_receipt(&session.root_path.join("cleanup.commit"))?;
    windows_validate_frame(&commit, 11, request_sha256, nonce)?;
    let cleanup = read_windows_supervisor_receipt(&session.root_path.join("cleanup.receipt"))?;
    if !cleanup.is_empty() {
        let detail =
            windows_validate_frame(&cleanup, 9, request_sha256, nonce).and_then(|payload| {
                String::from_utf8(payload.to_vec())
                    .map_err(|_| "Windows cleanup-only detail is not UTF-8".to_owned())
            })?;
        return Ok(Some(WindowsLateSupervisorEvidence::Cleanup(detail)));
    }
    Err("Windows supervisor exited without a terminal, abnormal, or cleanup receipt".to_owned())
}

#[cfg(windows)]
fn import_windows_terminal_after_transport(
    started: &WindowsExternalStarted,
) -> Result<Option<Vec<u8>>, String> {
    match import_windows_late_supervisor_evidence(
        &started.child,
        &started.session,
        started.request_sha256,
        started.nonce,
    )? {
        None => Ok(None),
        Some(WindowsLateSupervisorEvidence::Terminal(terminal)) => {
            encode_external_supervisor_terminal(started.request_sha256, started.nonce, &terminal)
                .map(Some)
        }
        Some(WindowsLateSupervisorEvidence::Abnormal(detail)) => Err(format!(
            "Windows supervisor published abnormal terminal evidence: {detail}"
        )),
        Some(WindowsLateSupervisorEvidence::Cleanup(detail)) => Err(format!(
            "Windows supervisor exited after authority cleanup without terminal evidence: {detail}"
        )),
    }
}

#[cfg(windows)]
fn close_imported_windows_supervisor_session(
    session: WindowsSupervisorSession,
    request_sha256: Digest,
    nonce: Digest,
    deadline: Instant,
) -> Result<(), String> {
    let commit = read_windows_supervisor_receipt(&session.root_path.join("cleanup.commit"))?;
    if windows_validate_frame(&commit, 11, request_sha256, nonce).is_err() {
        return session.close(true, deadline);
    }
    let late = session.transfer_session_cleanup()?;
    while Instant::now() < deadline {
        match fs::symlink_metadata(&late.session_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return late.close(deadline);
            }
            Err(error) => {
                return Err(format!(
                    "cannot inspect externally cleaned Windows session: {error}"
                ));
            }
            Ok(_) => std::thread::yield_now(),
        }
    }
    Err("Windows external session cleanup exceeded its report deadline".to_owned())
}

#[cfg(windows)]
fn run_windows_authority_cleanup_successor(
    control: &mut impl std::io::Read,
    observations: &mut impl std::io::Write,
) -> Result<(), String> {
    let request = windows_read_inherited_frame(control)?
        .ok_or_else(|| "Windows cleanup successor control closed before request".to_owned())?;
    let token = windows_supervisor_os_from_bytes(&request)?;
    let fields = hell_testkit::decode_windows_argv(&token)
        .map_err(|error| format!("cannot decode Windows cleanup successor request: {error}"))?;
    let [
        manifest_path,
        manifest_sha256,
        commit_path,
        cleanup_path,
        session_path,
        request_sha256,
        nonce,
        remaining,
        session_volume,
        session_index,
        session_size,
        session_attributes,
    ] = fields.as_slice()
    else {
        return Err("Windows cleanup successor request field count differs".to_owned());
    };
    let manifest_path = PathBuf::from(manifest_path);
    let commit_path = PathBuf::from(commit_path);
    let cleanup_path = PathBuf::from(cleanup_path);
    let session_path = PathBuf::from(session_path);
    let session_receipt = windows_parse_receipt(
        &[
            session_volume.clone(),
            session_index.clone(),
            session_size.clone(),
            session_attributes.clone(),
        ],
        "cleanup session",
    )?;
    let manifest_sha256 = Digest::from_hex(
        manifest_sha256
            .to_str()
            .ok_or_else(|| "Windows cleanup manifest digest is not UTF-8".to_owned())?,
    )
    .map_err(|error| format!("Windows cleanup manifest digest is invalid: {error}"))?;
    let request_sha256 = Digest::from_hex(
        request_sha256
            .to_str()
            .ok_or_else(|| "Windows cleanup request digest is not UTF-8".to_owned())?,
    )
    .map_err(|error| format!("Windows cleanup request digest is invalid: {error}"))?;
    let nonce = Digest::from_hex(
        nonce
            .to_str()
            .ok_or_else(|| "Windows cleanup nonce is not UTF-8".to_owned())?,
    )
    .map_err(|error| format!("Windows cleanup nonce is invalid: {error}"))?;
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(windows_parse_u64(
            remaining,
            "cleanup deadline",
        )?))
        .ok_or_else(|| "Windows cleanup successor deadline overflowed".to_owned())?;
    let cleanup_deadline = deadline
        .checked_sub(TERMINAL_PERSISTENCE_RESERVE)
        .ok_or_else(|| "Windows cleanup successor persistence reserve underflowed".to_owned())?;
    let (watchdog_complete, watchdog_receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("hell-windows-authority-cleanup-watchdog".to_owned())
        .spawn(move || {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if matches!(
                watchdog_receiver.recv_timeout(remaining),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                std::process::exit(1);
            }
        })
        .map_err(|error| format!("cannot start Windows cleanup successor watchdog: {error}"))?;
    let (mut manifest, manifest_receipt) = windows_bind_path(&manifest_path, false)?;
    if manifest_receipt.size > 16 * 1024 * 1024 {
        return Err("Windows cleanup successor manifest exceeds its bound".to_owned());
    }
    let mut manifest_bytes =
        Vec::with_capacity(usize::try_from(manifest_receipt.size).unwrap_or(16 * 1024 * 1024));
    manifest
        .read_to_end(&mut manifest_bytes)
        .map_err(|error| format!("cannot read Windows cleanup successor manifest: {error}"))?;
    let authority = import_authenticated_windows_nightly_authority_manifest(
        &manifest_bytes,
        manifest_sha256,
        deadline,
    )?;
    if windows_file_receipt(&manifest)? != manifest_receipt {
        return Err("Windows cleanup successor manifest changed during import".to_owned());
    }
    drop(manifest);
    let mut commit_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(
            windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
        )
        .open(&commit_path)
        .map_err(|error| format!("cannot retain Windows cleanup commit receipt: {error}"))?;
    let initial_commit_receipt = windows_file_receipt(&commit_file)?;
    if initial_commit_receipt.size != 0 {
        return Err("Windows cleanup commit receipt was not empty".to_owned());
    }
    let mut cleanup_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
        .open(&cleanup_path)
        .map_err(|error| format!("cannot retain Windows cleanup successor receipt: {error}"))?;
    let initial_cleanup_receipt = windows_file_receipt(&cleanup_file)?;
    if initial_cleanup_receipt.size != 0 {
        return Err("Windows cleanup successor receipt was not empty".to_owned());
    }
    windows_write_inherited_frame(
        observations,
        &windows_supervisor_frame(1, request_sha256, nonce, &manifest_sha256.0)?,
    )?;
    let commit_receipt = windows_supervisor_frame(11, request_sha256, nonce, &[])?;
    let commit_control = windows_read_inherited_frame(control);
    commit_file
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("cannot rewind Windows cleanup commit receipt: {error}"))?;
    let mut persisted_commit = Vec::new();
    commit_file
        .read_to_end(&mut persisted_commit)
        .map_err(|error| format!("cannot read Windows cleanup commit receipt: {error}"))?;
    let expected_commit_receipt = WindowsFileReceipt {
        size: u64::try_from(commit_receipt.len())
            .map_err(|_| "Windows cleanup commit receipt size overflowed".to_owned())?,
        ..initial_commit_receipt
    };
    let retained_commit_receipt = windows_file_receipt(&commit_file)?;
    drop(commit_file);
    let committed = persisted_commit == commit_receipt
        && retained_commit_receipt == expected_commit_receipt
        && windows_bind_path(&commit_path, false)?.1 == expected_commit_receipt;
    match commit_control {
        Ok(Some(commit)) => {
            windows_validate_frame(&commit, 10, request_sha256, nonce)?;
            if !committed {
                return Err("Windows cleanup successor command lacks its durable commit".to_owned());
            }
        }
        Ok(None) if !committed => {
            let _ = watchdog_complete.send(());
            return Ok(());
        }
        Ok(None) => {}
        Err(error) if committed => {
            let _ = error;
        }
        Err(error) => return Err(error),
    }
    let _ = windows_write_inherited_frame(observations, &commit_receipt);
    let command = windows_read_inherited_frame(control);
    let (command_error, authority_cleanup_deadline) = match command {
        Ok(Some(command)) => match windows_validate_frame(&command, 8, request_sha256, nonce) {
            Ok(payload) if payload.len() == size_of::<u64>() => {
                let millis =
                    u64::from_be_bytes(payload.try_into().map_err(|_| {
                        "Windows authority cleanup deadline width differs".to_owned()
                    })?);
                (
                    None,
                    Instant::now()
                        .checked_add(Duration::from_millis(millis))
                        .unwrap_or(cleanup_deadline)
                        .min(cleanup_deadline),
                )
            }
            Ok(_) => (
                Some("Windows authority cleanup deadline width differs".to_owned()),
                cleanup_deadline,
            ),
            Err(error) => (Some(error), cleanup_deadline),
        },
        Ok(None) => (None, cleanup_deadline),
        Err(error) => (Some(error), cleanup_deadline),
    };
    let cleanup = authority.close_until(authority_cleanup_deadline);
    let detail = match (command_error, cleanup) {
        (None, Ok(())) => "completed".to_owned(),
        (Some(primary), Ok(())) => format!("control-failed:{primary}"),
        (None, Err(cleanup)) => format!("cleanup-failed:{cleanup}"),
        (Some(primary), Err(cleanup)) => {
            format!("control-failed:{primary};cleanup-failed:{cleanup}")
        }
    };
    let cleanup_receipt = windows_supervisor_frame(9, request_sha256, nonce, detail.as_bytes())?;
    persist_windows_supervisor_receipt(
        &mut cleanup_file,
        initial_cleanup_receipt,
        &cleanup_receipt,
        "authority cleanup",
    )?;
    let _ = windows_write_inherited_frame(observations, &cleanup_receipt);
    drop(cleanup_file);
    let session_command = windows_read_inherited_frame(control);
    let session_command_error = match session_command {
        Ok(Some(command)) => windows_validate_frame(&command, 12, request_sha256, nonce)
            .map(|_| ())
            .err(),
        Ok(None) => None,
        Err(error) => Some(error),
    };
    let session_cleanup =
        cleanup_bound_windows_supervisor_session(&session_path, session_receipt, cleanup_deadline);
    let session_detail = match (session_command_error, session_cleanup) {
        (None, Ok(())) => "completed".to_owned(),
        (Some(primary), Ok(())) => format!("control-failed:{primary}"),
        (None, Err(cleanup)) => format!("session-cleanup-failed:{cleanup}"),
        (Some(primary), Err(cleanup)) => {
            format!("control-failed:{primary};session-cleanup-failed:{cleanup}")
        }
    };
    let session_receipt =
        windows_supervisor_frame(13, request_sha256, nonce, session_detail.as_bytes())?;
    let _ = windows_write_inherited_frame(observations, &session_receipt);
    let _ = watchdog_complete.send(());
    if detail == "completed" && session_detail == "completed" {
        Ok(())
    } else {
        Err(format!("{detail};session:{session_detail}"))
    }
}

#[cfg(windows)]
pub(crate) fn run_external_nightly_supervisor(
    arguments: &[std::ffi::OsString],
) -> Result<(), String> {
    let [protocol_token] = arguments else {
        return Err("Windows nightly supervisor requires one structured request token".to_owned());
    };
    let protocol = hell_testkit::decode_windows_argv(protocol_token)
        .map_err(|error| format!("cannot decode Windows supervisor protocol selector: {error}"))?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut control = stdin.lock();
    let mut observations = stdout.lock();
    if protocol.as_slice() == [std::ffi::OsString::from("windows-cleanup-exit-fixture-v1")] {
        return run_windows_cleanup_exit_fixture(&mut control, &mut observations);
    }
    if protocol.as_slice() == [std::ffi::OsString::from("windows-authority-cleanup-v1")] {
        return run_windows_authority_cleanup_successor(&mut control, &mut observations);
    }
    if protocol.as_slice() != [std::ffi::OsString::from("windows-inherited-pipe-v1")] {
        return Err("Windows nightly supervisor protocol selector differs".to_owned());
    }
    let request_bytes = windows_read_inherited_frame(&mut control)?
        .ok_or_else(|| "Windows supervisor request pipe closed before its request".to_owned())?;
    let token = windows_supervisor_os_from_bytes(&request_bytes)?;
    let request_sha256 = windows_supervisor_os_digest(&token);
    let fields = hell_testkit::decode_windows_argv(&token)
        .map_err(|error| format!("cannot decode Windows supervisor request: {error}"))?;
    let [
        plan,
        root,
        writable_target,
        session_path,
        request_path,
        late_receipt_path,
        nonce,
        execution,
        cleanup,
        report,
        lifetime,
        fixture,
        fixture_address,
        fixture_port,
        exit_fixture,
        exit_fixture_address,
        exit_fixture_port,
        root_volume,
        root_index,
        root_size,
        root_attributes,
        target_volume,
        target_index,
        target_size,
        target_attributes,
        session_volume,
        session_index,
        session_size,
        session_attributes,
        request_volume,
        request_index,
        request_size,
        request_attributes,
        late_volume,
        late_index,
        late_size,
        late_attributes,
        manifest_volume,
        manifest_index,
        manifest_size,
        manifest_attributes,
        manifest_sha256,
    ] = fields.as_slice()
    else {
        return Err("Windows supervisor request field count differs".to_owned());
    };
    let plan = ExternalSupervisorPlan::from_code(
        u8::try_from(windows_parse_u64(plan, "plan")?)
            .map_err(|_| "Windows supervisor plan is too large".to_owned())?,
    )?;
    let root = PathBuf::from(root);
    let writable_target = PathBuf::from(writable_target);
    let session_path = PathBuf::from(session_path);
    let request_path = PathBuf::from(request_path);
    let late_receipt_path = PathBuf::from(late_receipt_path);
    let nonce = Digest::from_hex(
        nonce
            .to_str()
            .ok_or_else(|| "Windows supervisor nonce is not UTF-8".to_owned())?,
    )
    .map_err(|error| format!("Windows supervisor nonce is invalid: {error}"))?;
    let fixture = match windows_parse_u64(fixture, "fixture")? {
        0 => None,
        1 => Some(parse_loopback_address(fixture_address, fixture_port)?),
        _ => return Err("Windows supervisor fixture flag is invalid".to_owned()),
    };
    let exit_fixture = match windows_parse_u64(exit_fixture, "exit fixture")? {
        0 => None,
        1 => Some(parse_loopback_address(
            exit_fixture_address,
            exit_fixture_port,
        )?),
        _ => return Err("Windows supervisor exit fixture flag is invalid".to_owned()),
    };
    let received = Instant::now();
    let deadline_from_remaining = |value: &std::ffi::OsStr, field: &str| {
        let remaining = Duration::from_millis(windows_parse_u64(value, field)?);
        received
            .checked_add(remaining)
            .ok_or_else(|| format!("Windows supervisor {field} deadline overflowed"))
    };
    let envelope = SupervisionEnvelope {
        execution: deadline_from_remaining(execution, "execution")?,
        child_completion_deadline: deadline_from_remaining(cleanup, "cleanup")?,
        report_completion_deadline: deadline_from_remaining(report, "report")?,
    };
    let lifetime_deadline = deadline_from_remaining(lifetime, "lifetime")?;
    let mut fixture_exit_guard = exit_fixture
        .map(|address| {
            WindowsSupervisorFixtureExitGuard::connect(
                address,
                request_sha256,
                nonce,
                lifetime_deadline,
            )
        })
        .transpose()?;
    if envelope.execution >= envelope.child_completion_deadline
        || envelope.child_completion_deadline >= envelope.report_completion_deadline
        || envelope.report_completion_deadline > lifetime_deadline
    {
        return Err("Windows supervisor deadline order differs".to_owned());
    }
    let received_total = envelope
        .report_completion_deadline
        .saturating_duration_since(received);
    let received_lifetime = lifetime_deadline.saturating_duration_since(received);
    let allowed_lifetime = if let Some(followup) = plan.combined_followup() {
        plan.total()
            .checked_add(followup.total())
            .ok_or_else(|| "Windows supervisor lifetime bound overflowed".to_owned())?
    } else {
        plan.total()
    };
    let received_cleanup_reserve = envelope
        .report_completion_deadline
        .saturating_duration_since(envelope.execution);
    let received_report_reserve = envelope
        .report_completion_deadline
        .saturating_duration_since(envelope.child_completion_deadline);
    if received_total > plan.total()
        || received_lifetime > allowed_lifetime
        || received_cleanup_reserve < NIGHTLY_COMMAND_CLEANUP_RESERVE
        || received_report_reserve < NIGHTLY_REPORT_RESERVE
    {
        return Err("Windows supervisor relative envelope exceeds its fixed plan".to_owned());
    }
    let supervisor_hard_exit_reserve = NIGHTLY_SUPERVISOR_START_TIMEOUT
        .checked_mul(2)
        .ok_or_else(|| "Windows supervisor hard-exit reserve overflowed".to_owned())?;
    let supervisor_hard_exit_deadline = lifetime_deadline
        .checked_sub(supervisor_hard_exit_reserve)
        .ok_or_else(|| "Windows supervisor hard-exit reserve underflowed".to_owned())?;
    let (watchdog_complete, watchdog_receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("hell-windows-supervisor-deadline-watchdog".to_owned())
        .spawn(move || {
            let remaining = supervisor_hard_exit_deadline.saturating_duration_since(Instant::now());
            if matches!(
                watchdog_receiver.recv_timeout(remaining),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                std::process::exit(1);
            }
        })
        .map_err(|error| format!("cannot start Windows supervisor deadline watchdog: {error}"))?;
    let root_receipt = windows_parse_receipt(
        &[
            root_volume.clone(),
            root_index.clone(),
            root_size.clone(),
            root_attributes.clone(),
        ],
        "workspace",
    )?;
    let writable_target_receipt = windows_parse_receipt(
        &[
            target_volume.clone(),
            target_index.clone(),
            target_size.clone(),
            target_attributes.clone(),
        ],
        "writable target",
    )?;
    let session_receipt = windows_parse_receipt(
        &[
            session_volume.clone(),
            session_index.clone(),
            session_size.clone(),
            session_attributes.clone(),
        ],
        "session",
    )?;
    let request_receipt = windows_parse_receipt(
        &[
            request_volume.clone(),
            request_index.clone(),
            request_size.clone(),
            request_attributes.clone(),
        ],
        "ownership",
    )?;
    let late_receipt_receipt = windows_parse_receipt(
        &[
            late_volume.clone(),
            late_index.clone(),
            late_size.clone(),
            late_attributes.clone(),
        ],
        "late receipt",
    )?;
    let manifest_receipt = windows_parse_receipt(
        &[
            manifest_volume.clone(),
            manifest_index.clone(),
            manifest_size.clone(),
            manifest_attributes.clone(),
        ],
        "authority manifest",
    )?;
    let manifest_sha256 = Digest::from_hex(
        manifest_sha256
            .to_str()
            .ok_or_else(|| "Windows authority manifest digest is not UTF-8".to_owned())?,
    )
    .map_err(|error| format!("Windows authority manifest digest is invalid: {error}"))?;
    let (root_guard, actual_root) = windows_bind_path(&root, true)?;
    let (writable_target_guard, actual_writable_target) =
        windows_bind_path(&writable_target, true)?;
    let (session_guard, actual_session) = windows_bind_path(&session_path, true)?;
    let (request_guard, actual_request) = windows_bind_path(&request_path, false)?;
    let mut late_receipt_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(
            windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
        )
        .open(&late_receipt_path)
        .map_err(|error| format!("cannot retain Windows late supervisor receipt: {error}"))?;
    let request_digest_path = session_path.join("request.digest");
    let (mut request_digest_guard, request_digest_receipt) =
        windows_bind_path(&request_digest_path, false)?;
    let mut request_digest_bytes = Vec::new();
    request_digest_guard
        .read_to_end(&mut request_digest_bytes)
        .map_err(|error| format!("cannot read Windows request digest receipt: {error}"))?;
    let authority_manifest_path = session_path.join("authority.manifest");
    let (mut authority_manifest_guard, actual_manifest_receipt) =
        windows_bind_path(&authority_manifest_path, false)?;
    let mut authority_manifest_bytes = Vec::new();
    authority_manifest_guard
        .read_to_end(&mut authority_manifest_bytes)
        .map_err(|error| format!("cannot read Windows authority manifest: {error}"))?;
    if actual_root != root_receipt
        || actual_writable_target != writable_target_receipt
        || actual_session != session_receipt
        || actual_request != request_receipt
        || windows_file_receipt(&late_receipt_file)? != late_receipt_receipt
        || request_digest_bytes != request_sha256.0
        || actual_manifest_receipt != manifest_receipt
        || sha256_bytes(&authority_manifest_bytes) != manifest_sha256
        || windows_file_receipt(&request_digest_guard)? != request_digest_receipt
    {
        return Err("Windows supervisor filesystem receipt differs".to_owned());
    }
    let terminal_path = session_path.join("terminal.receipt");
    let mut terminal_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
        .open(&terminal_path)
        .map_err(|error| format!("cannot create Windows supervisor terminal receipt: {error}"))?;
    let initial_terminal_receipt = windows_file_receipt(&terminal_file)?;
    let workspace_path = session_path.join("workspace.receipt");
    let mut workspace_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
        .open(&workspace_path)
        .map_err(|error| format!("cannot create Windows workspace terminal receipt: {error}"))?;
    let initial_workspace_receipt = windows_file_receipt(&workspace_file)?;
    let started_path = session_path.join("started.receipt");
    let mut started_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
        .open(&started_path)
        .map_err(|error| format!("cannot create Windows supervisor start receipt: {error}"))?;
    let initial_started_receipt = windows_file_receipt(&started_file)?;
    let abnormal_path = session_path.join("abnormal.receipt");
    let mut abnormal_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
        .open(&abnormal_path)
        .map_err(|error| format!("cannot create Windows supervisor abnormal receipt: {error}"))?;
    let initial_abnormal_receipt = windows_file_receipt(&abnormal_file)?;
    let cleanup_path = session_path.join("cleanup.receipt");
    let cleanup_commit_path = session_path.join("cleanup.commit");
    let mut cleanup_commit_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(
            windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ
                | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
        )
        .open(&cleanup_commit_path)
        .map_err(|error| format!("cannot create Windows cleanup commit receipt: {error}"))?;
    let initial_cleanup_commit_receipt = windows_file_receipt(&cleanup_commit_file)?;
    if initial_cleanup_commit_receipt.size != 0 {
        return Err("Windows cleanup commit receipt was not empty at creation".to_owned());
    }
    let cleanup_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
        .open(&cleanup_path)
        .map_err(|error| format!("cannot create Windows authority cleanup receipt: {error}"))?;
    if windows_file_receipt(&cleanup_file)?.size != 0 {
        return Err("Windows authority cleanup receipt was not empty at creation".to_owned());
    }
    drop(cleanup_file);
    let supervisor_executable = fs::canonicalize(
        std::env::current_exe()
            .map_err(|error| format!("cannot locate Windows cleanup successor: {error}"))?,
    )
    .map_err(|error| format!("cannot canonicalize Windows cleanup successor: {error}"))?;
    let mut cleanup_successor =
        start_windows_authority_cleanup_successor(WindowsAuthorityCleanupStart {
            executable: &supervisor_executable,
            manifest_path: &authority_manifest_path,
            manifest_sha256,
            commit_path: &cleanup_commit_path,
            cleanup_path: &cleanup_path,
            session_path: &session_path,
            session_receipt,
            request_sha256,
            nonce,
            deadline: lifetime_deadline,
        })?;
    protect_windows_supervisor_session(&session_path, envelope.execution)?;
    protect_windows_supervisor_receipt(&late_receipt_path, envelope.execution)?;
    if windows_file_receipt(&root_guard)? != root_receipt
        || windows_file_receipt(&writable_target_guard)? != writable_target_receipt
        || windows_file_receipt(&session_guard)? != session_receipt
        || windows_file_receipt(&request_guard)? != request_receipt
        || windows_file_receipt(&request_digest_guard)? != request_digest_receipt
        || windows_file_receipt(&terminal_file)? != initial_terminal_receipt
        || windows_file_receipt(&workspace_file)? != initial_workspace_receipt
        || windows_file_receipt(&started_file)? != initial_started_receipt
        || windows_file_receipt(&abnormal_file)? != initial_abnormal_receipt
        || windows_file_receipt(&late_receipt_file)? != late_receipt_receipt
    {
        return Err("Windows supervisor receipt changed during DACL confinement".to_owned());
    }
    windows_write_inherited_frame(
        &mut observations,
        &windows_supervisor_frame(1, request_sha256, nonce, &[])?,
    )?;
    drop(observations);
    let imported_authority =
        import_windows_nightly_authority_manifest(&authority_manifest_bytes, envelope.execution)?;
    let probe_executable = fs::canonicalize(
        std::env::current_exe()
            .map_err(|error| format!("cannot locate Windows session probe: {error}"))?,
    )
    .map_err(|error| format!("cannot canonicalize Windows session probe: {error}"))?;
    let probe = CommandSpec::new(
        probe_executable,
        envelope
            .execution_deadline
            .saturating_duration_since(Instant::now()),
    )
    .arguments([
        std::ffi::OsString::from("__nightly-windows-session-access-probe"),
        session_path.as_os_str().to_owned(),
        late_receipt_path.as_os_str().to_owned(),
        writable_target.as_os_str().to_owned(),
        imported_authority.root.as_os_str().to_owned(),
    ])
    .current_directory(&root);
    let probe = windows_write_restricted_supervisor_command(
        probe,
        &writable_target,
        None,
        envelope.execution,
    )?;
    let (probe_progress, _probe_progress_receiver) = SupervisedProgressObserver::bounded(8);
    let probe_result = probe.run_until(
        envelope.execution,
        envelope.child_completion_deadline,
        probe_progress,
    );
    match probe_result {
        Ok(result) if result.status.success() && !result.timed_out => {}
        Ok(result) => {
            return Err(format!(
                "Windows supervisor restricted-access probe failed: status={}, timedOut={}, stderr={}",
                result.status,
                result.timed_out,
                String::from_utf8_lossy(&result.stderr)
            ));
        }
        Err(error) => {
            return Err(format!(
                "cannot execute Windows supervisor restricted-access probe: {error}"
            ));
        }
    }
    let mut observations = stdout.lock();
    windows_write_inherited_frame(
        &mut observations,
        &windows_supervisor_frame(7, request_sha256, nonce, &manifest_sha256.0)?,
    )?;
    drop(observations);
    let commit_result = windows_read_inherited_frame(&mut control)
        .and_then(|commit| {
            commit.ok_or_else(|| {
                "Windows supervisor control pipe closed before cleanup commit".to_owned()
            })
        })
        .and_then(|commit| windows_validate_frame(&commit, 10, request_sha256, nonce).map(|_| ()));
    if let Err(primary) = commit_result {
        drop(cleanup_successor);
        let cleanup_deadline = envelope
            .child_completion_deadline
            .checked_sub(TERMINAL_PERSISTENCE_RESERVE)
            .unwrap_or(envelope.execution);
        let cleanup = imported_authority.close_until(cleanup_deadline);
        let detail = match cleanup {
            Ok(()) => format!("precommit-control-failed:{primary}"),
            Err(cleanup) => {
                format!("precommit-control-failed:{primary};cleanup-failed:{cleanup}")
            }
        };
        let mut cleanup_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
            .open(&cleanup_path)
            .map_err(|error| format!("cannot retain Windows precommit cleanup receipt: {error}"))?;
        let cleanup_initial = windows_file_receipt(&cleanup_file)?;
        if cleanup_initial.size != 0 {
            return Err(format!(
                "{detail}; additionally, Windows precommit cleanup receipt was not empty"
            ));
        }
        let cleanup_receipt =
            windows_supervisor_frame(9, request_sha256, nonce, detail.as_bytes())?;
        persist_windows_supervisor_receipt(
            &mut cleanup_file,
            cleanup_initial,
            &cleanup_receipt,
            "precommit authority cleanup",
        )?;
        let late = persist_windows_supervisor_abnormal(
            &mut late_receipt_file,
            late_receipt_receipt,
            request_sha256,
            nonce,
            &detail,
        );
        drop(cleanup_file);
        drop(cleanup_commit_file);
        drop(request_guard);
        drop(request_digest_guard);
        drop(authority_manifest_guard);
        drop(terminal_file);
        drop(workspace_file);
        drop(started_file);
        drop(abnormal_file);
        drop(late_receipt_file);
        drop(session_guard);
        let session_cleanup = cleanup_bound_windows_supervisor_session(
            &session_path,
            session_receipt,
            cleanup_deadline,
        );
        let _ = watchdog_complete.send(());
        return Err(match (late, session_cleanup) {
            (Ok(()), Ok(())) => detail,
            (Err(late), Ok(())) => {
                format!("{detail}; additionally, late receipt persistence failed: {late}")
            }
            (Ok(()), Err(session)) => {
                format!("{detail}; additionally, session cleanup failed: {session}")
            }
            (Err(late), Err(session)) => format!(
                "{detail}; additionally, late receipt persistence failed: {late}; session cleanup failed: {session}"
            ),
        });
    }
    let successor_commit = windows_supervisor_frame(10, request_sha256, nonce, &[])?;
    let durable_commit = windows_supervisor_frame(11, request_sha256, nonce, &[])?;
    persist_windows_supervisor_receipt(
        &mut cleanup_commit_file,
        initial_cleanup_commit_receipt,
        &durable_commit,
        "authority cleanup commit",
    )?;
    drop(cleanup_commit_file);
    if let Err(primary) = cleanup_successor.child.transfer() {
        drop(cleanup_successor);
        let cleanup = imported_authority.close_until(
            envelope
                .report_completion_deadline
                .checked_sub(TERMINAL_PERSISTENCE_RESERVE)
                .unwrap_or(envelope.child_completion_deadline),
        );
        return Err(match cleanup {
            Ok(()) => primary,
            Err(cleanup) => format!(
                "{primary}; additionally, imported Windows authority cleanup failed: {cleanup}"
            ),
        });
    }
    let successor_commit_result = (|| -> Result<(), String> {
        windows_write_inherited_frame(&mut cleanup_successor.control, &successor_commit)?;
        let successor_commit_receipt = cleanup_successor
            .observations
            .recv_timeout(
                envelope
                    .execution_deadline
                    .saturating_duration_since(Instant::now()),
            )
            .map_err(|error| format!("cannot receive Windows cleanup commit receipt: {error}"))??;
        windows_validate_frame(&successor_commit_receipt, 11, request_sha256, nonce)?;
        Ok(())
    })();
    if let Err(primary) = successor_commit_result {
        drop(cleanup_successor);
        return Err(format!(
            "{primary}; committed cleanup successor retains the imported Windows authority"
        ));
    }
    let mut observations = stdout.lock();
    windows_write_inherited_frame(
        &mut observations,
        &windows_supervisor_frame(11, request_sha256, nonce, &[])?,
    )?;
    drop(observations);
    let go_result = windows_read_inherited_frame(&mut control)
        .and_then(|go| {
            go.ok_or_else(|| "Windows supervisor control pipe closed before Go".to_owned())
        })
        .and_then(|go| windows_validate_frame(&go, 2, request_sha256, nonce).map(|_| ()));
    if let Err(primary) = go_result {
        let detail = format!("committed-before-go-control-failed:{primary}");
        let abnormal = persist_windows_supervisor_abnormal(
            &mut abnormal_file,
            initial_abnormal_receipt,
            request_sha256,
            nonce,
            &detail,
        );
        let late = persist_windows_supervisor_abnormal(
            &mut late_receipt_file,
            late_receipt_receipt,
            request_sha256,
            nonce,
            &detail,
        );
        let _ = watchdog_complete.send(());
        return Err(match (abnormal, late) {
            (Ok(()), Ok(())) => detail,
            (Err(error), Ok(())) | (Ok(()), Err(error)) => {
                format!("{detail}; additionally, abnormal receipt persistence failed: {error}")
            }
            (Err(abnormal), Err(late)) => format!(
                "{detail}; additionally, abnormal receipt persistence failed: {abnormal}; late receipt persistence failed: {late}"
            ),
        });
    }
    let observation_capacity = usize::try_from(NIGHTLY_SUPERVISOR_PROGRESS_FRAME_CAPACITY)
        .map_err(|_| "Windows supervisor progress capacity does not fit usize".to_owned())?
        .checked_add(2)
        .ok_or_else(|| "Windows supervisor observation capacity overflowed".to_owned())?;
    let (observation_sender, observation_receiver) =
        mpsc::sync_channel::<Vec<u8>>(observation_capacity);
    let published_progress = AtomicU64::new(0);
    if fixture.is_some() {
        published_progress.store(
            NIGHTLY_SUPERVISOR_PROGRESS_FRAME_CAPACITY,
            Ordering::Relaxed,
        );
    }
    let observation_relay = std::thread::Builder::new()
        .name("hell-windows-supervisor-progress-relay".to_owned())
        .spawn(move || {
            let mut observations = stdout.lock();
            while let Ok(frame) = observation_receiver.recv() {
                if windows_write_inherited_frame(&mut observations, &frame).is_err() {
                    return;
                }
            }
        });
    let observation_relay_error = observation_relay
        .as_ref()
        .err()
        .map(|error| format!("cannot start Windows supervisor progress relay: {error}"));
    let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<ExternalSupervisorTerminal, String> {
            if let Some(error) = &observation_relay_error {
                return Err(error.clone());
            }
            if windows_file_receipt(&root_guard)? != root_receipt
                || windows_file_receipt(&writable_target_guard)? != writable_target_receipt
                || windows_file_receipt(&session_guard)? != session_receipt
                || windows_file_receipt(&request_guard)? != request_receipt
                || windows_file_receipt(&request_digest_guard)? != request_digest_receipt
            {
                return Err(
                    "Windows supervisor retained authority changed before payload launch"
                        .to_owned(),
                );
            }
            let started_token = hell_testkit::encode_windows_argv(&[
                std::ffi::OsString::from(request_sha256.hex()),
                std::ffi::OsString::from(nonce.hex()),
                std::ffi::OsString::from(std::process::id().to_string()),
                std::ffi::OsString::from(
                    u64::try_from(
                        envelope
                            .report_completion_deadline
                            .saturating_duration_since(received)
                            .as_millis(),
                    )
                    .unwrap_or(u64::MAX)
                    .to_string(),
                ),
            ])
            .map_err(|error| format!("cannot encode Windows supervisor start receipt: {error}"))?;
            let started_bytes = windows_supervisor_os_bytes(&started_token);
            persist_windows_supervisor_receipt(
                &mut started_file,
                initial_started_receipt,
                &started_bytes,
                "start",
            )?;
            drop(started_file);
            observation_sender
                .send(windows_supervisor_frame(
                    3,
                    request_sha256,
                    nonce,
                    &sha256_bytes(&started_bytes).0,
                )?)
                .map_err(|_| {
                    "Windows supervisor progress relay disconnected before Started".to_owned()
                })?;
            let timeout = envelope
                .execution_deadline
                .saturating_duration_since(Instant::now());
            if timeout.is_zero() {
                return Err(
                    "Windows supervisor execution deadline expired before payload launch"
                        .to_owned(),
                );
            }
            let spec = if let Some(gate) = fixture {
                let executable = fs::canonicalize(std::env::current_exe().map_err(|error| {
                    format!("cannot locate Windows supervisor fixture child: {error}")
                })?)
                .map_err(|error| {
                    format!("cannot canonicalize Windows supervisor fixture child: {error}")
                })?;
                CommandSpec::new(executable, timeout)
                    .arguments([
                        std::ffi::OsString::from("__nightly-supervisor-owned-child"),
                        std::ffi::OsString::from(gate.ip().to_string()),
                        std::ffi::OsString::from(gate.port().to_string()),
                        std::ffi::OsString::from(request_sha256.hex()),
                        std::ffi::OsString::from(nonce.hex()),
                        session_path.as_os_str().to_owned(),
                        writable_target.as_os_str().to_owned(),
                        std::ffi::OsString::from(std::process::id().to_string()),
                    ])
                    .current_directory(&root)
            } else {
                plan.command(&root, timeout)
            };
            let spec = windows_write_restricted_supervisor_command(
                spec,
                &writable_target,
                (!imported_authority.root.as_os_str().is_empty()).then_some(&imported_authority),
                envelope.execution,
            )?;
            let result = execute_external_supervisor_command(
                spec,
                plan,
                if fixture.is_some() {
                    "external-supervisor-owned-child"
                } else {
                    plan.seed().1
                },
                envelope,
                |progress| {
                    if published_progress.load(Ordering::Relaxed)
                        >= NIGHTLY_SUPERVISOR_PROGRESS_FRAME_CAPACITY
                    {
                        return false;
                    }
                    encode_external_supervisor_progress(progress)
                        .and_then(|payload| {
                            windows_supervisor_frame(6, request_sha256, nonce, &payload)
                        })
                        .is_ok_and(|frame| {
                            if observation_sender.try_send(frame).is_ok() {
                                published_progress.fetch_add(1, Ordering::Relaxed);
                                true
                            } else {
                                false
                            }
                        })
                },
            );
            let mut terminal = match result {
                Ok((result, mut progress, loss)) => {
                    progress.record_terminal(
                        plan.name(),
                        if result.is_ok() {
                            PortabilityCaseState::Completed
                        } else {
                            PortabilityCaseState::Failed
                        },
                    );
                    external_supervisor_terminal_from_result(
                        result,
                        &progress,
                        loss,
                        envelope.report_completion_deadline,
                    )
                }
                Err(error) => external_supervisor_failure_terminal(plan, error, false),
            };
            let combined = plan.combined_followup().is_some()
                && fixture.is_none()
                && !imported_authority.root.as_os_str().is_empty();
            if combined {
                let workspace_bytes =
                    encode_external_supervisor_terminal(request_sha256, nonce, &terminal)?;
                persist_windows_supervisor_receipt(
                    &mut workspace_file,
                    initial_workspace_receipt,
                    &workspace_bytes,
                    "workspace terminal",
                )?;
                drop(workspace_file);
            }
            if terminal.execution.success && combined {
                let core_plan = plan
                    .combined_followup()
                    .ok_or_else(|| "Windows combined follow-up plan is absent".to_owned())?;
                let core_started = Instant::now();
                let core_phase_deadline = core_started
                    .checked_add(core_plan.total())
                    .unwrap_or(lifetime_deadline)
                    .min(lifetime_deadline);
                let core_command_deadline = core_phase_deadline
                    .min(supervisor_hard_exit_deadline)
                    .checked_sub(TERMINAL_PERSISTENCE_RESERVE)
                    .ok_or_else(|| {
                        "Windows supervisor core terminal reserve underflowed".to_owned()
                    })?;
                let core_envelope = SupervisionEnvelope::within(
                    core_started,
                    core_plan.total(),
                    NIGHTLY_COMMAND_CLEANUP_RESERVE,
                    NIGHTLY_REPORT_RESERVE,
                    core_command_deadline,
                )?;
                let core_timeout = core_envelope
                    .execution_deadline
                    .saturating_duration_since(Instant::now());
                if core_timeout.is_zero() {
                    return Err(
                        "Windows supervisor core execution deadline expired before launch"
                            .to_owned(),
                    );
                }
                let core_spec = windows_write_restricted_supervisor_command(
                    core_plan.command(&root, core_timeout),
                    &writable_target,
                    Some(&imported_authority),
                    core_envelope.execution,
                )?;
                let core_result = execute_external_supervisor_command(
                    core_spec,
                    core_plan,
                    core_plan.seed().1,
                    core_envelope,
                    |progress| {
                        if published_progress.load(Ordering::Relaxed)
                            >= NIGHTLY_SUPERVISOR_PROGRESS_FRAME_CAPACITY
                        {
                            return false;
                        }
                        encode_external_supervisor_progress(progress)
                            .and_then(|payload| {
                                windows_supervisor_frame(6, request_sha256, nonce, &payload)
                            })
                            .is_ok_and(|frame| {
                                if observation_sender.try_send(frame).is_ok() {
                                    published_progress.fetch_add(1, Ordering::Relaxed);
                                    true
                                } else {
                                    false
                                }
                            })
                    },
                );
                terminal = match core_result {
                    Ok((result, mut progress, loss)) => {
                        progress.record_terminal(
                            core_plan.name(),
                            if result.is_ok() {
                                PortabilityCaseState::Completed
                            } else {
                                PortabilityCaseState::Failed
                            },
                        );
                        external_supervisor_terminal_from_result(
                            result,
                            &progress,
                            loss,
                            core_envelope.report_completion_deadline,
                        )
                    }
                    Err(error) => external_supervisor_failure_terminal(core_plan, error, false),
                };
            }
            Ok(terminal)
        },
    ));
    let mut terminal = match payload {
        Ok(Ok(terminal)) => terminal,
        Ok(Err(error)) => external_supervisor_failure_terminal(plan, error, false),
        Err(_) => external_supervisor_failure_terminal(
            plan,
            "Windows external supervisor panicked after accepting ownership",
            false,
        ),
    };
    let authority_cleanup_deadline = if plan
        .combined_followup()
        .is_some_and(|followup| terminal.attribution.target.as_deref() == Some(followup.seed().0))
    {
        supervisor_hard_exit_deadline
    } else {
        envelope
            .report_completion_deadline
            .checked_sub(TERMINAL_PERSISTENCE_RESERVE)
            .unwrap_or(envelope.child_completion_deadline)
    };
    drop(imported_authority);
    let cleanup_successor = match finish_windows_authority_cleanup_successor(
        cleanup_successor,
        authority_cleanup_deadline,
    ) {
        Ok((successor, failure)) => {
            if let Some(error) = failure {
                terminal.execution.success = false;
                if terminal.failed_case.is_none() && terminal.failed_case_unavailable.is_none() {
                    terminal.failed_case_unavailable =
                        Some("process-cleanup-failure-without-test-failure".to_owned());
                }
                terminal.cleanup.terminal = false;
                terminal.cleanup_state = "failed".to_owned();
                terminal.cleanup_failures.push(format!(
                    "windows-toolchain-authority:failed: {}",
                    bounded_external_supervisor_detail(&error)
                ));
                terminal.cleanup_error = Some(bounded_external_supervisor_detail(&error));
                terminal.detail = bounded_external_supervisor_detail(&format!(
                    "{}; additionally, Windows authority cleanup failed: {error}",
                    terminal.detail
                ));
            }
            Some(successor)
        }
        Err(error) => {
            terminal.execution.success = false;
            if terminal.failed_case.is_none() && terminal.failed_case_unavailable.is_none() {
                terminal.failed_case_unavailable =
                    Some("process-cleanup-failure-without-test-failure".to_owned());
            }
            terminal.cleanup.terminal = false;
            terminal.cleanup_state = "failed".to_owned();
            terminal.cleanup_failures.push(format!(
                "windows-toolchain-authority:failed: {}",
                bounded_external_supervisor_detail(&error)
            ));
            terminal.cleanup_error = Some(bounded_external_supervisor_detail(&error));
            terminal.detail = bounded_external_supervisor_detail(&format!(
                "{}; additionally, Windows authority cleanup failed: {error}",
                terminal.detail
            ));
            None
        }
    };
    let publication = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        encode_external_supervisor_terminal(request_sha256, nonce, &terminal).and_then(
            |terminal_bytes| {
                let frame = windows_supervisor_frame(4, request_sha256, nonce, &terminal_bytes)?;
                persist_windows_supervisor_receipt(
                    &mut terminal_file,
                    initial_terminal_receipt,
                    &terminal_bytes,
                    "terminal",
                )?;
                persist_windows_supervisor_receipt(
                    &mut late_receipt_file,
                    late_receipt_receipt,
                    &terminal_bytes,
                    "late terminal",
                )?;
                let _ = observation_sender.try_send(frame);
                Ok(())
            },
        )
    }))
    .unwrap_or_else(|_| {
        Err("Windows supervisor terminal publication panicked after accepting ownership".to_owned())
    });
    if let Err(primary) = publication {
        let abnormal = persist_windows_supervisor_abnormal(
            &mut abnormal_file,
            initial_abnormal_receipt,
            request_sha256,
            nonce,
            &primary,
        );
        let late_abnormal = persist_windows_supervisor_abnormal(
            &mut late_receipt_file,
            late_receipt_receipt,
            request_sha256,
            nonce,
            &primary,
        );
        let _ = watchdog_complete.send(());
        return Err(match (abnormal, late_abnormal) {
            (Ok(()), Ok(())) => primary,
            (Err(abnormal), Ok(())) | (Ok(()), Err(abnormal)) => {
                format!("{primary}; additionally, abnormal receipt persistence failed: {abnormal}")
            }
            (Err(abnormal), Err(late)) => format!(
                "{primary}; additionally, abnormal receipt persistence failed: {abnormal}; late receipt persistence failed: {late}"
            ),
        });
    }
    let receipt_acknowledgement = windows_read_inherited_frame(&mut control).and_then(|frame| {
        frame.map_or(Ok(()), |frame| {
            windows_validate_frame(&frame, 5, request_sha256, nonce).map(|_| ())
        })
    });
    drop(request_guard);
    drop(request_digest_guard);
    drop(authority_manifest_guard);
    drop(terminal_file);
    drop(abnormal_file);
    drop(late_receipt_file);
    drop(writable_target_guard);
    drop(session_guard);
    drop(root_guard);
    let successor_cleanup = if let Some(mut successor) = cleanup_successor {
        let cleanup = windows_supervisor_frame(12, request_sha256, nonce, &[])?;
        let _ = windows_write_inherited_frame(&mut successor.control, &cleanup);
        drop(successor.control);
        await_windows_session_cleanup_successor_exit(
            &successor.child,
            &successor.observations,
            successor.request_sha256,
            successor.nonce,
            lifetime_deadline,
        )
    } else {
        Err("Windows session cleanup successor is unavailable".to_owned())
    };
    let _ = watchdog_complete.send(());
    let result = match (receipt_acknowledgement, successor_cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) | (Ok(()), Err(primary)) => Err(primary),
        (Err(primary), Err(cleanup)) => Err(format!("{primary}; additionally, {cleanup}")),
    };
    if result.is_ok()
        && let Some(guard) = &mut fixture_exit_guard
    {
        guard.mark_success();
    }
    result
}

#[cfg(windows)]
fn retain_windows_external_supervisor(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    progress: &mut PortabilityChildProgress,
    started: WindowsExternalStarted,
    reason: &str,
) -> Result<(), FailureKind> {
    let late = import_windows_late_supervisor_evidence(
        &started.child,
        &started.session,
        started.request_sha256,
        started.nonce,
    );
    let (state, late_detail, terminal_imported, supervisor_live) = match late {
        Ok(None) => (
            "owned-by-breakaway-windows-supervisor",
            "supervisor process remains live".to_owned(),
            false,
            true,
        ),
        Ok(Some(WindowsLateSupervisorEvidence::Terminal(terminal))) => (
            "terminal-receipt-imported-after-transport-failure",
            terminal.detail,
            true,
            false,
        ),
        Ok(Some(WindowsLateSupervisorEvidence::Abnormal(detail))) => (
            "abnormal-receipt-imported-after-supervisor-exit",
            detail,
            true,
            false,
        ),
        Ok(Some(WindowsLateSupervisorEvidence::Cleanup(detail))) => (
            "cleanup-receipt-imported-after-supervisor-hard-exit",
            detail,
            true,
            false,
        ),
        Err(error) => (
            "supervisor-exited-with-invalid-receipt",
            error,
            false,
            false,
        ),
    };
    progress.record_attribution(
        context.name,
        PortabilityAttributionEvent::Case(
            context.name.to_owned(),
            if supervisor_live {
                PortabilityCaseState::Retained
            } else {
                PortabilityCaseState::Failed
            },
        ),
    );
    report.evidence(
        format!("{}-external-supervisor", context.name),
        JsonValue::Object(BTreeMap::from([
            (
                "containmentScope".to_owned(),
                JsonValue::String("breakaway-supervisor-owning-payload-job".to_owned()),
            ),
            (
                "requestSha256".to_owned(),
                JsonValue::String(started.request_sha256.hex()),
            ),
            (
                "session".to_owned(),
                JsonValue::String(started.session.root_path.display().to_string()),
            ),
            (
                "lateReceipt".to_owned(),
                JsonValue::String(started.session.late_receipt_path.display().to_string()),
            ),
            ("state".to_owned(), JsonValue::String(state.to_owned())),
            (
                "supervisorPid".to_owned(),
                JsonValue::Number(u64::from(started.child.id())),
            ),
            (
                "observerDroppedProgressFrames".to_owned(),
                JsonValue::Number(started.observer_dropped.load(Ordering::Relaxed)),
            ),
            (
                "terminalDetail".to_owned(),
                JsonValue::String(late_detail.clone()),
            ),
        ])),
    );
    report.check(
        context.name,
        context.suite_started.elapsed(),
        Err(format!(
            "{reason}; Windows external supervisor state={state}: {late_detail}; session={}, pid={}",
            started.session.root_path.display(),
            started.child.id()
        )),
    );
    if checkpoint_attributed_phase_with_progress(report, context, progress).is_err() {
        report.check(
            format!("{}-external-supervisor-checkpoint", context.name),
            context.suite_started.elapsed(),
            Err("Windows external ownership checkpoint could not be persisted".to_owned()),
        );
    }
    if terminal_imported
        && let Err(error) = close_imported_windows_supervisor_session(
            started.session,
            started.request_sha256,
            started.nonce,
            context.envelope.report_completion_deadline,
        )
    {
        report.check(
            format!("{}-external-supervisor-session", context.name),
            context.suite_started.elapsed(),
            Err(error),
        );
    }
    Err(FailureKind::Child)
}

#[cfg(windows)]
fn retain_windows_external_supervisor_start(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    progress: &mut PortabilityChildProgress,
    retained: WindowsExternalStartReceipt,
    reason: &str,
) -> Result<(), FailureKind> {
    let late = import_windows_late_supervisor_evidence(
        &retained.child,
        &retained.session,
        retained.request_sha256,
        retained.nonce,
    );
    let (state, detail, live, imported) = match late {
        Ok(None) => (
            "ownership-transfer-indeterminate",
            "supervisor remains live after an indeterminate transfer".to_owned(),
            true,
            false,
        ),
        Ok(Some(WindowsLateSupervisorEvidence::Terminal(terminal))) => (
            "terminal-receipt-imported-after-indeterminate-transfer",
            terminal.detail,
            false,
            true,
        ),
        Ok(Some(WindowsLateSupervisorEvidence::Abnormal(detail))) => (
            "abnormal-receipt-imported-after-indeterminate-transfer",
            detail,
            false,
            true,
        ),
        Ok(Some(WindowsLateSupervisorEvidence::Cleanup(detail))) => (
            "cleanup-receipt-imported-after-indeterminate-transfer",
            detail,
            false,
            true,
        ),
        Err(error) => (
            "invalid-receipt-after-indeterminate-transfer",
            error,
            false,
            false,
        ),
    };
    progress.record_attribution(
        context.name,
        PortabilityAttributionEvent::Case(
            context.name.to_owned(),
            if live {
                PortabilityCaseState::Retained
            } else {
                PortabilityCaseState::Failed
            },
        ),
    );
    report.evidence(
        format!("{}-external-supervisor", context.name),
        JsonValue::Object(BTreeMap::from([
            (
                "containmentScope".to_owned(),
                JsonValue::String("breakaway-supervisor-owning-payload-job".to_owned()),
            ),
            (
                "requestSha256".to_owned(),
                JsonValue::String(retained.request_sha256.hex()),
            ),
            (
                "session".to_owned(),
                JsonValue::String(retained.session.root_path.display().to_string()),
            ),
            (
                "lateReceipt".to_owned(),
                JsonValue::String(retained.session.late_receipt_path.display().to_string()),
            ),
            ("state".to_owned(), JsonValue::String(state.to_owned())),
            (
                "supervisorPid".to_owned(),
                JsonValue::Number(u64::from(retained.child.id())),
            ),
            (
                "nonceSha256".to_owned(),
                JsonValue::String(sha256_bytes(&retained.nonce.0).hex()),
            ),
            (
                "terminalDetail".to_owned(),
                JsonValue::String(detail.clone()),
            ),
        ])),
    );
    report.check(
        context.name,
        context.suite_started.elapsed(),
        Err(format!(
            "{reason}; Windows supervisor state={state}: {detail}; session={}, pid={}",
            retained.session.root_path.display(),
            retained.child.id()
        )),
    );
    if checkpoint_attributed_phase_with_progress(report, context, progress).is_err() {
        report.check(
            format!("{}-external-supervisor-checkpoint", context.name),
            context.suite_started.elapsed(),
            Err("Windows ownership-transfer checkpoint could not be persisted".to_owned()),
        );
    }
    if imported
        && let Err(error) = close_imported_windows_supervisor_session(
            retained.session,
            retained.request_sha256,
            retained.nonce,
            context.envelope.report_completion_deadline,
        )
    {
        report.check(
            format!("{}-external-supervisor-session", context.name),
            context.suite_started.elapsed(),
            Err(error),
        );
    }
    Err(FailureKind::Child)
}

#[cfg(windows)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum WindowsReporterExitStage {
    AuthorityImported,
    CleanupCommitted,
    PayloadStarted,
}

#[cfg(windows)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum WindowsReporterAuthorityMode {
    SealedFixture,
}

#[cfg(windows)]
impl WindowsReporterAuthorityMode {
    fn token(self) -> &'static str {
        match self {
            Self::SealedFixture => "sealed-fixture",
        }
    }

    fn parse(value: &std::ffi::OsStr) -> Result<Self, String> {
        match value.to_str() {
            Some("sealed-fixture") => Ok(Self::SealedFixture),
            _ => Err("Windows reporter fixture authority mode differs".to_owned()),
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Copy)]
struct WindowsReporterExitFixture {
    gate: SocketAddrV4,
    observer: SocketAddrV4,
    exit_observer: SocketAddrV4,
    stage: WindowsReporterExitStage,
    verifier_nonce: Digest,
    malformed_semantic_receipt: bool,
    envelope: SupervisionEnvelope,
}

#[cfg(windows)]
#[derive(Clone, Copy)]
struct WindowsNightlyRunContext<'a> {
    root: &'a Path,
    session_parent: &'a Path,
    plan: ExternalSupervisorPlan,
    suite_started: Instant,
    outer_deadline: Instant,
    phase_started: Instant,
    fixture: Option<WindowsReporterExitFixture>,
}

#[cfg(windows)]
fn publish_windows_reporter_fixture_receipt(
    fixture: WindowsReporterExitFixture,
    session: &WindowsSupervisorSession,
    child: &WindowsSupervisorProcess,
    request_sha256: Digest,
    nonce: Digest,
    started_sha256: Option<Digest>,
    staged_root: Option<&Path>,
) -> Result<(), String> {
    let cleanup_authority_fields = [
        session.root_path.as_os_str().to_owned(),
        session.late_receipt_path.as_os_str().to_owned(),
        std::ffi::OsString::from(child.id().to_string()),
        std::ffi::OsString::from(nonce.hex()),
        staged_root.map_or_else(std::ffi::OsString::new, |path| path.as_os_str().to_owned()),
    ];
    let cleanup_authority = hell_testkit::encode_windows_argv(&cleanup_authority_fields)
        .map(|token| windows_supervisor_os_bytes(&token))
        .map_err(|error| format!("cannot encode Windows reporter cleanup authority: {error}"))?;
    let cleanup_authority = windows_supervisor_frame(
        15,
        request_sha256,
        fixture.verifier_nonce,
        &cleanup_authority,
    )?;
    let receipt_fields = [
        session.root_path.as_os_str().to_owned(),
        session.late_receipt_path.as_os_str().to_owned(),
        std::ffi::OsString::from(child.id().to_string()),
        std::ffi::OsString::from(request_sha256.hex()),
        std::ffi::OsString::from(nonce.hex()),
        started_sha256.map_or_else(std::ffi::OsString::new, |digest| {
            std::ffi::OsString::from(digest.hex())
        }),
        staged_root.map_or_else(std::ffi::OsString::new, |path| path.as_os_str().to_owned()),
    ];
    let mut receipt = hell_testkit::encode_windows_argv(&receipt_fields)
        .map(|token| windows_supervisor_os_bytes(&token))
        .map_err(|error| format!("cannot encode Windows reporter fixture receipt: {error}"))?;
    if fixture.malformed_semantic_receipt {
        receipt.pop().ok_or_else(|| {
            "Windows reporter semantic fixture receipt cannot be truncated".to_owned()
        })?;
    }
    let mut observer = TcpStream::connect(fixture.observer)
        .map_err(|error| format!("cannot connect Windows reporter fixture observer: {error}"))?;
    windows_write_inherited_frame(&mut observer, &cleanup_authority)?;
    windows_write_inherited_frame(&mut observer, &receipt)?;
    read_supervisor_handshake(
        &mut observer,
        ExternalSupervisorMessage::Go,
        request_sha256,
        nonce,
    )
}

#[cfg(windows)]
fn run_windows_externally_supervised_nightly_command_with_fixture(
    run: WindowsNightlyRunContext<'_>,
    report: &mut Report,
    mut authority: Option<&mut dyn WindowsNightlySupervisorAuthority>,
) -> Result<(), FailureKind> {
    let WindowsNightlyRunContext {
        root,
        session_parent,
        plan,
        suite_started,
        outer_deadline,
        phase_started,
        fixture,
    } = run;
    let envelope = if let Some(fixture) = fixture {
        fixture.envelope
    } else {
        SupervisionEnvelope::within(
            phase_started,
            plan.total(),
            NIGHTLY_COMMAND_CLEANUP_RESERVE,
            NIGHTLY_REPORT_RESERVE,
            outer_deadline,
        )
        .map_err(|error| {
            report.check("nightly-deadline", Duration::ZERO, Err(error));
            FailureKind::Policy
        })?
    };
    let seed = plan.seed();
    let mut context = AttributedRunContext {
        name: plan.name(),
        suite: "nightly",
        suite_started,
        envelope,
    };
    let mut progress = PortabilityChildProgress::seeded("nightly", seed.0, seed.1, seed.2);
    let combined_windows_phases =
        plan.combined_followup().is_some() && authority.is_some() && fixture.is_none();
    let supervisor_report_deadline = if combined_windows_phases {
        outer_deadline
    } else {
        envelope.report_completion_deadline
    };
    checkpoint_attributed_phase_with_progress(report, context, &progress)?;
    let prepared = match prepare_windows_external_supervisor(
        root,
        session_parent,
        plan,
        phase_started,
        envelope,
        fixture.map(|fixture| fixture.gate),
        fixture.map(|fixture| fixture.exit_observer),
        authority.as_deref(),
    ) {
        Ok(started) => started,
        Err(failure) => {
            if let Some(retained) = failure.retained {
                return retain_windows_external_supervisor_start(
                    report,
                    context,
                    &mut progress,
                    *retained,
                    &failure.detail,
                );
            }
            return fail_attributed_prelaunch(
                report,
                context,
                &mut progress,
                None,
                PortabilityCaseState::LaunchFailed,
                failure.detail,
            );
        }
    };
    report.evidence(
        format!("{}-external-supervisor", plan.name()),
        JsonValue::Object(BTreeMap::from([
            (
                "containmentScope".to_owned(),
                JsonValue::String("breakaway-supervisor-owning-payload-job".to_owned()),
            ),
            (
                "executionRemainingMillis".to_owned(),
                JsonValue::Number(
                    u64::try_from(
                        envelope
                            .execution_deadline
                            .saturating_duration_since(Instant::now())
                            .as_millis(),
                    )
                    .unwrap_or(u64::MAX),
                ),
            ),
            (
                "nonceSha256".to_owned(),
                JsonValue::String(sha256_bytes(&prepared.nonce.0).hex()),
            ),
            (
                "reportRemainingMillis".to_owned(),
                JsonValue::Number(
                    u64::try_from(
                        envelope
                            .report_completion_deadline
                            .saturating_duration_since(Instant::now())
                            .as_millis(),
                    )
                    .unwrap_or(u64::MAX),
                ),
            ),
            (
                "requestSha256".to_owned(),
                JsonValue::String(prepared.request_sha256.hex()),
            ),
            (
                "session".to_owned(),
                JsonValue::String(prepared.session.root_path.display().to_string()),
            ),
            (
                "lateReceipt".to_owned(),
                JsonValue::String(prepared.session.late_receipt_path.display().to_string()),
            ),
            (
                "state".to_owned(),
                JsonValue::String("ready-before-go".to_owned()),
            ),
            (
                "supervisorPid".to_owned(),
                JsonValue::Number(u64::from(prepared.child.id())),
            ),
        ])),
    );
    if checkpoint_attributed_phase_with_progress(report, context, &progress).is_err() {
        let failure = close_prepared_windows_supervisor(
            prepared,
            "Windows Ready checkpoint could not be persisted before Go".to_owned(),
        );
        return fail_attributed_prelaunch(
            report,
            context,
            &mut progress,
            None,
            PortabilityCaseState::LaunchFailed,
            failure.detail,
        );
    }
    let mut started = match transfer_windows_external_supervisor(prepared, |event| {
        match event {
            WindowsAuthorityTransferEvent::Imported(manifest_sha256) => {
                progress.record_attribution(
                    plan.name(),
                    PortabilityAttributionEvent::Subphase("authority-imported".to_owned()),
                );
                report.evidence(
                    format!("{}-authority-import", plan.name()),
                    JsonValue::Object(BTreeMap::from([
                        (
                            "manifestSha256".to_owned(),
                            JsonValue::String(manifest_sha256.hex()),
                        ),
                        (
                            "state".to_owned(),
                            JsonValue::String("imported-before-go".to_owned()),
                        ),
                    ])),
                );
                checkpoint_attributed_phase_with_progress(report, context, &progress).map_err(
                    |error| {
                        format!("cannot persist Windows authority import checkpoint: {error:?}")
                    },
                )?;
                if let Some(authority) = authority.as_deref_mut() {
                    authority.prepare_cleanup_transfer(envelope.execution)?;
                }
                if fixture.is_some_and(|fixture| {
                    fixture.stage == WindowsReporterExitStage::AuthorityImported
                }) {
                    if let Some(authority) = authority.as_deref_mut() {
                        authority.commit_cleanup_transfer();
                    }
                    return Ok(WindowsAuthorityTransferDecision::RetainBeforeCommit);
                }
            }
            WindowsAuthorityTransferEvent::Committed => {
                if let Some(authority) = authority.as_deref_mut() {
                    authority.commit_cleanup_transfer();
                }
                if fixture.is_some_and(|fixture| {
                    fixture.stage == WindowsReporterExitStage::CleanupCommitted
                }) {
                    return Ok(WindowsAuthorityTransferDecision::RetainBeforeGo);
                }
            }
        }
        Ok(WindowsAuthorityTransferDecision::Continue)
    }) {
        Ok(started) => started,
        Err(failure) => {
            if let Some(retained) = failure.retained {
                if let Some(fixture) = fixture
                    && fixture.stage != WindowsReporterExitStage::PayloadStarted
                {
                    let staged_root = authority
                        .as_deref()
                        .map(|authority| authority.staged_root());
                    if let Err(error) = publish_windows_reporter_fixture_receipt(
                        fixture,
                        &retained.session,
                        &retained.child,
                        retained.request_sha256,
                        retained.nonce,
                        None,
                        staged_root,
                    ) {
                        return retain_windows_external_supervisor_start(
                            report,
                            context,
                            &mut progress,
                            *retained,
                            &format!("{}; additionally, {error}", failure.detail),
                        );
                    }
                }
                return retain_windows_external_supervisor_start(
                    report,
                    context,
                    &mut progress,
                    *retained,
                    &failure.detail,
                );
            }
            return fail_attributed_prelaunch(
                report,
                context,
                &mut progress,
                None,
                PortabilityCaseState::LaunchFailed,
                failure.detail,
            );
        }
    };
    if let Some(fixture) = fixture {
        let staged_root = authority
            .as_deref()
            .map(|authority| authority.staged_root());
        let fixture_result = publish_windows_reporter_fixture_receipt(
            fixture,
            &started.session,
            &started.child,
            started.request_sha256,
            started.nonce,
            Some(started.started_sha256),
            staged_root,
        );
        if let Err(error) = fixture_result {
            return retain_windows_external_supervisor(
                report,
                context,
                &mut progress,
                started,
                &error,
            );
        }
        return retain_windows_external_supervisor(
            report,
            context,
            &mut progress,
            started,
            "Windows reporter fixture transferred ownership before reporter exit",
        );
    }
    let terminal_bytes = loop {
        let terminal_wait = supervisor_report_deadline.saturating_duration_since(Instant::now());
        let frame = match started.observations.recv_timeout(terminal_wait) {
            Ok(Ok(frame)) => frame,
            Ok(Err(error)) => {
                if let Ok(Some(terminal)) = import_windows_terminal_after_transport(&started) {
                    break terminal;
                }
                return retain_windows_external_supervisor(
                    report,
                    context,
                    &mut progress,
                    started,
                    &error,
                );
            }
            Err(error) => {
                if let Ok(Some(terminal)) = import_windows_terminal_after_transport(&started) {
                    break terminal;
                }
                return retain_windows_external_supervisor(
                    report,
                    context,
                    &mut progress,
                    started,
                    &format!("cannot receive Windows supervisor observation: {error}"),
                );
            }
        };
        match frame.first().copied() {
            Some(4) => {
                match windows_validate_frame(&frame, 4, started.request_sha256, started.nonce) {
                    Ok(bytes) => break bytes.to_vec(),
                    Err(error) => {
                        return retain_windows_external_supervisor(
                            report,
                            context,
                            &mut progress,
                            started,
                            &error,
                        );
                    }
                }
            }
            Some(6) => {
                let payload =
                    match windows_validate_frame(&frame, 6, started.request_sha256, started.nonce)
                        .and_then(decode_external_supervisor_progress)
                    {
                        Ok(attribution) => attribution,
                        Err(error) => {
                            return retain_windows_external_supervisor(
                                report,
                                context,
                                &mut progress,
                                started,
                                &error,
                            );
                        }
                    };
                if let Some(followup) = plan.combined_followup()
                    && combined_windows_phases
                    && payload.target.as_deref() == Some(followup.seed().0)
                    && context.name != followup.name()
                {
                    let core_started = Instant::now();
                    let core_envelope = SupervisionEnvelope::within(
                        core_started,
                        followup.total(),
                        NIGHTLY_COMMAND_CLEANUP_RESERVE,
                        NIGHTLY_REPORT_RESERVE,
                        outer_deadline,
                    )
                    .map_err(|error| {
                        report.check(
                            "nightly-core-data-deadline",
                            suite_started.elapsed(),
                            Err(error),
                        );
                        FailureKind::Policy
                    })?;
                    context = AttributedRunContext {
                        name: followup.name(),
                        suite: "nightly",
                        suite_started,
                        envelope: core_envelope,
                    };
                }
                if let Err(error) = progress.apply_external_attribution(payload) {
                    return retain_windows_external_supervisor(
                        report,
                        context,
                        &mut progress,
                        started,
                        &error,
                    );
                }
                emit_attributed_progress_with_deadlines(context, "running", &progress);
                if checkpoint_attributed_phase_with_progress(report, context, &progress).is_err() {
                    return retain_windows_external_supervisor(
                        report,
                        context,
                        &mut progress,
                        started,
                        "Windows progress checkpoint could not be persisted",
                    );
                }
            }
            _ => {
                return retain_windows_external_supervisor(
                    report,
                    context,
                    &mut progress,
                    started,
                    "Windows supervisor observation has an unknown phase",
                );
            }
        }
    };
    let terminal = match decode_external_supervisor_terminal(
        &terminal_bytes,
        started.request_sha256,
        started.nonce,
    ) {
        Ok(terminal) => terminal,
        Err(error) => {
            return retain_windows_external_supervisor(
                report,
                context,
                &mut progress,
                started,
                &error,
            );
        }
    };
    let workspace_terminal = if combined_windows_phases {
        let bytes =
            read_windows_supervisor_receipt(&started.session.root_path.join("workspace.receipt"))
                .map_err(|error| {
                report.check(plan.name(), suite_started.elapsed(), Err(error));
                FailureKind::Fixture
            })?;
        Some(
            decode_external_supervisor_terminal(&bytes, started.request_sha256, started.nonce)
                .map_err(|error| {
                    report.check(plan.name(), suite_started.elapsed(), Err(error));
                    FailureKind::Fixture
                })?,
        )
    } else {
        None
    };
    if let Some(followup) = plan.combined_followup()
        && combined_windows_phases
        && terminal.attribution.target.as_deref() == Some(followup.seed().0)
        && context.name != followup.name()
    {
        let core_started = Instant::now();
        let core_envelope = SupervisionEnvelope::within(
            core_started,
            followup.total(),
            NIGHTLY_COMMAND_CLEANUP_RESERVE,
            NIGHTLY_REPORT_RESERVE,
            outer_deadline,
        )
        .map_err(|error| {
            report.check(
                "nightly-core-data-deadline",
                suite_started.elapsed(),
                Err(error),
            );
            FailureKind::Policy
        })?;
        context = AttributedRunContext {
            name: followup.name(),
            suite: "nightly",
            suite_started,
            envelope: core_envelope,
        };
    }
    let mut terminal_evidence =
        external_supervisor_terminal_evidence(plan, &terminal, started.request_sha256);
    if let JsonValue::Object(fields) = &mut terminal_evidence {
        fields.insert(
            "startedSha256".to_owned(),
            JsonValue::String(started.started_sha256.hex()),
        );
        fields.insert(
            "supervisorPid".to_owned(),
            JsonValue::Number(u64::from(started.child.id())),
        );
        fields.insert(
            "observerDroppedProgressFrames".to_owned(),
            JsonValue::Number(started.observer_dropped.load(Ordering::Relaxed)),
        );
        fields.insert(
            "lateReceipt".to_owned(),
            JsonValue::String(started.session.late_receipt_path.display().to_string()),
        );
    }
    report.evidence(
        format!("{}-external-supervisor", plan.name()),
        terminal_evidence,
    );
    if let Some(workspace) = &workspace_terminal {
        report.evidence(
            format!("{}-external-supervisor-terminal", plan.name()),
            external_supervisor_terminal_evidence(plan, workspace, started.request_sha256),
        );
    }
    if let Err(error) = progress.apply_external_attribution(terminal.attribution.clone()) {
        return retain_windows_external_supervisor(report, context, &mut progress, started, &error);
    }
    started.session.revalidate().map_err(|error| {
        report.check(plan.name(), suite_started.elapsed(), Err(error));
        FailureKind::Fixture
    })?;
    let terminal_path = started.session.root_path.join("terminal.receipt");
    let (mut terminal_guard, terminal_receipt) =
        windows_bind_path(&terminal_path, false).map_err(|error| {
            report.check(plan.name(), suite_started.elapsed(), Err(error));
            FailureKind::Fixture
        })?;
    let mut persisted = Vec::new();
    terminal_guard
        .read_to_end(&mut persisted)
        .map_err(|error| {
            report.check(
                plan.name(),
                suite_started.elapsed(),
                Err(format!("cannot read Windows terminal receipt: {error}")),
            );
            FailureKind::Fixture
        })?;
    if persisted != terminal_bytes
        || windows_file_receipt(&terminal_guard).ok() != Some(terminal_receipt)
    {
        report.check(
            plan.name(),
            suite_started.elapsed(),
            Err("Windows terminal receipt differs from authenticated transport".to_owned()),
        );
        return Err(FailureKind::Fixture);
    }
    drop(terminal_guard);
    let cleanup_commit =
        read_windows_supervisor_receipt(&started.session.root_path.join("cleanup.commit"))
            .map_err(|error| {
                report.check(plan.name(), suite_started.elapsed(), Err(error));
                FailureKind::Fixture
            })?;
    windows_validate_frame(&cleanup_commit, 11, started.request_sha256, started.nonce).map_err(
        |error| {
            report.check(plan.name(), suite_started.elapsed(), Err(error));
            FailureKind::Fixture
        },
    )?;
    let cleanup_receipt =
        read_windows_supervisor_receipt(&started.session.root_path.join("cleanup.receipt"))
            .map_err(|error| {
                report.check(plan.name(), suite_started.elapsed(), Err(error));
                FailureKind::Fixture
            })?;
    let cleanup_detail =
        windows_validate_frame(&cleanup_receipt, 9, started.request_sha256, started.nonce)
            .and_then(|payload| {
                String::from_utf8(payload.to_vec())
                    .map_err(|_| "Windows authority cleanup detail is not UTF-8".to_owned())
            })
            .map_err(|error| {
                report.check(plan.name(), suite_started.elapsed(), Err(error));
                FailureKind::Fixture
            })?;
    if cleanup_detail != "completed" {
        report.check(
            plan.name(),
            suite_started.elapsed(),
            Err(format!(
                "Windows authority cleanup failed: {cleanup_detail}"
            )),
        );
        return Err(FailureKind::Fixture);
    }
    let late_receipt = started
        .session
        .transfer_session_cleanup()
        .map_err(|error| {
            report.check(plan.name(), suite_started.elapsed(), Err(error));
            FailureKind::Fixture
        })?;
    let acknowledgement = windows_supervisor_frame(5, started.request_sha256, started.nonce, &[])
        .and_then(|frame| windows_write_inherited_frame(&mut started.control, &frame));
    if let Err(error) = acknowledgement {
        report.check(plan.name(), suite_started.elapsed(), Err(error));
        return Err(FailureKind::Fixture);
    }
    drop(started.control);
    let supervisor_status = loop {
        match started.child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < supervisor_report_deadline => {
                std::thread::yield_now();
            }
            Ok(None) => {
                report.check(
                    plan.name(),
                    suite_started.elapsed(),
                    Err("Windows supervisor exit exceeded its report deadline".to_owned()),
                );
                return Err(FailureKind::Fixture);
            }
            Err(error) => {
                report.check(
                    plan.name(),
                    suite_started.elapsed(),
                    Err(format!("cannot poll Windows supervisor exit: {error}")),
                );
                return Err(FailureKind::Fixture);
            }
        }
    };
    let session_cleanup = late_receipt.close(supervisor_report_deadline);
    apply_terminal_failed_case(&mut progress, &terminal);
    let terminal_case = progress
        .case
        .clone()
        .unwrap_or_else(|| plan.name().to_owned());
    progress.record_attribution(
        plan.name(),
        PortabilityAttributionEvent::Case(
            terminal_case,
            if terminal.execution.success {
                PortabilityCaseState::Completed
            } else {
                PortabilityCaseState::Failed
            },
        ),
    );
    checkpoint_attributed_phase_with_progress(report, context, &progress)?;
    let primary =
        if terminal.execution.success && terminal.cleanup.terminal && supervisor_status == 0 {
            None
        } else {
            Some(format!(
                "{}: {}; cleanup terminal: {}; supervisor status: {}",
                plan.name(),
                terminal.detail,
                terminal.cleanup.terminal,
                supervisor_status
            ))
        };
    let result = match (primary, session_cleanup) {
        (None, Ok(())) => Ok(()),
        (Some(primary), Ok(())) => Err(primary),
        (None, Err(cleanup)) => Err(cleanup),
        (Some(primary), Err(cleanup)) => Err(format!(
            "{primary}; additionally, session cleanup failed: {cleanup}"
        )),
    };
    let passed = result.is_ok();
    let completed_workspace = workspace_terminal
        .as_ref()
        .is_some_and(|workspace| workspace.execution.success && workspace.cleanup.terminal);
    if completed_workspace {
        report.check(plan.name(), suite_started.elapsed(), Ok(()));
    }
    report.check(
        if completed_workspace {
            plan.combined_followup()
                .map_or(plan.name(), ExternalSupervisorPlan::name)
        } else {
            plan.name()
        },
        suite_started.elapsed(),
        result,
    );
    checkpoint_attributed_phase_complete(report, "nightly", Some(supervisor_report_deadline))?;
    passed.then_some(()).ok_or(FailureKind::Child)
}

#[cfg(windows)]
fn run_windows_externally_supervised_nightly_command(
    run: WindowsNightlyRunContext<'_>,
    report: &mut Report,
    authority: &mut crate::release::platform::NightlyWindowsLaunchAuthority,
) -> Result<(), FailureKind> {
    run_windows_externally_supervised_nightly_command_with_fixture(run, report, Some(authority))
}

#[cfg(windows)]
pub(crate) fn run_windows_external_supervisor_reporter_fixture(
    arguments: &[std::ffi::OsString],
) -> Result<(), String> {
    let [
        root,
        session_parent,
        report_path,
        observer_address,
        observer_port,
        gate_address,
        gate_port,
        exit_observer_address,
        exit_observer_port,
        exit_stage,
        authority_mode,
        authority_root,
        execution_remaining_millis,
        cleanup_remaining_millis,
        verifier_nonce,
    ] = arguments
    else {
        return Err(
            "Windows nightly reporter fixture requires root, session parent, report, three loopback addresses, an exit stage, an authority mode, an authority root, two deadline receipts, and a verifier nonce"
                .to_owned(),
        );
    };
    let (stage, malformed_semantic_receipt) = match exit_stage.to_str() {
        Some("authority-imported") => (WindowsReporterExitStage::AuthorityImported, false),
        Some("authority-imported-malformed-receipt") => {
            (WindowsReporterExitStage::AuthorityImported, true)
        }
        Some("cleanup-committed") => (WindowsReporterExitStage::CleanupCommitted, false),
        Some("payload-started") => (WindowsReporterExitStage::PayloadStarted, false),
        _ => return Err("Windows nightly reporter fixture exit stage differs".to_owned()),
    };
    let authority_mode = WindowsReporterAuthorityMode::parse(authority_mode)?;
    let verifier_nonce = Digest::from_hex(
        verifier_nonce
            .to_str()
            .ok_or_else(|| "Windows reporter verifier nonce is not UTF-8".to_owned())?,
    )
    .map_err(|error| format!("Windows reporter verifier nonce is invalid: {error}"))?;
    let observer = parse_loopback_address(observer_address, observer_port)?;
    let gate = parse_loopback_address(gate_address, gate_port)?;
    let exit_observer = parse_loopback_address(exit_observer_address, exit_observer_port)?;
    let phase_started = Instant::now();
    let execution_deadline = phase_started
        .checked_add(Duration::from_millis(windows_parse_u64(
            execution_remaining_millis,
            "reporter execution remaining millis",
        )?))
        .ok_or_else(|| "Windows reporter fixture execution deadline overflowed".to_owned())?;
    let outer_deadline = phase_started
        .checked_add(Duration::from_millis(windows_parse_u64(
            cleanup_remaining_millis,
            "reporter cleanup remaining millis",
        )?))
        .ok_or_else(|| "Windows reporter fixture cleanup deadline overflowed".to_owned())?;
    let child_completion_deadline = outer_deadline
        .checked_sub(NIGHTLY_SUPERVISOR_START_TIMEOUT)
        .ok_or_else(|| "Windows reporter fixture cleanup reserve underflowed".to_owned())?;
    if execution_deadline >= child_completion_deadline || Instant::now() >= execution_deadline {
        return Err(
            "Windows reporter fixture deadline receipt is exhausted or unordered".to_owned(),
        );
    }
    let report_path = PathBuf::from(report_path);
    let root = Path::new(root);
    let envelope = SupervisionEnvelope {
        execution: execution_deadline,
        child_completion_deadline,
        report_completion_deadline: outer_deadline,
    };
    let mut authority = match authority_mode {
        WindowsReporterAuthorityMode::SealedFixture => {
            WindowsReporterBorrowedAuthority::bind_until(
                Path::new(session_parent),
                Path::new(authority_root),
                envelope.execution,
            )?
        }
    };
    let staged_root = authority.staged_root().to_path_buf();
    let mut report = Report::new("windows-nightly-supervisor-reporter-fixture");
    let primary = (|| {
        report
            .attach_checkpoint(report_path.clone())
            .map_err(|error| {
                format!("cannot attach Windows reporter fixture checkpoint: {error}")
            })?;
        let result = run_windows_externally_supervised_nightly_command_with_fixture(
            WindowsNightlyRunContext {
                root,
                session_parent: Path::new(session_parent),
                plan: ExternalSupervisorPlan::WindowsAuthorityProbe,
                suite_started: phase_started,
                outer_deadline,
                phase_started,
                fixture: Some(WindowsReporterExitFixture {
                    gate,
                    observer,
                    exit_observer,
                    stage,
                    verifier_nonce,
                    malformed_semantic_receipt,
                    envelope,
                }),
            },
            &mut report,
            Some(&mut authority),
        );
        report.evidence(
            "windows-reporter-fixture-staged-authority",
            JsonValue::String(staged_root.display().to_string()),
        );
        report.evidence(
            "windows-reporter-fixture-authority-pass-counts",
            JsonValue::Object(BTreeMap::from([
                ("realAcquisitions".to_owned(), JsonValue::Number(0)),
                (
                    "sealedFixtureImports".to_owned(),
                    JsonValue::Number(u64::from(
                        authority_mode == WindowsReporterAuthorityMode::SealedFixture,
                    )),
                ),
                (
                    "cleanupTransferred".to_owned(),
                    JsonValue::Bool(authority.cleanup_transferred()),
                ),
            ])),
        );
        report
            .write(&report_path)
            .map_err(|error| format!("cannot persist Windows reporter fixture report: {error}"))?;
        if result != Err(FailureKind::Child) || report.failures.is_empty() {
            return Err("Windows reporter fixture did not persist external ownership".to_owned());
        }
        Ok(())
    })();
    let cleanup = Ok(());
    match (primary, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(format!(
            "{primary}; additionally, reporter authority cleanup failed: {cleanup}"
        )),
    }
}

#[cfg(windows)]
fn cleanup_bound_windows_supervisor_session(
    session_path: &Path,
    expected: WindowsFileReceipt,
    deadline: Instant,
) -> Result<(), String> {
    let (root, observed) = windows_bind_path(session_path, true)?;
    if observed != expected || windows_file_receipt(&root)? != expected {
        return Err("Windows cleanup successor session identity changed".to_owned());
    }
    drop(root);
    cleanup_windows_supervisor_verifier_session(session_path, deadline)
}

#[cfg(windows)]
fn cleanup_windows_supervisor_verifier_session(
    session_path: &Path,
    deadline: Instant,
) -> Result<(), String> {
    let parent_path = session_path
        .parent()
        .ok_or_else(|| "Windows verifier session has no parent".to_owned())?;
    let (parent, parent_receipt) = windows_bind_path(parent_path, true)?;
    let (root, root_receipt) = windows_bind_path(session_path, true)?;
    reset_windows_supervisor_session(session_path, deadline)?;
    if windows_file_receipt(&parent)? != parent_receipt
        || windows_file_receipt(&root)? != root_receipt
        || windows_bind_path(parent_path, true)?.1 != parent_receipt
        || windows_bind_path(session_path, true)?.1 != root_receipt
    {
        return Err("Windows verifier session changed during DACL reset".to_owned());
    }
    let allowed = [
        "ownership.receipt",
        "request.digest",
        "authority.manifest",
        "started.receipt",
        "terminal.receipt",
        "workspace.receipt",
        "abnormal.receipt",
        "cleanup.commit",
        "cleanup.receipt",
    ];
    let mut count = 0_usize;
    for entry in fs::read_dir(session_path)
        .map_err(|error| format!("cannot enumerate Windows verifier session: {error}"))?
    {
        if Instant::now() >= deadline {
            return Err("Windows verifier session cleanup exceeded its deadline".to_owned());
        }
        let entry = entry
            .map_err(|error| format!("cannot read Windows verifier session entry: {error}"))?;
        count = count.saturating_add(1);
        if count > allowed.len() || !allowed.iter().any(|name| entry.file_name() == *name) {
            return Err("Windows verifier session inventory differs".to_owned());
        }
        let path = entry.path();
        let (file, receipt) = windows_bind_path(&path, false)?;
        drop(file);
        if windows_file_receipt(&parent)? != parent_receipt
            || windows_file_receipt(&root)? != root_receipt
            || windows_bind_path(parent_path, true)?.1 != parent_receipt
            || windows_bind_path(session_path, true)?.1 != root_receipt
            || windows_bind_path(&path, false)?.1 != receipt
        {
            return Err("Windows verifier session changed before receipt cleanup".to_owned());
        }
        fs::remove_file(&path)
            .map_err(|error| format!("cannot remove Windows verifier receipt: {error}"))?;
    }
    if count != allowed.len()
        || windows_file_receipt(&parent)? != parent_receipt
        || windows_file_receipt(&root)? != root_receipt
        || windows_bind_path(parent_path, true)?.1 != parent_receipt
        || windows_bind_path(session_path, true)?.1 != root_receipt
    {
        return Err("Windows verifier session changed before root cleanup".to_owned());
    }
    drop(root);
    fs::remove_dir(session_path)
        .map_err(|error| format!("cannot remove Windows verifier session: {error}"))
}

#[cfg(windows)]
fn verify_windows_supervisor_report(
    bytes: &[u8],
    session_path: &Path,
    supervisor_pid: u32,
    request_sha256: Digest,
    cleanup_transferred: bool,
) -> Result<(), String> {
    let document: serde_yaml::Value = serde_yaml::from_slice(bytes)
        .map_err(|error| format!("cannot parse Windows verifier report: {error}"))?;
    let active_state = document
        .get("activePhase")
        .and_then(|phase| phase.get("attribution"))
        .and_then(|attribution| attribution.get("caseState"))
        .and_then(serde_yaml::Value::as_str);
    if active_state != Some("retained") {
        return Err("Windows verifier report lacks retained active attribution".to_owned());
    }
    let evidence = document
        .get("evidence")
        .and_then(serde_yaml::Value::as_sequence)
        .ok_or_else(|| "Windows verifier report evidence is absent".to_owned())?;
    let expected_name = format!(
        "{}-external-supervisor",
        ExternalSupervisorPlan::WindowsAuthorityProbe.name()
    );
    let receipt = evidence
        .iter()
        .find(|entry| entry.get("name").and_then(serde_yaml::Value::as_str) == Some(&expected_name))
        .and_then(|entry| entry.get("value"))
        .ok_or_else(|| "Windows verifier report external receipt is absent".to_owned())?;
    let expected_session = session_path.display().to_string();
    if receipt.get("state").and_then(serde_yaml::Value::as_str)
        != Some("owned-by-breakaway-windows-supervisor")
        || receipt.get("session").and_then(serde_yaml::Value::as_str)
            != Some(expected_session.as_str())
        || receipt
            .get("requestSha256")
            .and_then(serde_yaml::Value::as_str)
            != Some(request_sha256.hex().as_str())
        || receipt
            .get("supervisorPid")
            .and_then(serde_yaml::Value::as_u64)
            != Some(u64::from(supervisor_pid))
    {
        return Err("Windows verifier report external receipt differs".to_owned());
    }
    if document
        .get("failures")
        .and_then(serde_yaml::Value::as_sequence)
        .is_none_or(Vec::is_empty)
    {
        return Err("Windows verifier report failure chronology is absent".to_owned());
    }
    let pass_counts = evidence
        .iter()
        .find(|entry| {
            entry.get("name").and_then(serde_yaml::Value::as_str)
                == Some("windows-reporter-fixture-authority-pass-counts")
        })
        .and_then(|entry| entry.get("value"))
        .ok_or_else(|| "Windows verifier authority pass counts are absent".to_owned())?;
    if pass_counts
        .get("realAcquisitions")
        .and_then(serde_yaml::Value::as_u64)
        != Some(0)
        || pass_counts
            .get("sealedFixtureImports")
            .and_then(serde_yaml::Value::as_u64)
            != Some(1)
        || pass_counts
            .get("cleanupTransferred")
            .and_then(serde_yaml::Value::as_bool)
            != Some(cleanup_transferred)
    {
        return Err("Windows verifier authority pass counts differ".to_owned());
    }
    Ok(())
}

#[cfg(windows)]
fn windows_csv_fields(line: &str) -> Result<Vec<String>, String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut characters = line.chars().peekable();
    let mut quoted = false;
    while let Some(character) = characters.next() {
        match character {
            '"' if quoted && characters.peek() == Some(&'"') => {
                field.push('"');
                characters.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => {
                fields.push(std::mem::take(&mut field));
            }
            _ => field.push(character),
        }
    }
    if quoted {
        return Err("Windows process inventory CSV has an unterminated quote".to_owned());
    }
    fields.push(field);
    Ok(fields)
}

#[cfg(windows)]
fn require_windows_process_absent(pid: u32, deadline: Instant) -> Result<(), String> {
    let environment = ProcessEnvironment::from_process();
    let system_root = environment
        .value(StandardVariable::SystemRoot)
        .map(PathBuf::from)
        .ok_or_else(|| "Windows system root is absent".to_owned())?;
    let tasklist = system_root.join("System32").join("tasklist.exe");
    let pid_text = pid.to_string();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "Windows process {pid} remained present past its deadline"
            ));
        }
        let result = CommandSpec::new(&tasklist, remaining.min(Duration::from_secs(5)))
            .arguments([
                std::ffi::OsString::from("/FO"),
                std::ffi::OsString::from("CSV"),
                std::ffi::OsString::from("/NH"),
            ])
            .run()
            .map_err(|error| format!("cannot inspect Windows process {pid}: {error}"))?;
        if !result.status.success() || result.timed_out {
            return Err(format!("Windows process inventory failed for {pid}"));
        }
        let output = std::str::from_utf8(&result.stdout)
            .map_err(|_| "Windows process inventory is not UTF-8".to_owned())?;
        let mut present = false;
        for line in output.lines() {
            let fields = windows_csv_fields(line)?;
            if fields.get(1).is_some_and(|value| value == &pid_text) {
                present = true;
                break;
            }
        }
        if !present {
            return Ok(());
        }
        std::thread::yield_now();
    }
}

#[cfg(windows)]
fn verify_windows_external_supervisor_no_go_for_integration(
    root: &Path,
    session_parent: &Path,
    deadline: Instant,
    authority: Option<&crate::release::platform::NightlyWindowsLaunchAuthority>,
) -> Result<(), String> {
    let phase_started = Instant::now();
    let envelope = SupervisionEnvelope::within(
        phase_started,
        ExternalSupervisorPlan::NightlyCoreData.total(),
        NIGHTLY_COMMAND_CLEANUP_RESERVE,
        NIGHTLY_REPORT_RESERVE,
        deadline,
    )?;
    let prepared = prepare_windows_external_supervisor(
        root,
        session_parent,
        ExternalSupervisorPlan::NightlyCoreData,
        phase_started,
        envelope,
        None,
        None,
        authority.map(|authority| authority as &dyn WindowsNightlySupervisorAuthority),
    )
    .map_err(|failure| failure.detail)?;
    let session_path = prepared.session.root_path.clone();
    let supervisor_pid = prepared.child.id();
    let started_path = session_path.join("started.receipt");
    let marker = (|| {
        let (started, started_receipt) = windows_bind_path(&started_path, false)?;
        if started_receipt.size != 0 || windows_file_receipt(&started)? != started_receipt {
            return Err("Windows supervisor launched a payload before Go".to_owned());
        }
        Ok(())
    })();
    let failure = close_prepared_windows_supervisor(
        prepared,
        "Windows no-Go verifier requested prelaunch cleanup".to_owned(),
    );
    if failure.retained.is_some() {
        return Err(format!(
            "Windows no-Go cleanup retained external ownership: {}",
            failure.detail
        ));
    }
    marker?;
    if let Some(authority) = authority {
        encode_windows_nightly_authority_manifest(Some(authority), deadline).map_err(|error| {
            format!("Windows no-Go authority was not retained by the reporter: {error}")
        })?;
    }
    require_windows_process_absent(supervisor_pid, deadline)?;
    match fs::symlink_metadata(&session_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot attest Windows no-Go session absence: {error}"
        )),
        Ok(_) => Err("Windows no-Go session remains after cleanup".to_owned()),
    }
}

#[cfg(windows)]
fn verify_windows_cargo_authority_for_integration(
    root: &Path,
    session_parent: &Path,
    deadline: Instant,
) -> Result<(), String> {
    let phase_started = Instant::now();
    let envelope = SupervisionEnvelope::within(
        phase_started,
        ExternalSupervisorPlan::WindowsAuthorityProbe.total(),
        NIGHTLY_COMMAND_CLEANUP_RESERVE,
        NIGHTLY_REPORT_RESERVE,
        deadline,
    )?;
    let target = fs::canonicalize(root.join("target"))
        .map_err(|error| format!("cannot bind Windows authority probe target: {error}"))?;
    let mut authority = crate::release::platform::NightlyWindowsLaunchAuthority::acquire_until(
        root,
        &target,
        envelope.execution,
        envelope.child_completion_deadline,
    )?;
    let staged_root = authority.staged_root().to_path_buf();
    verify_windows_external_supervisor_no_go_for_integration(
        root,
        session_parent,
        envelope.execution,
        Some(&authority),
    )?;
    let mut report = Report::new("windows-nightly-authority-probe");
    let primary = run_windows_externally_supervised_nightly_command(
        WindowsNightlyRunContext {
            root,
            session_parent,
            plan: ExternalSupervisorPlan::WindowsAuthorityProbe,
            suite_started: phase_started,
            outer_deadline: deadline,
            phase_started,
            fixture: None,
        },
        &mut report,
        &mut authority,
    )
    .map_err(|error| format!("Windows staged Cargo authority probe failed: {error:?}"));
    let receipts = (|| -> Result<(), String> {
        for (name, target) in [
            (
                format!(
                    "{}-external-supervisor-terminal",
                    ExternalSupervisorPlan::WindowsAuthorityProbe.name()
                ),
                ExternalSupervisorPlan::WindowsAuthorityProbe.seed().0,
            ),
            (
                format!(
                    "{}-external-supervisor",
                    ExternalSupervisorPlan::WindowsAuthorityProbe.name()
                ),
                ExternalSupervisorPlan::WindowsCoreAuthorityProbe.seed().0,
            ),
        ] {
            let receipt = report
                .evidence_value(&name)
                .ok_or_else(|| format!("Windows combined phase receipt {name} is absent"))?
                .object()?;
            let attribution = receipt
                .get("attribution")
                .ok_or_else(|| format!("Windows combined phase receipt {name} lacks attribution"))?
                .object()?;
            if receipt
                .get("success")
                .and_then(|value| value.boolean().ok())
                != Some(true)
                || receipt
                    .get("cleanupTerminal")
                    .and_then(|value| value.boolean().ok())
                    != Some(true)
                || receipt
                    .get("captureState")
                    .and_then(|value| value.string().ok())
                    != Some("available")
                || attribution
                    .get("target")
                    .and_then(|value| value.string().ok())
                    != Some(target)
                || attribution
                    .get("caseState")
                    .and_then(|value| value.string().ok())
                    != Some("completed")
            {
                return Err(format!("Windows combined phase receipt {name} differs"));
            }
        }
        Ok(())
    })();
    let cleanup = if authority.cleanup_transferred() {
        match fs::symlink_metadata(&staged_root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("cannot attest staged Cargo probe absence: {error}")),
            Ok(_) => Err("staged Cargo probe authority remains after terminal cleanup".to_owned()),
        }
    } else {
        authority.close_until(envelope.report_completion_deadline)
    };
    match (primary, receipts, cleanup) {
        (Ok(()), Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(()), Ok(()))
        | (Ok(()), Err(primary), Ok(()))
        | (Ok(()), Ok(()), Err(primary)) => Err(primary),
        (primary, receipts, cleanup) => Err([primary.err(), receipts.err(), cleanup.err()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("; additionally, ")),
    }
}

#[cfg(windows)]
struct WindowsReporterExitObservation {
    report_path: PathBuf,
    session_path: PathBuf,
    late_receipt_path: PathBuf,
    late_receipt: Option<fs::File>,
    initial_late_receipt: Option<WindowsFileReceipt>,
    supervisor_pid: u32,
    request_sha256: Digest,
    nonce: Digest,
    staged_root: PathBuf,
    terminal: Option<mpsc::Receiver<AttributedWorkerTerminal>>,
    exit_receipt: Option<TcpStream>,
    exit_receiver: Option<mpsc::Receiver<Result<TcpStream, std::io::Error>>>,
    reporter_control: Option<TcpStream>,
    gate_receiver: Option<mpsc::Receiver<Result<TcpStream, std::io::Error>>>,
    gate: Option<TcpStream>,
    payload_processes: Option<(u32, u32)>,
    reporter_exited: bool,
    supervisor_exit_code: Option<u32>,
    late_bytes: Option<Vec<u8>>,
    report_removed: bool,
    finalized: bool,
    deadline: Instant,
    cleanup_deadline: Instant,
    stage: String,
}

#[cfg(windows)]
struct WindowsReporterLaunchOwner {
    terminal: Option<mpsc::Receiver<AttributedWorkerTerminal>>,
    report_path: Option<PathBuf>,
    reporter_control: Option<TcpStream>,
    exit_receiver: Option<mpsc::Receiver<Result<TcpStream, std::io::Error>>>,
    gate_receiver: Option<mpsc::Receiver<Result<TcpStream, std::io::Error>>>,
    raw_cleanup_authority: Option<Vec<u8>>,
    verifier_nonce: Digest,
    observation: Option<WindowsReporterExitObservation>,
    deadline: Instant,
    cleanup_deadline: Instant,
    stage: String,
    inject_finalizer_failure: bool,
    armed: bool,
}

#[cfg(windows)]
struct WindowsReporterConstructionFailure {
    primary: String,
    cleanup: Option<Result<(), String>>,
}

#[cfg(windows)]
impl From<String> for WindowsReporterConstructionFailure {
    fn from(primary: String) -> Self {
        Self {
            primary,
            cleanup: None,
        }
    }
}

#[cfg(windows)]
impl WindowsReporterConstructionFailure {
    fn into_detail(self) -> String {
        match self.cleanup {
            None | Some(Ok(())) => self.primary,
            Some(Err(cleanup)) => format!(
                "{}; additionally, launch cleanup failed: {cleanup}",
                self.primary
            ),
        }
    }
}

#[cfg(windows)]
impl WindowsReporterLaunchOwner {
    fn new(
        terminal: mpsc::Receiver<AttributedWorkerTerminal>,
        report_path: PathBuf,
        exit_receiver: mpsc::Receiver<Result<TcpStream, std::io::Error>>,
        gate_receiver: Option<mpsc::Receiver<Result<TcpStream, std::io::Error>>>,
        deadline: Instant,
        cleanup_deadline: Instant,
        stage: &str,
        verifier_nonce: Digest,
        inject_finalizer_failure: bool,
    ) -> Self {
        Self {
            terminal: Some(terminal),
            report_path: Some(report_path),
            reporter_control: None,
            exit_receiver: Some(exit_receiver),
            gate_receiver,
            raw_cleanup_authority: None,
            verifier_nonce,
            observation: None,
            deadline,
            cleanup_deadline,
            stage: stage.to_owned(),
            inject_finalizer_failure,
            armed: true,
        }
    }

    fn retain_reporter_control(&mut self, observer: TcpStream) {
        self.reporter_control = Some(observer);
    }

    fn retain_cleanup_authority(&mut self, receipt: Vec<u8>) {
        self.raw_cleanup_authority = Some(receipt);
    }

    fn promote_receipt(&mut self) -> Result<(), String> {
        if self.observation.is_some() {
            return Ok(());
        }
        let receipt = self
            .raw_cleanup_authority
            .as_deref()
            .ok_or_else(|| "Windows reporter cleanup authority is absent".to_owned())?;
        let (session_path, late_receipt_path, supervisor_pid, request_sha256, nonce, staged_root) =
            parse_windows_reporter_cleanup_authority(receipt, self.verifier_nonce)?;
        self.observation = Some(WindowsReporterExitObservation {
            report_path: self
                .report_path
                .take()
                .ok_or_else(|| "Windows reporter launch report ownership was lost".to_owned())?,
            session_path,
            late_receipt_path,
            late_receipt: None,
            initial_late_receipt: None,
            supervisor_pid,
            request_sha256,
            nonce,
            staged_root,
            terminal: self.terminal.take(),
            exit_receipt: None,
            exit_receiver: self.exit_receiver.take(),
            reporter_control: self.reporter_control.take(),
            gate_receiver: self.gate_receiver.take(),
            gate: None,
            payload_processes: None,
            reporter_exited: false,
            supervisor_exit_code: None,
            late_bytes: None,
            report_removed: false,
            finalized: false,
            deadline: self.deadline,
            cleanup_deadline: self.cleanup_deadline,
            stage: self.stage.clone(),
        });
        Ok(())
    }

    fn observation_mut(&mut self) -> Result<&mut WindowsReporterExitObservation, String> {
        self.observation
            .as_mut()
            .ok_or_else(|| "Windows reporter observation was not promoted".to_owned())
    }

    fn transfer_observation(&mut self) -> Result<WindowsReporterExitObservation, String> {
        let observation = self
            .observation
            .take()
            .ok_or_else(|| "Windows reporter observation was already transferred".to_owned())?;
        self.armed = false;
        Ok(observation)
    }

    fn finish_failure(&mut self, primary: String) -> WindowsReporterConstructionFailure {
        if self.observation.is_none() && self.raw_cleanup_authority.is_some() {
            let _ = self.promote_receipt();
        }
        if let Some(observation) = self.observation.as_mut() {
            let expectation = if self.stage == "payload-started" {
                WindowsReporterExitExpectation::PayloadTerminal
            } else if self.stage == "cleanup-committed" {
                WindowsReporterExitExpectation::Abnormal("committed-before-go-control-failed")
            } else {
                WindowsReporterExitExpectation::Abnormal("precommit-control-failed")
            };
            let mut cleanup = finalize_windows_reporter_observation(observation, expectation);
            if self.inject_finalizer_failure && cleanup.is_ok() {
                cleanup =
                    Err("injected Windows reporter construction finalizer failure".to_owned());
            }
            self.armed = false;
            return WindowsReporterConstructionFailure {
                primary,
                cleanup: Some(cleanup),
            };
        }
        drop(self.reporter_control.take());
        let cleanup = self.terminal.take().map_or_else(
            || Err("Windows reporter launch terminal ownership was lost".to_owned()),
            |terminal| match terminal
                .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
            {
                Ok(AttributedWorkerTerminal::Complete(_)) => Ok(()),
                Ok(AttributedWorkerTerminal::Panicked) => {
                    Err("Windows reporter launch cleanup panicked".to_owned())
                }
                Err(error) => Err(format!(
                    "Windows reporter launch cleanup exceeded its deadline: {error}"
                )),
            },
        );
        self.armed = false;
        WindowsReporterConstructionFailure {
            primary,
            cleanup: Some(cleanup),
        }
    }
}

#[cfg(windows)]
impl Drop for WindowsReporterLaunchOwner {
    fn drop(&mut self) {
        if self.armed {
            eprintln!("Windows reporter launch owner dropped before explicit finalization");
        }
    }
}

#[cfg(windows)]
impl Drop for WindowsReporterExitObservation {
    fn drop(&mut self) {
        if !self.finalized {
            eprintln!(
                "Windows reporter-exit owner for {} dropped before explicit finalization",
                self.stage
            );
        }
    }
}

#[cfg(windows)]
fn parse_windows_reporter_cleanup_authority(
    bytes: &[u8],
    verifier_nonce: Digest,
) -> Result<(PathBuf, PathBuf, u32, Digest, Digest, PathBuf), String> {
    let digest_width = Digest::default().0.len();
    if bytes.len() < 1 + digest_width * 2 {
        return Err("Windows reporter cleanup authority is truncated".to_owned());
    }
    let mut request_sha256 = Digest::default();
    request_sha256
        .0
        .copy_from_slice(&bytes[1..1 + digest_width]);
    let payload = windows_validate_frame(bytes, 15, request_sha256, verifier_nonce)?;
    let token = windows_supervisor_os_from_bytes(payload)?;
    let fields = hell_testkit::decode_windows_argv(&token)
        .map_err(|error| format!("cannot decode Windows reporter cleanup authority: {error}"))?;
    let [session, late, supervisor_pid, nonce, staged_root] = fields.as_slice() else {
        return Err("Windows reporter cleanup authority field count differs".to_owned());
    };
    let supervisor_pid = u32::try_from(windows_parse_u64(supervisor_pid, "supervisor pid")?)
        .map_err(|_| "Windows supervisor pid is too large".to_owned())?;
    if supervisor_pid == 0 {
        return Err("Windows supervisor pid is zero".to_owned());
    }
    let nonce = Digest::from_hex(
        nonce
            .to_str()
            .ok_or_else(|| "Windows reporter supervisor nonce is not UTF-8".to_owned())?,
    )
    .map_err(|error| format!("Windows reporter supervisor nonce is invalid: {error}"))?;
    Ok((
        PathBuf::from(session),
        PathBuf::from(late),
        supervisor_pid,
        request_sha256,
        nonce,
        PathBuf::from(staged_root),
    ))
}

#[cfg(windows)]
fn parse_windows_reporter_fixture_receipt(
    bytes: &[u8],
) -> Result<(PathBuf, PathBuf, u32, Digest, Digest, PathBuf), String> {
    let token = windows_supervisor_os_from_bytes(bytes)?;
    let fields = hell_testkit::decode_windows_argv(&token)
        .map_err(|error| format!("cannot decode Windows reporter receipt: {error}"))?;
    let [
        session,
        late,
        supervisor_pid,
        request_sha256,
        nonce,
        _started,
        staged_root,
    ] = fields.as_slice()
    else {
        return Err("Windows reporter receipt field count differs".to_owned());
    };
    let supervisor_pid = u32::try_from(windows_parse_u64(supervisor_pid, "supervisor pid")?)
        .map_err(|_| "Windows supervisor pid is too large".to_owned())?;
    if supervisor_pid == 0 {
        return Err("Windows supervisor pid is zero".to_owned());
    }
    let parse_digest = |value: &std::ffi::OsStr, label: &str| {
        Digest::from_hex(
            value
                .to_str()
                .ok_or_else(|| format!("Windows reporter {label} is not UTF-8"))?,
        )
        .map_err(|error| format!("Windows reporter {label} is invalid: {error}"))
    };
    Ok((
        PathBuf::from(session),
        PathBuf::from(late),
        supervisor_pid,
        parse_digest(request_sha256, "request digest")?,
        parse_digest(nonce, "nonce")?,
        PathBuf::from(staged_root),
    ))
}

#[cfg(windows)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum WindowsReporterConstructionInjection {
    None,
    BeforeParse,
    MalformedParse,
    MalformedParseFinalizerFailure,
    AfterParse,
    AfterSidecarBind,
    AfterExitAccept,
    PanicAfterParse,
    PanicAfterSidecarBind,
    PanicAfterExitAccept,
}

#[cfg(windows)]
impl WindowsReporterConstructionInjection {
    fn detail(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::BeforeParse => "before receipt parse",
            Self::MalformedParse => "during malformed receipt parse",
            Self::MalformedParseFinalizerFailure => "during malformed receipt parse",
            Self::AfterParse => "after receipt parse",
            Self::AfterSidecarBind => "after sidecar bind",
            Self::AfterExitAccept => "after exit accept",
            Self::PanicAfterParse => "panic after receipt parse",
            Self::PanicAfterSidecarBind => "panic after sidecar bind",
            Self::PanicAfterExitAccept => "panic after exit accept",
        }
    }
}

#[cfg(windows)]
fn start_windows_reporter_exit_observation_typed(
    root: &Path,
    session_parent: &Path,
    deadline: Instant,
    cleanup_deadline: Instant,
    stage: &str,
    authority_root: &Path,
    injection: WindowsReporterConstructionInjection,
) -> Result<WindowsReporterExitObservation, WindowsReporterConstructionFailure> {
    if deadline >= cleanup_deadline
        || cleanup_deadline.saturating_duration_since(deadline) < NIGHTLY_SUPERVISOR_START_TIMEOUT
        || Instant::now() >= deadline
    {
        return Err("Windows reporter execution deadline expired before launch"
            .to_owned()
            .into());
    }
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| format!("cannot allocate Windows reporter-exit nonce: {error}"))?;
    let verifier_nonce = sha256_bytes(&nonce);
    let report_path = session_parent.join(format!(
        "nightly-supervisor-{stage}-{}.json",
        verifier_nonce.hex()
    ));
    match fs::symlink_metadata(&report_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err("Windows reporter-exit report candidate already exists"
                .to_owned()
                .into());
        }
        Err(error) => {
            return Err(
                format!("cannot inspect Windows reporter-exit report candidate: {error}").into(),
            );
        }
    }
    let observer = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| format!("cannot bind Windows reporter-exit observer: {error}"))?;
    let observer_address = observer
        .local_addr()
        .map_err(|error| format!("cannot inspect Windows reporter-exit observer: {error}"))?;
    let std::net::SocketAddr::V4(observer_address) = observer_address else {
        return Err("Windows reporter-exit observer is not IPv4"
            .to_owned()
            .into());
    };
    let observer_receiver = submit_external_supervisor_accept(observer)?;
    let gate = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| format!("cannot bind Windows reporter-exit gate: {error}"))?;
    let gate_address = gate
        .local_addr()
        .map_err(|error| format!("cannot inspect Windows reporter-exit gate: {error}"))?;
    let std::net::SocketAddr::V4(gate_address) = gate_address else {
        return Err("Windows reporter-exit gate is not IPv4".to_owned().into());
    };
    let gate_receiver = (stage == "payload-started")
        .then(|| submit_external_supervisor_accept(gate))
        .transpose()?;
    let exit_observer = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| format!("cannot bind Windows supervisor exit observer: {error}"))?;
    let exit_observer_address = exit_observer
        .local_addr()
        .map_err(|error| format!("cannot inspect Windows supervisor exit observer: {error}"))?;
    let std::net::SocketAddr::V4(exit_observer_address) = exit_observer_address else {
        return Err("Windows supervisor exit observer is not IPv4"
            .to_owned()
            .into());
    };
    let exit_observer_receiver = submit_external_supervisor_accept(exit_observer)?;
    let executable = fs::canonicalize(
        std::env::current_exe()
            .map_err(|error| format!("cannot locate Windows reporter-exit verifier: {error}"))?,
    )
    .map_err(|error| format!("cannot canonicalize Windows reporter-exit verifier: {error}"))?;
    let malformed_semantic = matches!(
        injection,
        WindowsReporterConstructionInjection::MalformedParse
            | WindowsReporterConstructionInjection::MalformedParseFinalizerFailure
    );
    let fixture_stage = if malformed_semantic {
        "authority-imported-malformed-receipt"
    } else {
        stage
    };
    let encoded_remaining_millis = |cutoff: Instant| {
        u64::try_from(
            cutoff
                .saturating_duration_since(Instant::now())
                .saturating_sub(NIGHTLY_SUPERVISOR_START_TIMEOUT)
                .as_millis(),
        )
        .unwrap_or(u64::MAX)
        .to_string()
    };
    let spec = CommandSpec::new(
        executable,
        deadline.saturating_duration_since(Instant::now()),
    )
    .arguments([
        std::ffi::OsString::from("__nightly-supervisor-reporter-fixture"),
        root.as_os_str().to_owned(),
        session_parent.as_os_str().to_owned(),
        report_path.as_os_str().to_owned(),
        std::ffi::OsString::from(observer_address.ip().to_string()),
        std::ffi::OsString::from(observer_address.port().to_string()),
        std::ffi::OsString::from(gate_address.ip().to_string()),
        std::ffi::OsString::from(gate_address.port().to_string()),
        std::ffi::OsString::from(exit_observer_address.ip().to_string()),
        std::ffi::OsString::from(exit_observer_address.port().to_string()),
        std::ffi::OsString::from(fixture_stage),
        std::ffi::OsString::from(WindowsReporterAuthorityMode::SealedFixture.token()),
        authority_root.as_os_str().to_owned(),
        std::ffi::OsString::from(encoded_remaining_millis(deadline)),
        std::ffi::OsString::from(encoded_remaining_millis(cleanup_deadline)),
        std::ffi::OsString::from(verifier_nonce.hex()),
    ])
    .current_directory(root);
    let worker = attributed_worker_sender()?;
    let permit = PortabilityWorkerPermit::acquire()?;
    let receipt = AttributedWorkerReceipt::new(permit.id);
    let (progress, _progress_receiver) =
        SupervisedProgressObserver::bounded(PORTABILITY_PROGRESS_QUEUE_CAPACITY);
    let (terminal, terminal_receiver) = mpsc::sync_channel(1);
    let worker_completion_deadline = cleanup_deadline
        .checked_sub(NIGHTLY_SUPERVISOR_START_TIMEOUT)
        .unwrap_or(deadline)
        .max(deadline);
    worker
        .send(AttributedWorkerTask {
            spec,
            execution_deadline: deadline,
            child_completion_deadline: worker_completion_deadline,
            progress,
            terminal,
            receipt,
            permit,
        })
        .map_err(|_| "Windows reporter-exit executor disconnected".to_owned())?;
    let mut launch_owner = WindowsReporterLaunchOwner::new(
        terminal_receiver,
        report_path,
        exit_observer_receiver,
        gate_receiver,
        deadline,
        cleanup_deadline,
        stage,
        verifier_nonce,
        injection == WindowsReporterConstructionInjection::MalformedParseFinalizerFailure,
    );
    let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let observer = observer_receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|error| format!("Windows reporter-exit observer exceeded deadline: {error}"))?
            .map_err(|error| format!("cannot accept Windows reporter-exit observer: {error}"))?;
        observer
            .set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))
            .map_err(|error| format!("cannot bound Windows reporter fixture receipt: {error}"))?;
        launch_owner.retain_reporter_control(observer);
        let cleanup_authority = windows_read_inherited_frame(
            launch_owner
                .reporter_control
                .as_mut()
                .ok_or_else(|| "Windows reporter control ownership was lost".to_owned())?,
        )?
        .ok_or_else(|| "Windows reporter exited before its cleanup authority".to_owned())?;
        launch_owner.retain_cleanup_authority(cleanup_authority);
        launch_owner.promote_receipt()?;
        if injection == WindowsReporterConstructionInjection::BeforeParse {
            return Err(format!(
                "injected Windows reporter construction failure {}",
                injection.detail()
            ));
        }
        let semantic_receipt = windows_read_inherited_frame(
            launch_owner
                .observation_mut()?
                .reporter_control
                .as_mut()
                .ok_or_else(|| "Windows reporter control ownership was lost".to_owned())?,
        )?
        .ok_or_else(|| "Windows reporter exited before its semantic fixture receipt".to_owned())?;
        let semantic = parse_windows_reporter_fixture_receipt(&semantic_receipt);
        if malformed_semantic {
            let malformed =
                semantic.expect_err("malformed Windows reporter semantic receipt must be rejected");
            return Err(format!(
                "injected Windows reporter construction failure {}: {malformed}",
                injection.detail()
            ));
        }
        let (session, late, supervisor_pid, request_sha256, nonce, staged_root) = semantic?;
        let observed = launch_owner.observation_mut()?;
        if session != observed.session_path
            || late != observed.late_receipt_path
            || supervisor_pid != observed.supervisor_pid
            || request_sha256 != observed.request_sha256
            || nonce != observed.nonce
            || staged_root != observed.staged_root
        {
            return Err(
                "Windows reporter semantic receipt differs from cleanup authority".to_owned(),
            );
        }
        if injection == WindowsReporterConstructionInjection::PanicAfterParse {
            panic!("injected Windows reporter construction panic after receipt parse");
        }
        if injection == WindowsReporterConstructionInjection::AfterParse {
            return Err(format!(
                "injected Windows reporter construction failure {}",
                injection.detail()
            ));
        }
        launch_owner.observation_mut()?.bind_late_receipt()?;
        if injection == WindowsReporterConstructionInjection::PanicAfterSidecarBind {
            panic!("injected Windows reporter construction panic after sidecar bind");
        }
        if injection == WindowsReporterConstructionInjection::AfterSidecarBind {
            return Err(format!(
                "injected Windows reporter construction failure {}",
                injection.detail()
            ));
        }
        launch_owner.observation_mut()?.bind_exit_receipt()?;
        if injection == WindowsReporterConstructionInjection::PanicAfterExitAccept {
            panic!("injected Windows reporter construction panic after exit accept");
        }
        if injection == WindowsReporterConstructionInjection::AfterExitAccept {
            return Err(format!(
                "injected Windows reporter construction failure {}",
                injection.detail()
            ));
        }
        launch_owner.transfer_observation()
    }))
    .unwrap_or_else(|_| Err("Windows reporter observation construction panicked".to_owned()));
    match observed {
        Ok(observed) => Ok(observed),
        Err(primary) => Err(launch_owner.finish_failure(primary)),
    }
}

#[cfg(windows)]
fn start_windows_reporter_exit_observation(
    root: &Path,
    session_parent: &Path,
    deadline: Instant,
    cleanup_deadline: Instant,
    stage: &str,
    authority_root: &Path,
    injection: WindowsReporterConstructionInjection,
) -> Result<WindowsReporterExitObservation, String> {
    start_windows_reporter_exit_observation_typed(
        root,
        session_parent,
        deadline,
        cleanup_deadline,
        stage,
        authority_root,
        injection,
    )
    .map_err(WindowsReporterConstructionFailure::into_detail)
}

#[cfg(windows)]
fn await_windows_reporter_supervisor_exit(
    observed: &mut WindowsReporterExitObservation,
) -> Result<u32, String> {
    if let Some(exit_code) = observed.supervisor_exit_code {
        return Ok(exit_code);
    }
    observed.bind_exit_receipt()?;
    let exit_timeout = observed
        .completion_deadline()
        .saturating_duration_since(Instant::now());
    if exit_timeout.is_zero() {
        return Err("Windows supervisor exit receipt exceeded its deadline".to_owned());
    }
    let exit_receipt = observed
        .exit_receipt
        .as_mut()
        .ok_or_else(|| "Windows supervisor exit channel ownership was lost".to_owned())?;
    exit_receipt
        .set_read_timeout(Some(exit_timeout))
        .map_err(|error| format!("cannot bound Windows supervisor exact exit: {error}"))?;
    let frame = windows_read_inherited_frame(exit_receipt)?
        .ok_or_else(|| "Windows supervisor exited without its exact exit receipt".to_owned())?;
    let payload = windows_validate_frame(&frame, 14, observed.request_sha256, observed.nonce)?;
    if payload.len() != size_of::<u32>() * 2 {
        return Err("Windows supervisor exit receipt field count differs".to_owned());
    }
    let process_id = u32::from_be_bytes(
        payload[..size_of::<u32>()]
            .try_into()
            .map_err(|_| "Windows supervisor exit process width differs".to_owned())?,
    );
    let exit_code = u32::from_be_bytes(
        payload[size_of::<u32>()..]
            .try_into()
            .map_err(|_| "Windows supervisor exit code width differs".to_owned())?,
    );
    if process_id != observed.supervisor_pid {
        return Err("Windows supervisor exit receipt process identity differs".to_owned());
    }
    let mut tail = Vec::new();
    exit_receipt
        .read_to_end(&mut tail)
        .map_err(|error| format!("cannot attest exact Windows supervisor exit: {error}"))?;
    if !tail.is_empty() {
        return Err("Windows supervisor emitted bytes after its exact exit receipt".to_owned());
    }
    observed.supervisor_exit_code = Some(exit_code);
    Ok(exit_code)
}

#[cfg(windows)]
fn read_windows_reporter_late_receipt(
    observed: &mut WindowsReporterExitObservation,
) -> Result<Vec<u8>, String> {
    if let Some(bytes) = &observed.late_bytes {
        return Ok(bytes.clone());
    }
    observed.bind_late_receipt()?;
    let retained = observed
        .late_receipt
        .as_ref()
        .ok_or_else(|| "Windows reporter late receipt was already released".to_owned())?;
    let mut file = observed
        .late_receipt
        .as_ref()
        .ok_or_else(|| "Windows reporter late receipt was already released".to_owned())?
        .try_clone()
        .map_err(|error| format!("cannot clone Windows reporter late receipt: {error}"))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("cannot rewind Windows reporter late receipt: {error}"))?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(NIGHTLY_SUPERVISOR_TERMINAL_LIMIT).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read Windows reporter late receipt: {error}"))?;
    let initial = observed
        .initial_late_receipt
        .ok_or_else(|| "Windows reporter late receipt identity was not bound".to_owned())?;
    let final_receipt = WindowsFileReceipt {
        size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        ..initial
    };
    if bytes.is_empty()
        || bytes.len() > NIGHTLY_SUPERVISOR_TERMINAL_LIMIT
        || windows_file_receipt(retained)? != final_receipt
        || windows_bind_shared_late_receipt(&observed.late_receipt_path)?.1 != final_receipt
    {
        return Err("Windows reporter late receipt is incomplete or changed".to_owned());
    }
    observed.late_bytes = Some(bytes.clone());
    Ok(bytes)
}

#[cfg(windows)]
#[derive(Clone, Copy)]
enum WindowsReporterExitExpectation<'a> {
    Abnormal(&'a str),
    PayloadTerminal,
}

#[cfg(windows)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum WindowsReporterFailureInjection {
    None,
    AfterReceipt,
    AfterSidecarBind,
    AfterExitAccept,
}

#[cfg(windows)]
impl WindowsReporterFailureInjection {
    fn active(self) -> bool {
        self != Self::None
    }

    fn detail(self, stage: &str) -> String {
        let boundary = match self {
            Self::None => "none",
            Self::AfterReceipt => "receipt",
            Self::AfterSidecarBind => "sidecar-bind",
            Self::AfterExitAccept => "exit-accept",
        };
        format!("injected Windows {stage} verifier failure after {boundary}")
    }
}

#[cfg(windows)]
impl WindowsReporterExitObservation {
    fn completion_deadline(&self) -> Instant {
        self.cleanup_deadline
            .checked_sub(NIGHTLY_SUPERVISOR_START_TIMEOUT)
            .unwrap_or(self.deadline)
            .max(self.deadline)
    }

    fn bind_late_receipt(&mut self) -> Result<(), String> {
        if self.late_receipt.is_some() {
            return Ok(());
        }
        let (file, receipt) = windows_bind_shared_late_receipt(&self.late_receipt_path)?;
        if receipt.size != 0 || windows_file_receipt(&file)? != receipt {
            return Err("Windows reporter late receipt was not empty at handoff".to_owned());
        }
        self.late_receipt = Some(file);
        self.initial_late_receipt = Some(receipt);
        Ok(())
    }

    fn bind_exit_receipt(&mut self) -> Result<(), String> {
        if self.exit_receipt.is_some() {
            return Ok(());
        }
        let receiver = self
            .exit_receiver
            .as_ref()
            .ok_or_else(|| "Windows supervisor exit channel ownership was lost".to_owned())?;
        let remaining = self
            .completion_deadline()
            .saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("Windows supervisor exit receipt exceeded its deadline".to_owned());
        }
        let receipt = receiver
            .recv_timeout(remaining)
            .map_err(|error| format!("Windows supervisor exit receipt exceeded deadline: {error}"))?
            .map_err(|error| format!("cannot accept Windows supervisor exit receipt: {error}"))?;
        self.exit_receiver = None;
        receipt
            .set_read_timeout(Some(remaining))
            .map_err(|error| format!("cannot bound Windows supervisor exit receipt: {error}"))?;
        self.exit_receipt = Some(receipt);
        Ok(())
    }

    fn release_reporter(&mut self) -> Result<(), String> {
        let Some(mut control) = self.reporter_control.take() else {
            return Ok(());
        };
        let remaining = self
            .completion_deadline()
            .saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("Windows reporter release exceeded its deadline".to_owned());
        }
        control
            .set_write_timeout(Some(remaining))
            .map_err(|error| format!("cannot bound Windows reporter release: {error}"))?;
        write_supervisor_handshake(
            &mut control,
            ExternalSupervisorMessage::Go,
            self.request_sha256,
            self.nonce,
        )
    }

    fn receive_payload_gate(&mut self) -> Result<(), String> {
        if self.gate.is_some() {
            return Ok(());
        }
        let Some(receiver) = self.gate_receiver.as_ref() else {
            return Ok(());
        };
        let remaining = self
            .completion_deadline()
            .saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("Windows payload gate exceeded its deadline".to_owned());
        }
        let gate = receiver
            .recv_timeout(remaining)
            .map_err(|error| format!("Windows payload gate exceeded its deadline: {error}"))?
            .map_err(|error| format!("cannot accept Windows payload gate: {error}"))?;
        self.gate_receiver = None;
        gate.set_read_timeout(Some(remaining))
            .map_err(|error| format!("cannot bound Windows payload gate: {error}"))?;
        self.gate = Some(gate);
        let gate = self
            .gate
            .as_mut()
            .ok_or_else(|| "Windows payload gate ownership was lost".to_owned())?;
        read_supervisor_handshake(
            gate,
            ExternalSupervisorMessage::Started,
            self.request_sha256,
            self.nonce,
        )?;
        let mut process_ids = [0_u8; size_of::<u32>() * 2];
        gate.read_exact(&mut process_ids)
            .map_err(|error| format!("cannot read Windows payload process ids: {error}"))?;
        let leader = u32::from_be_bytes(
            process_ids[..size_of::<u32>()]
                .try_into()
                .map_err(|_| "Windows payload leader receipt width differs".to_owned())?,
        );
        let descendant = u32::from_be_bytes(
            process_ids[size_of::<u32>()..]
                .try_into()
                .map_err(|_| "Windows payload descendant receipt width differs".to_owned())?,
        );
        if leader == 0 || descendant == 0 || leader == descendant {
            return Err("Windows payload process receipt differs".to_owned());
        }
        self.payload_processes = Some((leader, descendant));
        let mut restricted = [0_u8; 12];
        gate.read_exact(&mut restricted)
            .map_err(|error| format!("cannot read Windows payload token receipt: {error}"))?;
        if restricted != [1; 12] {
            return Err(
                "Windows payload token, privilege, session mutation, or writable-target receipt differs"
                    .to_owned(),
            );
        }
        Ok(())
    }

    fn release_payload_gate(&mut self) -> Result<(), String> {
        let Some(mut gate) = self.gate.take() else {
            return Ok(());
        };
        let remaining = self
            .completion_deadline()
            .saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("Windows payload gate release exceeded its deadline".to_owned());
        }
        gate.set_read_timeout(Some(remaining))
            .map_err(|error| format!("cannot bound Windows payload gate release: {error}"))?;
        gate.set_write_timeout(Some(remaining))
            .map_err(|error| format!("cannot bound Windows payload gate write: {error}"))?;
        let primary = write_supervisor_handshake(
            &mut gate,
            ExternalSupervisorMessage::Go,
            self.request_sha256,
            self.nonce,
        );
        let mut tail = Vec::new();
        let closure = gate
            .read_to_end(&mut tail)
            .map_err(|error| format!("cannot attest Windows payload gate closure: {error}"))
            .and_then(|_| {
                if tail.is_empty() {
                    Ok(())
                } else {
                    Err("Windows payload gate has unexpected trailing data".to_owned())
                }
            });
        compose_windows_reporter_fixture_results(primary, closure)
    }

    fn wait_reporter_until(&mut self, deadline: Instant) -> Result<(), String> {
        if self.reporter_exited {
            return Ok(());
        }
        let terminal = self
            .terminal
            .as_ref()
            .ok_or_else(|| "Windows reporter terminal ownership was lost".to_owned())?;
        let result = match terminal
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|error| {
                format!(
                    "Windows {} reporter exit exceeded deadline: {error}",
                    self.stage
                )
            })? {
            AttributedWorkerTerminal::Complete(Ok(result))
                if result.status.success() && !result.timed_out =>
            {
                Ok(())
            }
            AttributedWorkerTerminal::Complete(_) => {
                Err(format!("Windows {} reporter fixture failed", self.stage))
            }
            AttributedWorkerTerminal::Panicked => {
                Err(format!("Windows {} reporter fixture panicked", self.stage))
            }
        };
        self.terminal = None;
        self.reporter_exited = true;
        result
    }

    fn verify_and_remove_report(&mut self) -> Result<(), String> {
        if self.report_removed {
            return Ok(());
        }
        let primary = (|| {
            let (mut report, receipt) = windows_bind_path(&self.report_path, false)?;
            let mut bytes = Vec::new();
            report
                .read_to_end(&mut bytes)
                .map_err(|error| format!("cannot read Windows {} report: {error}", self.stage))?;
            verify_windows_supervisor_report(
                &bytes,
                &self.session_path,
                self.supervisor_pid,
                self.request_sha256,
                self.stage != "authority-imported",
            )?;
            if windows_file_receipt(&report)? != receipt {
                return Err(format!("Windows {} report identity changed", self.stage));
            }
            Ok(())
        })();
        let cleanup = fs::remove_file(&self.report_path)
            .map_err(|error| format!("cannot remove Windows {} report: {error}", self.stage))
            .and_then(|()| match fs::symlink_metadata(&self.report_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(format!(
                    "cannot attest Windows {} report absence: {error}",
                    self.stage
                )),
                Ok(_) => Err(format!("Windows {} report remains", self.stage)),
            });
        if cleanup.is_ok() {
            self.report_removed = true;
        }
        compose_windows_reporter_fixture_results(primary, cleanup)
    }

    fn attest_absence(&self) -> Result<(), String> {
        require_windows_process_absent(self.supervisor_pid, self.cleanup_deadline)?;
        if let Some((leader, descendant)) = self.payload_processes {
            require_windows_process_absent(leader, self.cleanup_deadline)?;
            require_windows_process_absent(descendant, self.cleanup_deadline)?;
        }
        loop {
            match fs::symlink_metadata(&self.session_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(error) => {
                    return Err(format!(
                        "cannot attest Windows {} session: {error}",
                        self.stage
                    ));
                }
                Ok(_) if Instant::now() < self.cleanup_deadline => std::thread::yield_now(),
                Ok(_) => return Err(format!("Windows {} session remains", self.stage)),
            }
        }
        Ok(())
    }

    fn validate_late_receipt(
        &mut self,
        expectation: WindowsReporterExitExpectation<'_>,
    ) -> Result<(), String> {
        let exit_code = await_windows_reporter_supervisor_exit(self)?;
        let late = read_windows_reporter_late_receipt(self)?;
        match expectation {
            WindowsReporterExitExpectation::Abnormal(expected) => {
                if exit_code == 0 {
                    return Err(format!(
                        "Windows {} supervisor falsely reported a successful pre-Go exit",
                        self.stage
                    ));
                }
                let detail =
                    decode_windows_supervisor_abnormal(&late, self.request_sha256, self.nonce)?;
                if !detail.contains(expected) {
                    return Err(format!(
                        "Windows {} late receipt differs: {detail}",
                        self.stage
                    ));
                }
            }
            WindowsReporterExitExpectation::PayloadTerminal => {
                if exit_code != 0 {
                    return Err(format!(
                        "Windows payload supervisor exited with code {exit_code}"
                    ));
                }
                let terminal =
                    decode_external_supervisor_terminal(&late, self.request_sha256, self.nonce)?;
                if !terminal.execution.success
                    || !terminal.cleanup.terminal
                    || !terminal.capture.available
                    || !terminal.cleanup.leader_reaped
                    || terminal.cleanup_state != "completed"
                    || !terminal.cleanup_failures.is_empty()
                    || terminal.dropped_chunks == 0
                    || terminal.attribution.case_state.as_deref() != Some("completed")
                    || terminal.attribution.target.as_deref() != Some("windows-staged-cargo")
                {
                    return Err(format!(
                        "Windows supervisor terminal receipt differs: {}",
                        terminal.detail
                    ));
                }
            }
        }
        Ok(())
    }

    fn cleanup_late_receipt(&mut self) -> Result<(), String> {
        let binding = self.bind_late_receipt();
        let parent = self
            .late_receipt_path
            .parent()
            .ok_or_else(|| "Windows late receipt has no parent".to_owned())?;
        let (parent_guard, parent_receipt) = windows_bind_path(parent, true)?;
        let primary = run_windows_supervisor_icacls(
            &self.late_receipt_path,
            &["/reset"],
            self.cleanup_deadline,
        );
        let identity = (|| {
            let retained = self
                .late_receipt
                .as_ref()
                .ok_or_else(|| "Windows reporter late receipt ownership was lost".to_owned())?;
            let observed = windows_file_receipt(retained)?;
            let initial = self
                .initial_late_receipt
                .ok_or_else(|| "Windows reporter late receipt identity was not bound".to_owned())?;
            if observed.volume != initial.volume
                || observed.index != initial.index
                || observed.attributes != initial.attributes
                || observed.size
                    > u64::try_from(NIGHTLY_SUPERVISOR_TERMINAL_LIMIT).unwrap_or(u64::MAX)
                || windows_bind_shared_late_receipt(&self.late_receipt_path)?.1 != observed
            {
                return Err("Windows late receipt changed before verifier cleanup".to_owned());
            }
            Ok(())
        })();
        drop(self.late_receipt.take());
        let removal = fs::remove_file(&self.late_receipt_path)
            .map_err(|error| format!("cannot remove Windows late receipt: {error}"))
            .and_then(|()| {
                if Instant::now() >= self.cleanup_deadline
                    || windows_file_receipt(&parent_guard)? != parent_receipt
                    || windows_bind_path(parent, true)?.1 != parent_receipt
                {
                    return Err(
                        "Windows late receipt parent changed during verifier cleanup".to_owned(),
                    );
                }
                match fs::symlink_metadata(&self.late_receipt_path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(format!(
                        "cannot attest Windows late receipt absence: {error}"
                    )),
                    Ok(_) => Err("Windows late receipt remains after verifier cleanup".to_owned()),
                }
            });
        compose_windows_reporter_fixture_results(
            compose_windows_reporter_fixture_results(
                compose_windows_reporter_fixture_results(binding, primary),
                identity,
            ),
            removal,
        )
    }

    fn finalize(&mut self, expectation: WindowsReporterExitExpectation<'_>) -> Result<(), String> {
        let mut failures = Vec::new();
        let completion_deadline = self.completion_deadline();
        for result in [
            self.bind_late_receipt(),
            self.bind_exit_receipt(),
            self.release_reporter(),
            self.receive_payload_gate(),
            self.release_payload_gate(),
            self.wait_reporter_until(completion_deadline),
            self.verify_and_remove_report(),
            self.validate_late_receipt(expectation),
            self.cleanup_late_receipt(),
            self.attest_absence(),
        ] {
            if let Err(error) = result {
                failures.push(error);
            }
        }
        self.finalized = true;
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; additionally, "))
        }
    }
}

#[cfg(windows)]
fn compose_windows_reporter_fixture_results(
    primary: Result<(), String>,
    cleanup: Result<(), String>,
) -> Result<(), String> {
    match (primary, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(format!(
            "{primary}; additionally, cleanup failed: {cleanup}"
        )),
    }
}

#[cfg(windows)]
fn finish_windows_reporter_fixture(
    primary: Result<(), String>,
    cleanup: Result<(), String>,
    injection: WindowsReporterFailureInjection,
    stage: &str,
) -> Result<(), String> {
    if !injection.active() {
        return compose_windows_reporter_fixture_results(primary, cleanup);
    }
    match primary {
        Err(error) if error == injection.detail(stage) => cleanup,
        Err(error) => Err(format!("Windows {stage} injection differed: {error}")),
        Ok(()) => Err(format!(
            "Windows {stage} verifier did not exercise its injected failure"
        )),
    }
}

#[cfg(windows)]
fn windows_reporter_primary<F>(operation: F) -> Result<(), String>
where
    F: FnOnce() -> Result<(), String>,
{
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
        .unwrap_or_else(|_| Err("Windows reporter verifier panicked".to_owned()))
}

#[cfg(windows)]
fn inject_windows_reporter_failure(
    observed: &mut WindowsReporterExitObservation,
    injection: WindowsReporterFailureInjection,
    stage: &str,
) -> Result<(), String> {
    match injection {
        WindowsReporterFailureInjection::None => Ok(()),
        WindowsReporterFailureInjection::AfterReceipt => Err(injection.detail(stage)),
        WindowsReporterFailureInjection::AfterSidecarBind => {
            observed.bind_late_receipt()?;
            Err(injection.detail(stage))
        }
        WindowsReporterFailureInjection::AfterExitAccept => {
            observed.bind_late_receipt()?;
            observed.bind_exit_receipt()?;
            Err(injection.detail(stage))
        }
    }
}

#[cfg(windows)]
fn finalize_windows_reporter_observation(
    observed: &mut WindowsReporterExitObservation,
    expectation: WindowsReporterExitExpectation<'_>,
) -> Result<(), String> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        observed.finalize(expectation)
    })) {
        Ok(result) => result,
        Err(_) => {
            let retry = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                observed.finalize(expectation)
            }))
            .unwrap_or_else(|_| Err("Windows reporter finalizer panicked repeatedly".to_owned()));
            compose_windows_reporter_fixture_results(
                Err("Windows reporter finalizer panicked".to_owned()),
                retry,
            )
        }
    }
}

#[cfg(windows)]
fn verify_windows_reporter_exit_before_go(
    root: &Path,
    session_parent: &Path,
    deadline: Instant,
    cleanup_deadline: Instant,
    stage: &str,
    expected_detail: &str,
    injection: WindowsReporterFailureInjection,
    construction_injection: WindowsReporterConstructionInjection,
) -> Result<(), String> {
    let mut authority =
        WindowsReporterFixtureAuthority::create_until(session_parent, deadline, cleanup_deadline)?;
    let mut observed = match start_windows_reporter_exit_observation(
        root,
        session_parent,
        deadline,
        cleanup_deadline,
        stage,
        authority.staged_root(),
        construction_injection,
    ) {
        Ok(observed) => observed,
        Err(primary) => {
            let cleanup = authority.finish_until(cleanup_deadline);
            return compose_windows_reporter_fixture_results(Err(primary), cleanup);
        }
    };
    if stage == "cleanup-committed" {
        authority.commit_cleanup_transfer();
    }
    let primary = windows_reporter_primary(|| {
        inject_windows_reporter_failure(&mut observed, injection, stage)?;
        observed.release_reporter()?;
        let deadline = observed.deadline;
        observed.wait_reporter_until(deadline)?;
        observed.verify_and_remove_report()
    });
    let cleanup = finalize_windows_reporter_observation(
        &mut observed,
        WindowsReporterExitExpectation::Abnormal(expected_detail),
    );
    let result = finish_windows_reporter_fixture(primary, cleanup, injection, stage);
    let authority = authority.finish_until(cleanup_deadline);
    compose_windows_reporter_fixture_results(result, authority)
}

#[cfg(windows)]
fn verify_windows_two_hop_deadline_debit() -> Result<(), String> {
    let total = Duration::from_secs(180);
    let first_transit = Duration::from_secs(25);
    let second_launch = Duration::from_secs(25);
    let second_transit = Duration::from_secs(25);
    let main_deadline = first_transit
        .checked_add(total.saturating_sub(NIGHTLY_SUPERVISOR_START_TIMEOUT))
        .ok_or_else(|| "Windows two-hop main deadline overflowed".to_owned())?;
    let main_hard_exit = main_deadline
        .checked_sub(
            NIGHTLY_SUPERVISOR_START_TIMEOUT
                .checked_mul(2)
                .ok_or_else(|| "Windows two-hop hard-exit reserve overflowed".to_owned())?,
        )
        .ok_or_else(|| "Windows two-hop hard-exit deadline underflowed".to_owned())?;
    let successor_start = first_transit
        .checked_add(second_launch)
        .ok_or_else(|| "Windows two-hop successor start overflowed".to_owned())?;
    let successor_remaining = main_deadline
        .saturating_sub(successor_start)
        .saturating_sub(NIGHTLY_SUPERVISOR_START_TIMEOUT);
    let successor_deadline = successor_start
        .checked_add(second_transit)
        .and_then(|received| received.checked_add(successor_remaining))
        .ok_or_else(|| "Windows two-hop successor deadline overflowed".to_owned())?;
    if main_deadline > total || successor_deadline > total || successor_deadline <= main_hard_exit {
        return Err(
            "Windows two-hop deadline debit inflated or exhausted cleanup reserve".to_owned(),
        );
    }
    Ok(())
}

#[cfg(windows)]
fn start_windows_cleanup_exit_fixture(
    mode: &str,
    deadline: Instant,
) -> Result<WindowsAuthorityCleanupSuccessor, String> {
    if Instant::now() >= deadline {
        return Err("Windows cleanup-exit fixture deadline expired before launch".to_owned());
    }
    let executable = fs::canonicalize(
        std::env::current_exe()
            .map_err(|error| format!("cannot locate Windows cleanup-exit fixture: {error}"))?,
    )
    .map_err(|error| format!("cannot canonicalize Windows cleanup-exit fixture: {error}"))?;
    let mut launch = spawn_windows_pipe_supervisor(&executable, "windows-cleanup-exit-fixture-v1")?;
    let mut nonce_bytes = [0_u8; 16];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|error| format!("cannot allocate Windows cleanup-exit nonce: {error}"))?;
    let request_sha256 = sha256_bytes(mode.as_bytes());
    let nonce = sha256_bytes(&nonce_bytes);
    let token = hell_testkit::encode_windows_argv(&[
        std::ffi::OsString::from(mode),
        std::ffi::OsString::from(request_sha256.hex()),
        std::ffi::OsString::from(nonce.hex()),
    ])
    .map_err(|error| format!("cannot encode Windows cleanup-exit fixture: {error}"))?;
    windows_write_inherited_frame(&mut launch.control, &windows_supervisor_os_bytes(&token))?;
    let ready = launch
        .observations
        .recv_timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(NIGHTLY_SUPERVISOR_START_TIMEOUT),
        )
        .map_err(|error| format!("Windows cleanup-exit fixture Ready timed out: {error}"))??;
    windows_validate_frame(&ready, 1, request_sha256, nonce)?;
    Ok(WindowsAuthorityCleanupSuccessor {
        child: launch.child,
        control: launch.control,
        observations: launch.observations,
        request_sha256,
        nonce,
    })
}

#[cfg(windows)]
fn verify_windows_cleanup_successor_exit_receipt(deadline: Instant) -> Result<(), String> {
    let mut held = start_windows_cleanup_exit_fixture("held", deadline)?;
    let held_deadline = Instant::now()
        .checked_add(Duration::from_millis(250))
        .ok_or_else(|| "Windows held-successor deadline overflowed".to_owned())?
        .min(deadline);
    let held_error = match await_windows_session_cleanup_successor_exit(
        &held.child,
        &held.observations,
        held.request_sha256,
        held.nonce,
        held_deadline,
    ) {
        Ok(()) => return Err("held Windows cleanup successor falsely attested exit".to_owned()),
        Err(error) => error,
    };
    if !held_error.contains("retained exit ownership") {
        return Err(format!(
            "Windows held-successor diagnostic differs: {held_error}"
        ));
    }
    windows_write_inherited_frame(&mut held.control, b"release")?;
    let release_deadline = Instant::now()
        .checked_add(NIGHTLY_SUPERVISOR_START_TIMEOUT)
        .ok_or_else(|| "Windows held-successor release deadline overflowed".to_owned())?
        .min(deadline);
    loop {
        match held.child.try_wait()? {
            Some(0) => break,
            Some(code) => {
                return Err(format!(
                    "Windows held cleanup successor exited with code {code}"
                ));
            }
            None if Instant::now() < release_deadline => std::thread::yield_now(),
            None => return Err("Windows held cleanup successor did not exit".to_owned()),
        }
    }
    let nonzero = start_windows_cleanup_exit_fixture("nonzero", deadline)?;
    let nonzero_deadline = Instant::now()
        .checked_add(NIGHTLY_SUPERVISOR_START_TIMEOUT)
        .ok_or_else(|| "Windows nonzero-successor deadline overflowed".to_owned())?
        .min(deadline);
    let nonzero_error = match await_windows_session_cleanup_successor_exit(
        &nonzero.child,
        &nonzero.observations,
        nonzero.request_sha256,
        nonzero.nonce,
        nonzero_deadline,
    ) {
        Ok(()) => {
            return Err("nonzero Windows cleanup successor falsely attested success".to_owned());
        }
        Err(error) => error,
    };
    if !nonzero_error.contains("exited with code") {
        return Err(format!(
            "Windows nonzero-successor diagnostic differs: {nonzero_error}"
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn verify_windows_payload_started_reporter_exit(
    root: &Path,
    session_parent: &Path,
    execution_deadline: Instant,
    child_completion_deadline: Instant,
    terminal_deadline: Instant,
    injection: WindowsReporterFailureInjection,
    construction_injection: WindowsReporterConstructionInjection,
) -> Result<(), String> {
    let (report_parent, report_parent_receipt) = windows_bind_path(session_parent, true)?;
    let mut authority = WindowsReporterFixtureAuthority::create_until(
        session_parent,
        execution_deadline,
        terminal_deadline,
    )?;
    let mut observed = match start_windows_reporter_exit_observation(
        root,
        session_parent,
        execution_deadline,
        terminal_deadline,
        "payload-started",
        authority.staged_root(),
        construction_injection,
    ) {
        Ok(observed) => observed,
        Err(primary) => {
            let cleanup = authority.finish_until(terminal_deadline);
            return compose_windows_reporter_fixture_results(Err(primary), cleanup);
        }
    };
    authority.commit_cleanup_transfer();
    if child_completion_deadline >= terminal_deadline {
        return Err("Windows payload finalizer deadline order differs".to_owned());
    }
    let primary = windows_reporter_primary(|| {
        inject_windows_reporter_failure(&mut observed, injection, "payload-started")?;
        observed.release_reporter()?;
        observed.receive_payload_gate()?;
        observed.release_payload_gate()?;
        let deadline = observed.deadline;
        observed.wait_reporter_until(deadline)?;
        observed.verify_and_remove_report()?;
        if windows_file_receipt(&report_parent)? != report_parent_receipt
            || windows_bind_path(session_parent, true)?.1 != report_parent_receipt
        {
            return Err("Windows verifier report parent receipt differs".to_owned());
        }
        Ok(())
    });
    let cleanup = finalize_windows_reporter_observation(
        &mut observed,
        WindowsReporterExitExpectation::PayloadTerminal,
    );
    let parent = if windows_file_receipt(&report_parent)? == report_parent_receipt
        && windows_bind_path(session_parent, true)?.1 == report_parent_receipt
    {
        Ok(())
    } else {
        Err("Windows verifier report parent changed during finalization".to_owned())
    };
    let cleanup = compose_windows_reporter_fixture_results(cleanup, parent);
    let result = finish_windows_reporter_fixture(primary, cleanup, injection, "payload-started");
    let authority = authority.finish_until(terminal_deadline);
    compose_windows_reporter_fixture_results(result, authority)
}

#[cfg(windows)]
fn verify_windows_reporter_construction_failure(
    root: &Path,
    session_parent: &Path,
    deadline: Instant,
    cleanup_deadline: Instant,
    stage: &str,
    injection: WindowsReporterConstructionInjection,
) -> Result<(), String> {
    let mut authority =
        WindowsReporterFixtureAuthority::create_until(session_parent, deadline, cleanup_deadline)?;
    let result = (|| {
        let failure = match start_windows_reporter_exit_observation_typed(
            root,
            session_parent,
            deadline,
            cleanup_deadline,
            stage,
            authority.staged_root(),
            injection,
        ) {
            Ok(mut observed) => {
                let cleanup = finalize_windows_reporter_observation(
                    &mut observed,
                    WindowsReporterExitExpectation::Abnormal("precommit-control-failed"),
                );
                return compose_windows_reporter_fixture_results(
                    Err("Windows reporter construction injection was not exercised".to_owned()),
                    cleanup,
                );
            }
            Err(failure) => failure,
        };
        let expected = format!(
            "injected Windows reporter construction failure {}",
            injection.detail()
        );
        let panic_expected = "Windows reporter observation construction panicked";
        let expected_primary = if matches!(
            injection,
            WindowsReporterConstructionInjection::MalformedParse
                | WindowsReporterConstructionInjection::MalformedParseFinalizerFailure
        ) {
            format!("{expected}: Windows supervisor request token has a partial wide character")
        } else if matches!(
            injection,
            WindowsReporterConstructionInjection::PanicAfterParse
                | WindowsReporterConstructionInjection::PanicAfterSidecarBind
                | WindowsReporterConstructionInjection::PanicAfterExitAccept
        ) {
            panic_expected.to_owned()
        } else {
            expected
        };
        if failure.primary != expected_primary {
            return Err(format!(
                "Windows reporter construction primary differed: {}",
                failure.primary
            ));
        }
        let cleanup = failure
            .cleanup
            .ok_or_else(|| "Windows reporter construction cleanup receipt is absent".to_owned())?;
        if injection == WindowsReporterConstructionInjection::MalformedParseFinalizerFailure {
            let cleanup = cleanup
                .expect_err("injected Windows reporter finalizer failure must remain observable");
            if cleanup == "injected Windows reporter construction finalizer failure" {
                return Ok(());
            }
            return Err(format!(
                "Windows reporter injected finalizer diagnostic differs: {cleanup}"
            ));
        }
        cleanup.map_err(|error| format!("Windows reporter construction cleanup failed: {error}"))
    })();
    let authority = authority.finish_until(cleanup_deadline);
    compose_windows_reporter_fixture_results(result, authority)
}

#[cfg(windows)]
fn record_windows_supervisor_matrix_case(
    completed: &mut usize,
    result: Result<(), String>,
) -> Result<(), String> {
    result?;
    *completed = completed
        .checked_add(1)
        .ok_or_else(|| "Windows supervisor matrix pass count overflowed".to_owned())?;
    Ok(())
}

#[cfg(windows)]
fn verify_windows_sealed_authority_matrix(
    root: &Path,
    session_parent: &Path,
    execution_deadline: Instant,
    child_completion_deadline: Instant,
    terminal_deadline: Instant,
) -> Result<(), String> {
    verify_windows_two_hop_deadline_debit()?;
    verify_windows_cleanup_successor_exit_receipt(execution_deadline)?;
    verify_windows_nightly_authority_manifest_for_integration(
        session_parent,
        execution_deadline,
        child_completion_deadline,
    )?;
    verify_windows_external_supervisor_no_go_for_integration(
        root,
        session_parent,
        execution_deadline,
        None,
    )?;

    let mut completed = 0_usize;
    record_windows_supervisor_matrix_case(
        &mut completed,
        verify_windows_reporter_exit_before_go(
            root,
            session_parent,
            execution_deadline,
            child_completion_deadline,
            "authority-imported",
            "precommit-control-failed",
            WindowsReporterFailureInjection::None,
            WindowsReporterConstructionInjection::None,
        ),
    )?;
    record_windows_supervisor_matrix_case(
        &mut completed,
        verify_windows_reporter_exit_before_go(
            root,
            session_parent,
            execution_deadline,
            child_completion_deadline,
            "cleanup-committed",
            "committed-before-go-control-failed",
            WindowsReporterFailureInjection::None,
            WindowsReporterConstructionInjection::None,
        ),
    )?;
    record_windows_supervisor_matrix_case(
        &mut completed,
        verify_windows_payload_started_reporter_exit(
            root,
            session_parent,
            execution_deadline,
            child_completion_deadline,
            terminal_deadline,
            WindowsReporterFailureInjection::None,
            WindowsReporterConstructionInjection::None,
        ),
    )?;

    for (stage, expected, injection) in [
        (
            "authority-imported",
            "precommit-control-failed",
            WindowsReporterFailureInjection::AfterReceipt,
        ),
        (
            "cleanup-committed",
            "committed-before-go-control-failed",
            WindowsReporterFailureInjection::AfterReceipt,
        ),
        (
            "authority-imported",
            "precommit-control-failed",
            WindowsReporterFailureInjection::AfterSidecarBind,
        ),
        (
            "authority-imported",
            "precommit-control-failed",
            WindowsReporterFailureInjection::AfterExitAccept,
        ),
    ] {
        record_windows_supervisor_matrix_case(
            &mut completed,
            verify_windows_reporter_exit_before_go(
                root,
                session_parent,
                execution_deadline,
                child_completion_deadline,
                stage,
                expected,
                injection,
                WindowsReporterConstructionInjection::None,
            ),
        )?;
    }
    record_windows_supervisor_matrix_case(
        &mut completed,
        verify_windows_payload_started_reporter_exit(
            root,
            session_parent,
            execution_deadline,
            child_completion_deadline,
            terminal_deadline,
            WindowsReporterFailureInjection::AfterReceipt,
            WindowsReporterConstructionInjection::None,
        ),
    )?;

    for injection in [
        WindowsReporterConstructionInjection::BeforeParse,
        WindowsReporterConstructionInjection::AfterParse,
        WindowsReporterConstructionInjection::MalformedParse,
        WindowsReporterConstructionInjection::MalformedParseFinalizerFailure,
        WindowsReporterConstructionInjection::AfterSidecarBind,
        WindowsReporterConstructionInjection::AfterExitAccept,
        WindowsReporterConstructionInjection::PanicAfterParse,
        WindowsReporterConstructionInjection::PanicAfterSidecarBind,
        WindowsReporterConstructionInjection::PanicAfterExitAccept,
    ] {
        record_windows_supervisor_matrix_case(
            &mut completed,
            verify_windows_reporter_construction_failure(
                root,
                session_parent,
                execution_deadline,
                child_completion_deadline,
                "authority-imported",
                injection,
            ),
        )?;
    }
    if completed != 17 {
        return Err(format!(
            "Windows sealed-authority matrix pass count differs: {completed}"
        ));
    }
    Ok(())
}

/// Verifies one bounded Windows external-supervisor lifecycle case.
///
/// # Errors
///
/// Returns an error when the selected inherited-pipe, breakaway supervisor,
/// payload Job, or immutable receipt invariant differs.
#[cfg(windows)]
#[doc(hidden)]
pub(crate) fn verify_windows_external_nightly_supervisor_for_integration(
    arguments: &[std::ffi::OsString],
) -> Result<(), String> {
    let [case] = arguments else {
        return Err("Windows external supervisor verification requires one case".to_owned());
    };
    let case = case
        .to_str()
        .ok_or_else(|| "Windows external supervisor case is not UTF-8".to_owned())?;
    let started = Instant::now();
    let execution_deadline = started
        .checked_add(Duration::from_mins(12))
        .ok_or_else(|| "Windows supervisor verifier execution deadline overflowed".to_owned())?;
    let child_completion_deadline = started
        .checked_add(Duration::from_mins(15))
        .ok_or_else(|| "Windows supervisor verifier cleanup deadline overflowed".to_owned())?;
    let terminal_deadline = started
        .checked_add(Duration::from_mins(16))
        .ok_or_else(|| "Windows terminal receipt deadline overflowed".to_owned())?;
    let verifier_deadline = started
        .checked_add(Duration::from_mins(38))
        .ok_or_else(|| "Windows supervisor verifier deadline overflowed".to_owned())?;
    let root = fs::canonicalize(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| "cannot locate Windows supervisor verifier workspace".to_owned())?,
    )
    .map_err(|error| format!("cannot canonicalize Windows supervisor verifier: {error}"))?;
    let session_parent = fs::canonicalize(root.join("target"))
        .map_err(|error| format!("cannot bind Windows supervisor verifier target: {error}"))?;
    match case {
        "real-authority-positive" => verify_windows_cargo_authority_for_integration(
            &root,
            &session_parent,
            verifier_deadline,
        ),
        "sealed-authority-matrix" => verify_windows_sealed_authority_matrix(
            &root,
            &session_parent,
            execution_deadline,
            child_completion_deadline,
            terminal_deadline,
        ),
        _ => Err("Windows external supervisor verification case differs".to_owned()),
    }
}

#[cfg(unix)]
struct ExternalSupervisorLifecycleObservation<'a> {
    state: &'a str,
    terminal: &'a ExternalSupervisorTerminal,
    cleanup_receipted: bool,
    transport_closed: bool,
    exit_status: Option<i32>,
}

#[cfg(unix)]
fn retain_external_supervisor_lifecycle(
    report: &mut Report,
    plan: ExternalSupervisorPlan,
    started: &ExternalSupervisorStarted,
    observation: &ExternalSupervisorLifecycleObservation<'_>,
) {
    report.evidence(
        format!("{}-external-supervisor-lifecycle", plan.name()),
        JsonValue::Object(BTreeMap::from([
            (
                "cleanupReceipted".to_owned(),
                JsonValue::Bool(observation.cleanup_receipted),
            ),
            (
                "exitStatus".to_owned(),
                observation.exit_status.map_or(JsonValue::Null, |status| {
                    JsonValue::String(status.to_string())
                }),
            ),
            (
                "requestSha256".to_owned(),
                JsonValue::String(started.request_sha256.hex()),
            ),
            (
                "session".to_owned(),
                JsonValue::String(started.session.path().display().to_string()),
            ),
            (
                "state".to_owned(),
                JsonValue::String(observation.state.to_owned()),
            ),
            (
                "supervisorPid".to_owned(),
                JsonValue::Number(u64::from(started.pid())),
            ),
            (
                "terminal".to_owned(),
                external_supervisor_terminal_evidence(
                    plan,
                    observation.terminal,
                    started.request_sha256,
                ),
            ),
            (
                "transportClosed".to_owned(),
                JsonValue::Bool(observation.transport_closed),
            ),
        ])),
    );
}

#[cfg(unix)]
fn persist_external_supervisor_terminal_outcome(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    progress: &mut PortabilityChildProgress,
    plan: ExternalSupervisorPlan,
    started: &ExternalSupervisorStarted,
    terminal: &ExternalSupervisorTerminal,
) -> Result<bool, FailureKind> {
    retain_external_supervisor_lifecycle(
        report,
        plan,
        started,
        &ExternalSupervisorLifecycleObservation {
            state: "terminal-authenticated",
            terminal,
            cleanup_receipted: false,
            transport_closed: false,
            exit_status: None,
        },
    );
    report.evidence(
        format!("{}-external-supervisor", plan.name()),
        external_supervisor_terminal_evidence(plan, terminal, started.request_sha256),
    );
    apply_terminal_failed_case(progress, terminal);
    let terminal_case = progress
        .case
        .clone()
        .unwrap_or_else(|| plan.name().to_owned());
    progress.record_attribution(
        plan.name(),
        PortabilityAttributionEvent::Case(
            terminal_case,
            if terminal.execution.success {
                PortabilityCaseState::Completed
            } else {
                PortabilityCaseState::Failed
            },
        ),
    );
    let result = if terminal.execution.success && terminal.cleanup.terminal {
        Ok(())
    } else {
        Err(format!(
            "{}: {}; cleanup terminal: {}",
            plan.name(),
            terminal.detail,
            terminal.cleanup.terminal
        ))
    };
    let passed = result.is_ok();
    report.check(plan.name(), context.suite_started.elapsed(), result);
    checkpoint_attributed_phase_with_progress(report, context, progress)?;
    Ok(passed)
}

#[cfg(unix)]
fn retain_external_supervisor_control_failure_evidence(
    report: &mut Report,
    plan: ExternalSupervisorPlan,
    started: &ExternalSupervisorStarted,
    control_error: &str,
    exit_status: Option<i32>,
) {
    report.evidence(
        format!("{}-external-supervisor-control-failure", plan.name()),
        JsonValue::Object(BTreeMap::from([
            (
                "controlError".to_owned(),
                JsonValue::String(control_error.to_owned()),
            ),
            (
                "exitStatus".to_owned(),
                exit_status.map_or(JsonValue::Null, |status| {
                    JsonValue::String(status.to_string())
                }),
            ),
            (
                "requestSha256".to_owned(),
                JsonValue::String(started.request_sha256.hex()),
            ),
            (
                "session".to_owned(),
                JsonValue::String(started.session.path().display().to_string()),
            ),
            (
                "supervisorPid".to_owned(),
                JsonValue::Number(u64::from(started.pid())),
            ),
        ])),
    );
}

#[cfg(unix)]
struct ExternalSupervisorRetainedExit<'a> {
    plan: ExternalSupervisorPlan,
    terminal: &'a ExternalSupervisorTerminal,
    state: &'a str,
    reason: &'a str,
    cleanup_receipted: bool,
    transport_closed: bool,
}

#[cfg(unix)]
fn retain_external_supervisor_exit_owned(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    progress: &mut PortabilityChildProgress,
    started: &ExternalSupervisorStarted,
    retained: &ExternalSupervisorRetainedExit<'_>,
) -> Result<(), FailureKind> {
    progress.record_attribution(
        context.name,
        PortabilityAttributionEvent::Case(context.name.to_owned(), PortabilityCaseState::Retained),
    );
    retain_external_supervisor_lifecycle(
        report,
        retained.plan,
        started,
        &ExternalSupervisorLifecycleObservation {
            state: retained.state,
            terminal: retained.terminal,
            cleanup_receipted: retained.cleanup_receipted,
            transport_closed: retained.transport_closed,
            exit_status: None,
        },
    );
    report.check(
        context.name,
        context.suite_started.elapsed(),
        Err(format!(
            "{}; supervisor exit waiter remains owner: pid={}",
            retained.reason,
            started.pid()
        )),
    );
    if checkpoint_attributed_phase_with_progress(report, context, progress).is_err() {
        report.check(
            format!("{}-external-supervisor-checkpoint", context.name),
            context.suite_started.elapsed(),
            Err(
                "supervisor exit ownership was retained, but its checkpoint could not be persisted"
                    .to_owned(),
            ),
        );
    }
    Err(FailureKind::Child)
}

#[cfg(unix)]
fn retain_external_supervisor_owned(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    progress: &mut PortabilityChildProgress,
    started: &ExternalSupervisorStarted,
    reason: &str,
) -> Result<(), FailureKind> {
    progress.record_attribution(
        context.name,
        PortabilityAttributionEvent::Case(context.name.to_owned(), PortabilityCaseState::Retained),
    );
    report.evidence(
        format!("{}-external-supervisor", context.name),
        JsonValue::Object(BTreeMap::from([
            (
                "plan".to_owned(),
                JsonValue::String(context.name.to_owned()),
            ),
            (
                "requestSha256".to_owned(),
                JsonValue::String(started.request_sha256.hex()),
            ),
            (
                "session".to_owned(),
                JsonValue::String(started.session.path().display().to_string()),
            ),
            (
                "state".to_owned(),
                JsonValue::String("owned-by-external-supervisor".to_owned()),
            ),
            (
                "supervisorPid".to_owned(),
                JsonValue::Number(u64::from(started.pid())),
            ),
        ])),
    );
    report.check(
        context.name,
        context.suite_started.elapsed(),
        Err(format!(
            "{}; external supervisor remains owner: session={}, pid={}",
            reason,
            started.session.path().display(),
            started.pid()
        )),
    );
    if checkpoint_attributed_phase_with_progress(report, context, progress).is_err() {
        report.check(
            format!("{}-external-supervisor-checkpoint", context.name),
            context.suite_started.elapsed(),
            Err("external supervisor ownership was retained, but its checkpoint could not be persisted".to_owned()),
        );
    }
    Err(FailureKind::Child)
}

#[cfg(unix)]
struct ExternalSupervisorControlFailure<'a> {
    plan: ExternalSupervisorPlan,
    started: &'a ExternalSupervisorStarted,
    control_error: &'a str,
    exit_deadline: Instant,
    lifecycle_deadline: Instant,
}

#[cfg(unix)]
fn finish_external_supervisor_after_control_failure(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    progress: &mut PortabilityChildProgress,
    failure: &ExternalSupervisorControlFailure<'_>,
) -> Result<(), FailureKind> {
    let Some((status, terminal)) =
        import_terminal_after_control_failure(report, context, progress, failure)?
    else {
        return Ok(());
    };
    if let Err(error) = progress.apply_external_attribution(terminal.attribution.clone()) {
        report.check(
            format!("{}-external-supervisor-recovery", failure.plan.name()),
            context.suite_started.elapsed(),
            Err(format!("{}; {error}", failure.control_error)),
        );
        checkpoint_attributed_phase_with_progress(report, context, progress)?;
        return Err(FailureKind::Fixture);
    }
    let terminal_passed = persist_external_supervisor_terminal_outcome(
        report,
        context,
        progress,
        failure.plan,
        failure.started,
        &terminal,
    )?;
    retain_external_supervisor_lifecycle(
        report,
        failure.plan,
        failure.started,
        &ExternalSupervisorLifecycleObservation {
            state: "terminal-imported-after-control-failure",
            terminal: &terminal,
            cleanup_receipted: false,
            transport_closed: true,
            exit_status: status.code(),
        },
    );
    let session_cleanup = failure
        .started
        .session
        .close_until(failure.lifecycle_deadline);
    let exit_passed = status.success();
    if !exit_passed {
        report.check(
            format!("{}-external-supervisor-exit", failure.plan.name()),
            context.suite_started.elapsed(),
            Err(format!(
                "nightly supervisor exited with status {:?} after {}",
                status.code(),
                failure.control_error
            )),
        );
    }
    if let Err(cleanup) = &session_cleanup {
        report.check(
            format!("{}-external-supervisor-session", failure.plan.name()),
            context.suite_started.elapsed(),
            Err(format!(
                "nightly supervisor session cleanup failed after {}: {cleanup}",
                failure.control_error
            )),
        );
    }
    checkpoint_attributed_phase_complete(
        report,
        context.suite,
        Some(context.envelope.report_completion_deadline),
    )?;
    if terminal_passed && exit_passed && session_cleanup.is_ok() {
        Ok(())
    } else {
        Err(FailureKind::Child)
    }
}

#[cfg(unix)]
fn import_terminal_after_control_failure(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    progress: &mut PortabilityChildProgress,
    failure: &ExternalSupervisorControlFailure<'_>,
) -> Result<Option<(std::process::ExitStatus, ExternalSupervisorTerminal)>, FailureKind> {
    let status = match failure.started.exit.wait_until(failure.exit_deadline) {
        ExternalSupervisorExitState::DeadlineExpired => {
            retain_external_supervisor_owned(
                report,
                context,
                progress,
                failure.started,
                &format!("{}; exit receipt remains pending", failure.control_error),
            )?;
            return Ok(None);
        }
        ExternalSupervisorExitState::Failed(exit_error) => {
            report.check(
                format!("{}-external-supervisor-exit", failure.plan.name()),
                context.suite_started.elapsed(),
                Err(format!("{}; {exit_error}", failure.control_error)),
            );
            checkpoint_attributed_phase_with_progress(report, context, progress)?;
            return Err(FailureKind::Fixture);
        }
        ExternalSupervisorExitState::Exited(status) => status,
    };
    retain_external_supervisor_control_failure_evidence(
        report,
        failure.plan,
        failure.started,
        failure.control_error,
        status.code(),
    );
    if Instant::now() >= failure.lifecycle_deadline {
        report.check(
            format!("{}-external-supervisor-recovery", failure.plan.name()),
            context.suite_started.elapsed(),
            Err(format!(
                "{}; lifecycle deadline expired before durable terminal import",
                failure.control_error
            )),
        );
        checkpoint_attributed_phase_with_progress(report, context, progress)?;
        return Err(FailureKind::Fixture);
    }
    let terminal_path = failure.started.session.path().join("terminal.receipt");
    let terminal =
        read_bounded_file(&terminal_path, NIGHTLY_SUPERVISOR_TERMINAL_LIMIT).and_then(|bytes| {
            decode_external_supervisor_terminal(
                &bytes,
                failure.started.request_sha256,
                failure.started.nonce,
            )
        });
    let terminal = match terminal {
        Ok(terminal) => terminal,
        Err(terminal_error) => {
            let cleanup = failure
                .started
                .session
                .close_until(failure.lifecycle_deadline);
            report.evidence(
                format!("{}-external-supervisor-recovery", failure.plan.name()),
                JsonValue::Object(BTreeMap::from([
                    (
                        "controlError".to_owned(),
                        JsonValue::String(failure.control_error.to_owned()),
                    ),
                    (
                        "exitStatus".to_owned(),
                        status
                            .code()
                            .map_or(JsonValue::Null, |code| JsonValue::String(code.to_string())),
                    ),
                    (
                        "session".to_owned(),
                        JsonValue::String(failure.started.session.path().display().to_string()),
                    ),
                    (
                        "terminalError".to_owned(),
                        JsonValue::String(terminal_error.clone()),
                    ),
                ])),
            );
            report.check(
                format!("{}-external-supervisor-recovery", failure.plan.name()),
                context.suite_started.elapsed(),
                Err(format!(
                    "{}; cannot import authenticated terminal receipt: {terminal_error}; session cleanup={cleanup:?}",
                    failure.control_error
                )),
            );
            checkpoint_attributed_phase_with_progress(report, context, progress)?;
            return Err(FailureKind::Fixture);
        }
    };
    Ok(Some((status, terminal)))
}

#[cfg(unix)]
struct AuthenticatedTerminalControlFailure<'a> {
    plan: ExternalSupervisorPlan,
    started: &'a ExternalSupervisorStarted,
    terminal: &'a ExternalSupervisorTerminal,
    terminal_passed: bool,
    control_error: &'a str,
    cleanup_receipted: bool,
    transport_closed: bool,
    exit_deadline: Instant,
    lifecycle_deadline: Instant,
}

#[cfg(unix)]
fn finish_external_supervisor_after_authenticated_terminal_control_failure(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    progress: &mut PortabilityChildProgress,
    failure: &AuthenticatedTerminalControlFailure<'_>,
) -> Result<(), FailureKind> {
    let status = match failure.started.exit.wait_until(failure.exit_deadline) {
        ExternalSupervisorExitState::DeadlineExpired => {
            return retain_external_supervisor_exit_owned(
                report,
                context,
                progress,
                failure.started,
                &ExternalSupervisorRetainedExit {
                    plan: failure.plan,
                    terminal: failure.terminal,
                    state: "control-failed-exit-owned-by-waiter",
                    reason: failure.control_error,
                    cleanup_receipted: failure.cleanup_receipted,
                    transport_closed: failure.transport_closed,
                },
            );
        }
        ExternalSupervisorExitState::Failed(exit_error) => {
            report.check(
                format!("{}-external-supervisor-exit", failure.plan.name()),
                context.suite_started.elapsed(),
                Err(format!("{}; {exit_error}", failure.control_error)),
            );
            checkpoint_attributed_phase_with_progress(report, context, progress)?;
            return Err(FailureKind::Fixture);
        }
        ExternalSupervisorExitState::Exited(status) => status,
    };
    retain_external_supervisor_control_failure_evidence(
        report,
        failure.plan,
        failure.started,
        failure.control_error,
        status.code(),
    );
    retain_external_supervisor_lifecycle(
        report,
        failure.plan,
        failure.started,
        &ExternalSupervisorLifecycleObservation {
            state: "exit-reaped-after-control-failure",
            terminal: failure.terminal,
            cleanup_receipted: failure.cleanup_receipted,
            transport_closed: failure.transport_closed,
            exit_status: status.code(),
        },
    );
    let session_cleanup = failure
        .started
        .session
        .close_until(failure.lifecycle_deadline);
    let exit_passed = status.success();
    if !exit_passed {
        report.check(
            format!("{}-external-supervisor-exit", failure.plan.name()),
            context.suite_started.elapsed(),
            Err(format!(
                "nightly supervisor exited with status {:?} after {}",
                status.code(),
                failure.control_error
            )),
        );
    }
    if let Err(cleanup) = &session_cleanup {
        report.check(
            format!("{}-external-supervisor-session", failure.plan.name()),
            context.suite_started.elapsed(),
            Err(format!(
                "nightly supervisor session cleanup failed after {}: {cleanup}",
                failure.control_error
            )),
        );
    }
    checkpoint_attributed_phase_complete(
        report,
        context.suite,
        Some(context.envelope.report_completion_deadline),
    )?;
    if failure.terminal_passed && exit_passed && session_cleanup.is_ok() {
        Ok(())
    } else {
        Err(FailureKind::Child)
    }
}

#[cfg(unix)]
fn run_externally_supervised_nightly_command(
    root: &Path,
    session_parent: &Path,
    report: &mut Report,
    plan: ExternalSupervisorPlan,
    suite_started: Instant,
    outer_deadline: Instant,
) -> Result<(), FailureKind> {
    let Some(mut execution) = start_external_supervisor_nightly_phase(
        root,
        session_parent,
        report,
        plan,
        suite_started,
        outer_deadline,
    )?
    else {
        return Ok(());
    };
    let context = execution.context;
    let progress = &mut execution.progress;
    let started = &mut execution.started;
    let observation_deadline = execution.observation_deadline;
    let exit_recovery_deadline = execution.exit_recovery_deadline;
    wait_for_external_supervisor_terminal(
        report,
        context,
        progress,
        plan,
        started,
        observation_deadline,
        exit_recovery_deadline,
    )?;
    let Some((terminal, terminal_passed)) = load_external_supervisor_terminal(
        report,
        context,
        progress,
        plan,
        started,
        observation_deadline,
        exit_recovery_deadline,
    )?
    else {
        return Ok(());
    };
    let mut terminal_phase = ExternalSupervisorTerminalPhase {
        plan,
        started,
        terminal: &terminal,
        terminal_passed,
        observation_deadline,
        exit_recovery_deadline,
    };
    if !complete_external_supervisor_terminal_cleanup(
        report,
        context,
        progress,
        &mut terminal_phase,
    )? {
        return Ok(());
    }
    finish_external_supervisor_exit(report, context, progress, &mut terminal_phase)
}

#[cfg(unix)]
struct StartedExternalSupervisorNightly {
    context: AttributedRunContext<'static>,
    progress: PortabilityChildProgress,
    started: ExternalSupervisorStarted,
    observation_deadline: Instant,
    exit_recovery_deadline: Instant,
}

#[cfg(unix)]
fn start_external_supervisor_nightly_phase(
    root: &Path,
    session_parent: &Path,
    report: &mut Report,
    plan: ExternalSupervisorPlan,
    suite_started: Instant,
    outer_deadline: Instant,
) -> Result<Option<StartedExternalSupervisorNightly>, FailureKind> {
    let phase_started = Instant::now();
    let envelope = SupervisionEnvelope::within(
        phase_started,
        plan.total(),
        NIGHTLY_COMMAND_CLEANUP_RESERVE,
        NIGHTLY_REPORT_RESERVE,
        outer_deadline,
    )
    .map_err(|error| {
        report.check("nightly-deadline", Duration::ZERO, Err(error));
        FailureKind::Policy
    })?;
    let seed = plan.seed();
    let context = AttributedRunContext {
        name: plan.name(),
        suite: "nightly",
        suite_started,
        envelope,
    };
    let mut progress = PortabilityChildProgress::seeded("nightly", seed.0, seed.1, seed.2);
    if checkpoint_attributed_phase_with_progress(report, context, &progress).is_err() {
        report.check(
            format!("{}-prelaunch-checkpoint", plan.name()),
            suite_started.elapsed(),
            Err("nightly supervisor prelaunch checkpoint could not be persisted".to_owned()),
        );
        return Err(FailureKind::Fixture);
    }
    let started = start_external_nightly_supervisor(
        root,
        session_parent,
        plan,
        phase_started,
        outer_deadline,
    )
    .map_err(|error| {
        report.check(plan.name(), suite_started.elapsed(), Err(error));
        FailureKind::Child
    })?;
    debug_assert_eq!(started.envelope.execution, envelope.execution);
    if let Some(reason) = started.launch_ownership_uncertain.clone() {
        retain_external_supervisor_owned(
            report,
            context,
            &mut progress,
            &started,
            &format!(
                "nightly supervisor launch authorization delivery was indeterminate: {reason}"
            ),
        )?;
        return Ok(None);
    }
    if checkpoint_attributed_phase_with_progress(report, context, &progress).is_err() {
        retain_external_supervisor_owned(
            report,
            context,
            &mut progress,
            &started,
            "nightly supervisor ownership transferred before its initial checkpoint persisted",
        )?;
        return Ok(None);
    }
    let observation_deadline = started
        .envelope
        .report_completion_deadline
        .checked_sub(REPORT_WRITE_RESERVE)
        .unwrap_or(started.envelope.child_completion_deadline)
        .max(started.envelope.child_completion_deadline);
    let exit_recovery_deadline = observation_deadline
        .checked_sub(TERMINAL_PERSISTENCE_RESERVE)
        .unwrap_or(started.envelope.child_completion_deadline)
        .max(started.envelope.child_completion_deadline);
    Ok(Some(StartedExternalSupervisorNightly {
        context,
        progress,
        started,
        observation_deadline,
        exit_recovery_deadline,
    }))
}

#[cfg(unix)]
fn finish_external_supervisor_exit(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    progress: &mut PortabilityChildProgress,
    phase: &mut ExternalSupervisorTerminalPhase<'_>,
) -> Result<(), FailureKind> {
    let Some(supervisor_status) =
        wait_for_external_supervisor_exit(report, context, progress, phase)?
    else {
        return Ok(());
    };
    retain_external_supervisor_lifecycle(
        report,
        phase.plan,
        phase.started,
        &ExternalSupervisorLifecycleObservation {
            state: if supervisor_status.success() {
                "exit-reaped"
            } else {
                "exit-reaped-nonzero"
            },
            terminal: phase.terminal,
            cleanup_receipted: true,
            transport_closed: true,
            exit_status: supervisor_status.code(),
        },
    );
    let supervisor_exit_passed = supervisor_status.success();
    if !supervisor_exit_passed {
        report.check(
            format!("{}-external-supervisor-exit", phase.plan.name()),
            context.suite_started.elapsed(),
            Err(format!(
                "nightly supervisor exited with status {:?}",
                supervisor_status.code()
            )),
        );
        checkpoint_attributed_phase_with_progress(report, context, progress)?;
    }
    let session_absent = matches!(
        fs::symlink_metadata(phase.started.session.path()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    );
    if !session_absent {
        report.check(
            format!("{}-external-supervisor-session", phase.plan.name()),
            context.suite_started.elapsed(),
            Err("nightly supervisor session remains after cleanup receipt".to_owned()),
        );
        checkpoint_attributed_phase_with_progress(report, context, progress)?;
    }
    if session_absent {
        retain_external_supervisor_lifecycle(
            report,
            phase.plan,
            phase.started,
            &ExternalSupervisorLifecycleObservation {
                state: "exit-reaped-session-absent",
                terminal: phase.terminal,
                cleanup_receipted: true,
                transport_closed: true,
                exit_status: supervisor_status.code(),
            },
        );
    }
    checkpoint_attributed_phase_complete(
        report,
        "nightly",
        Some(phase.started.envelope.report_completion_deadline),
    )?;
    if phase.terminal_passed && supervisor_exit_passed && session_absent {
        Ok(())
    } else {
        Err(FailureKind::Child)
    }
}

#[cfg(unix)]
fn wait_for_external_supervisor_exit(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    progress: &mut PortabilityChildProgress,
    phase: &mut ExternalSupervisorTerminalPhase<'_>,
) -> Result<Option<std::process::ExitStatus>, FailureKind> {
    let status = match phase.started.exit.wait_until(phase.observation_deadline) {
        ExternalSupervisorExitState::Exited(status) => status,
        ExternalSupervisorExitState::DeadlineExpired => {
            retain_external_supervisor_exit_owned(
                report,
                context,
                progress,
                phase.started,
                &ExternalSupervisorRetainedExit {
                    plan: phase.plan,
                    terminal: phase.terminal,
                    state: "exit-reap-owned-by-waiter",
                    reason: "nightly supervisor exit exceeded its report deadline",
                    cleanup_receipted: true,
                    transport_closed: true,
                },
            )?;
            return Ok(None);
        }
        ExternalSupervisorExitState::Failed(error) => {
            retain_external_supervisor_lifecycle(
                report,
                phase.plan,
                phase.started,
                &ExternalSupervisorLifecycleObservation {
                    state: "exit-reap-failed",
                    terminal: phase.terminal,
                    cleanup_receipted: true,
                    transport_closed: true,
                    exit_status: None,
                },
            );
            report.check(
                phase.plan.name(),
                context.suite_started.elapsed(),
                Err(error),
            );
            checkpoint_attributed_phase_with_progress(report, context, progress)?;
            return Err(FailureKind::Fixture);
        }
    };
    Ok(Some(status))
}

#[cfg(unix)]
struct ExternalSupervisorTerminalPhase<'a> {
    plan: ExternalSupervisorPlan,
    started: &'a mut ExternalSupervisorStarted,
    terminal: &'a ExternalSupervisorTerminal,
    terminal_passed: bool,
    observation_deadline: Instant,
    exit_recovery_deadline: Instant,
}

#[cfg(unix)]
struct ExternalSupervisorCleanupObservation<'a> {
    reason: &'a str,
    cleanup_receipted: bool,
    transport_closed: bool,
}

#[cfg(unix)]
fn complete_external_supervisor_terminal_cleanup(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    progress: &mut PortabilityChildProgress,
    phase: &mut ExternalSupervisorTerminalPhase<'_>,
) -> Result<bool, FailureKind> {
    if let Err(error) = write_supervisor_handshake(
        &mut phase.started.control_input,
        ExternalSupervisorMessage::Go,
        phase.started.request_sha256,
        phase.started.nonce,
    ) {
        return finish_external_supervisor_terminal_phase_failure(
            report,
            context,
            progress,
            phase,
            &ExternalSupervisorCleanupObservation {
                reason: &format!(
                    "cannot acknowledge nightly supervisor terminal ownership: {error}"
                ),
                cleanup_receipted: false,
                transport_closed: false,
            },
        );
    }
    let cleanup_receipt = read_supervisor_handshake_until(
        &mut phase.started.control_output,
        ExternalSupervisorMessage::Ready,
        phase.started.request_sha256,
        phase.started.nonce,
        phase.observation_deadline,
    );
    match cleanup_receipt {
        Ok(true) => {}
        Ok(false) => {
            return finish_external_supervisor_terminal_phase_failure(
                report,
                context,
                progress,
                phase,
                &ExternalSupervisorCleanupObservation {
                    reason: "nightly supervisor session cleanup exceeded its lifecycle deadline",
                    cleanup_receipted: false,
                    transport_closed: false,
                },
            );
        }
        Err(error) => {
            return finish_external_supervisor_terminal_phase_failure(
                report,
                context,
                progress,
                phase,
                &ExternalSupervisorCleanupObservation {
                    reason: &format!("cannot read nightly supervisor cleanup receipt: {error}"),
                    cleanup_receipted: false,
                    transport_closed: false,
                },
            );
        }
    }
    complete_external_supervisor_transport_close(report, context, progress, phase)
}

#[cfg(unix)]
fn complete_external_supervisor_transport_close(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    progress: &mut PortabilityChildProgress,
    phase: &mut ExternalSupervisorTerminalPhase<'_>,
) -> Result<bool, FailureKind> {
    retain_external_supervisor_lifecycle(
        report,
        phase.plan,
        phase.started,
        &ExternalSupervisorLifecycleObservation {
            state: "cleanup-receipted",
            terminal: phase.terminal,
            cleanup_receipted: true,
            transport_closed: false,
            exit_status: None,
        },
    );
    match wait_supervisor_eof_until(
        &mut phase.started.control_output,
        phase.observation_deadline,
    ) {
        Ok(true) => {}
        Ok(false) => {
            return finish_external_supervisor_terminal_phase_failure(
                report,
                context,
                progress,
                phase,
                &ExternalSupervisorCleanupObservation {
                    reason: "nightly supervisor transport closure exceeded its lifecycle deadline",
                    cleanup_receipted: true,
                    transport_closed: false,
                },
            );
        }
        Err(error) => {
            return finish_external_supervisor_terminal_phase_failure(
                report,
                context,
                progress,
                phase,
                &ExternalSupervisorCleanupObservation {
                    reason: &error,
                    cleanup_receipted: true,
                    transport_closed: false,
                },
            );
        }
    }
    retain_external_supervisor_lifecycle(
        report,
        phase.plan,
        phase.started,
        &ExternalSupervisorLifecycleObservation {
            state: "transport-closed",
            terminal: phase.terminal,
            cleanup_receipted: true,
            transport_closed: true,
            exit_status: None,
        },
    );
    Ok(true)
}

#[cfg(unix)]
fn finish_external_supervisor_terminal_phase_failure(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    progress: &mut PortabilityChildProgress,
    phase: &ExternalSupervisorTerminalPhase<'_>,
    observation: &ExternalSupervisorCleanupObservation<'_>,
) -> Result<bool, FailureKind> {
    finish_external_supervisor_after_authenticated_terminal_control_failure(
        report,
        context,
        progress,
        &AuthenticatedTerminalControlFailure {
            plan: phase.plan,
            started: phase.started,
            terminal: phase.terminal,
            terminal_passed: phase.terminal_passed,
            control_error: observation.reason,
            cleanup_receipted: observation.cleanup_receipted,
            transport_closed: observation.transport_closed,
            exit_deadline: phase.exit_recovery_deadline,
            lifecycle_deadline: phase.observation_deadline,
        },
    )?;
    Ok(false)
}

#[cfg(unix)]
fn load_external_supervisor_terminal(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    progress: &mut PortabilityChildProgress,
    plan: ExternalSupervisorPlan,
    started: &mut ExternalSupervisorStarted,
    observation_deadline: Instant,
    exit_recovery_deadline: Instant,
) -> Result<Option<(ExternalSupervisorTerminal, bool)>, FailureKind> {
    let terminal_bytes = match read_supervisor_terminal_payload_until(
        &mut started.control_output,
        observation_deadline,
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            finish_external_supervisor_after_control_failure(
                report,
                context,
                progress,
                &ExternalSupervisorControlFailure {
                    plan,
                    started,
                    control_error: &format!(
                        "cannot read nightly supervisor terminal payload: {error}"
                    ),
                    exit_deadline: exit_recovery_deadline,
                    lifecycle_deadline: observation_deadline,
                },
            )?;
            return Ok(None);
        }
    };
    let terminal = match decode_external_supervisor_terminal(
        &terminal_bytes,
        started.request_sha256,
        started.nonce,
    ) {
        Ok(terminal) => terminal,
        Err(error) => {
            finish_external_supervisor_after_control_failure(
                report,
                context,
                progress,
                &ExternalSupervisorControlFailure {
                    plan,
                    started,
                    control_error: &format!(
                        "cannot decode nightly supervisor terminal payload: {error}"
                    ),
                    exit_deadline: exit_recovery_deadline,
                    lifecycle_deadline: observation_deadline,
                },
            )?;
            return Ok(None);
        }
    };
    if let Err(error) = progress.apply_external_attribution(terminal.attribution.clone()) {
        retain_external_supervisor_owned(report, context, progress, started, &error)?;
        return Ok(None);
    }
    let terminal_passed = persist_external_supervisor_terminal_outcome(
        report, context, progress, plan, started, &terminal,
    )?;
    Ok(Some((terminal, terminal_passed)))
}

#[cfg(unix)]
fn wait_for_external_supervisor_terminal(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    progress: &mut PortabilityChildProgress,
    plan: ExternalSupervisorPlan,
    started: &mut ExternalSupervisorStarted,
    observation_deadline: Instant,
    exit_recovery_deadline: Instant,
) -> Result<(), FailureKind> {
    loop {
        if observation_deadline
            .saturating_duration_since(Instant::now())
            .is_zero()
        {
            return finish_external_supervisor_after_control_failure(
                report,
                context,
                progress,
                &ExternalSupervisorControlFailure {
                    plan,
                    started,
                    control_error: "nightly external supervisor reached its report cutoff",
                    exit_deadline: exit_recovery_deadline,
                    lifecycle_deadline: observation_deadline,
                },
            );
        }
        let observation = Instant::now()
            .checked_add(PORTABILITY_PROGRESS_INTERVAL)
            .unwrap_or(observation_deadline)
            .min(observation_deadline);
        match read_supervisor_message_until(
            &mut started.control_output,
            started.request_sha256,
            started.nonce,
            observation,
        ) {
            Ok(Some(ExternalSupervisorMessage::Terminal)) => return Ok(()),
            Ok(Some(ExternalSupervisorMessage::Progress)) => {
                process_external_supervisor_progress(
                    report,
                    context,
                    progress,
                    plan,
                    started,
                    observation_deadline,
                    exit_recovery_deadline,
                )?;
            }
            Ok(Some(_)) => {
                return finish_external_supervisor_after_control_failure(
                    report,
                    context,
                    progress,
                    &ExternalSupervisorControlFailure {
                        plan,
                        started,
                        control_error: "nightly supervisor sent an out-of-order control message",
                        exit_deadline: exit_recovery_deadline,
                        lifecycle_deadline: observation_deadline,
                    },
                );
            }
            Ok(None) => {
                emit_attributed_progress_with_deadlines(context, "running", progress);
                if checkpoint_attributed_phase_with_progress(report, context, progress).is_err() {
                    return retain_external_supervisor_owned(
                        report,
                        context,
                        progress,
                        started,
                        "nightly supervisor heartbeat checkpoint could not be persisted",
                    );
                }
            }
            Err(error) => {
                return finish_external_supervisor_after_control_failure(
                    report,
                    context,
                    progress,
                    &ExternalSupervisorControlFailure {
                        plan,
                        started,
                        control_error: &format!(
                            "cannot read nightly supervisor terminal signal: {error}"
                        ),
                        exit_deadline: exit_recovery_deadline,
                        lifecycle_deadline: observation_deadline,
                    },
                );
            }
        }
    }
}

#[cfg(unix)]
fn process_external_supervisor_progress(
    report: &mut Report,
    context: AttributedRunContext<'_>,
    progress: &mut PortabilityChildProgress,
    plan: ExternalSupervisorPlan,
    started: &mut ExternalSupervisorStarted,
    observation_deadline: Instant,
    exit_recovery_deadline: Instant,
) -> Result<(), FailureKind> {
    let payload = match read_supervisor_terminal_payload_until(
        &mut started.control_output,
        observation_deadline,
    ) {
        Ok(payload) => payload,
        Err(error) => {
            return finish_external_supervisor_after_control_failure(
                report,
                context,
                progress,
                &ExternalSupervisorControlFailure {
                    plan,
                    started,
                    control_error: &format!("cannot read nightly supervisor progress: {error}"),
                    exit_deadline: exit_recovery_deadline,
                    lifecycle_deadline: observation_deadline,
                },
            );
        }
    };
    let attribution = match decode_external_supervisor_progress(&payload) {
        Ok(attribution) => attribution,
        Err(error) => {
            return retain_external_supervisor_owned(
                report,
                context,
                progress,
                started,
                &format!("cannot decode nightly supervisor progress: {error}"),
            );
        }
    };
    if let Err(error) = progress.apply_external_attribution(attribution) {
        return retain_external_supervisor_owned(report, context, progress, started, &error);
    }
    emit_attributed_progress_with_deadlines(context, "running", progress);
    if checkpoint_attributed_phase_with_progress(report, context, progress).is_err() {
        return retain_external_supervisor_owned(
            report,
            context,
            progress,
            started,
            "nightly supervisor progress checkpoint could not be persisted",
        );
    }
    Ok(())
}

pub(crate) fn nightly(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    oracle: &Path,
    oracle_sha256: Digest,
    dependency: &Path,
) -> Result<(), FailureKind> {
    policy_suite(root, report)?;
    let tests_started = Instant::now();
    let tests_deadline = tests_started
        .checked_add(WORKSPACE_TEST_TIMEOUT)
        .ok_or_else(|| {
            report.check(
                "nightly-deadline",
                Duration::ZERO,
                Err("nightly test deadline overflowed".to_owned()),
            );
            FailureKind::Policy
        })?;
    run_nightly_platform_phases(root, report, failures, tests_started, tests_deadline)?;
    finish_verify(root, report, failures)?;
    let candidate = candidate_binary(root, false);
    differential_gate(
        report,
        &DifferentialExecution {
            root,
            failures,
            oracle,
            oracle_digest: Some(oracle_sha256),
            candidate: &candidate,
            dependency,
            candidate_sha: None,
        },
    )
}

#[cfg(unix)]
fn run_nightly_platform_phases(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    tests_started: Instant,
    tests_deadline: Instant,
) -> Result<(), FailureKind> {
    let workspace_partition_deadline = tests_started
        .checked_add(NIGHTLY_WORKSPACE_TEST_TIMEOUT)
        .ok_or_else(|| {
            report.check(
                "nightly-workspace-deadline",
                Duration::ZERO,
                Err("nightly workspace partition deadline overflowed".to_owned()),
            );
            FailureKind::Policy
        })?
        .min(tests_deadline);
    let session_parent = failures.parent().unwrap_or_else(|| Path::new("."));
    run_externally_supervised_nightly_command(
        root,
        session_parent,
        report,
        ExternalSupervisorPlan::NightlyWorkspace,
        tests_started,
        workspace_partition_deadline,
    )?;
    #[cfg(target_os = "macos")]
    run_externally_supervised_nightly_command(
        root,
        session_parent,
        report,
        ExternalSupervisorPlan::MacosStagedNativeToolchain,
        tests_started,
        workspace_partition_deadline,
    )?;
    run_externally_supervised_nightly_command(
        root,
        session_parent,
        report,
        ExternalSupervisorPlan::NightlyCoreData,
        tests_started,
        tests_deadline,
    )
}

#[cfg(windows)]
fn run_nightly_platform_phases(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    tests_started: Instant,
    tests_deadline: Instant,
) -> Result<(), FailureKind> {
    let mut authority =
        acquire_windows_nightly_authority(root, report, tests_started, tests_deadline)?;
    report.evidence(
        "nightly-windows-launch-authority",
        JsonValue::Object(BTreeMap::from([
            (
                "stagedCargo".to_owned(),
                JsonValue::String(authority.staged_cargo().display().to_string()),
            ),
            (
                "stagedRustc".to_owned(),
                JsonValue::String(authority.staged_rustc().display().to_string()),
            ),
            (
                "state".to_owned(),
                JsonValue::String("retained-across-nightly-phases".to_owned()),
            ),
            (
                "writableTarget".to_owned(),
                JsonValue::String(authority.target().display().to_string()),
            ),
        ])),
    );
    let phases = run_windows_externally_supervised_nightly_command(
        WindowsNightlyRunContext {
            root,
            session_parent: failures.parent().unwrap_or_else(|| Path::new(".")),
            plan: ExternalSupervisorPlan::NightlyWorkspace,
            suite_started: tests_started,
            outer_deadline: tests_deadline,
            phase_started: tests_started,
            fixture: None,
        },
        report,
        &mut authority,
    );
    let cleanup = if authority.cleanup_transferred() {
        Ok(())
    } else {
        authority.close_until(tests_deadline)
    };
    if let Err(error) = cleanup {
        report.check(
            "nightly-windows-launch-authority-cleanup",
            tests_started.elapsed(),
            Err(error),
        );
        return Err(FailureKind::Fixture);
    }
    phases
}

#[cfg(windows)]
fn acquire_windows_nightly_authority(
    root: &Path,
    report: &mut Report,
    tests_started: Instant,
    tests_deadline: Instant,
) -> Result<crate::release::platform::NightlyWindowsLaunchAuthority, FailureKind> {
    let envelope = SupervisionEnvelope::within(
        tests_started,
        ExternalSupervisorPlan::NightlyWorkspace.total(),
        NIGHTLY_COMMAND_CLEANUP_RESERVE,
        NIGHTLY_REPORT_RESERVE,
        tests_deadline,
    )
    .map_err(|error| {
        report.check("nightly-deadline", tests_started.elapsed(), Err(error));
        FailureKind::Policy
    })?;
    let context = AttributedRunContext {
        name: ExternalSupervisorPlan::NightlyWorkspace.name(),
        suite: "nightly",
        suite_started: tests_started,
        envelope,
    };
    let seed = ExternalSupervisorPlan::NightlyWorkspace.seed();
    let mut progress =
        PortabilityChildProgress::seeded("nightly", seed.0, seed.1, "authority-acquisition");
    checkpoint_attributed_phase_with_progress(report, context, &progress)?;
    let target =
        match fs::canonicalize(release_candidate_target().unwrap_or_else(|| root.join("target"))) {
            Ok(target) => target,
            Err(error) => {
                return fail_attributed_prelaunch(
                    report,
                    context,
                    &mut progress,
                    None,
                    PortabilityCaseState::LaunchFailed,
                    format!("cannot canonicalize Windows Nightly target: {error}"),
                );
            }
        };
    match crate::release::platform::NightlyWindowsLaunchAuthority::acquire_until(
        root,
        &target,
        envelope.execution,
        envelope.child_completion_deadline,
    ) {
        Ok(authority) => Ok(authority),
        Err(error) => fail_attributed_prelaunch(
            report,
            context,
            &mut progress,
            None,
            PortabilityCaseState::LaunchFailed,
            error,
        ),
    }
}

#[cfg(not(any(unix, windows)))]
fn run_nightly_platform_phases(
    root: &Path,
    report: &mut Report,
    _failures: &Path,
    tests_started: Instant,
    tests_deadline: Instant,
) -> Result<(), FailureKind> {
    run_direct_nightly_command(
        root,
        report,
        ExternalSupervisorPlan::NightlyWorkspace,
        tests_started,
        tests_deadline,
    )?;
    run_direct_nightly_command(
        root,
        report,
        ExternalSupervisorPlan::NightlyCoreData,
        tests_started,
        tests_deadline,
    )
}

pub(crate) fn native_oracle_shard(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    source: &Path,
    platform: &str,
    dependency: &Path,
) -> Result<(), FailureKind> {
    release_native_oracle_shard(root, report, failures, source, platform, dependency, None)
}

pub(crate) fn native_differential_benchmark(
    root: &Path,
    report: &mut Report,
    oracle: &Path,
    candidate: &Path,
    sample_count: usize,
) -> Result<(), FailureKind> {
    policy_suite(root, report)?;
    let authority = prepare_native_benchmark(report, oracle, candidate)?;
    let inventory = native_benchmark_inventory();
    let sample = representative_differential_sample(&inventory, sample_count).map_err(|error| {
        report.check("native-benchmark-inventory", Duration::ZERO, Err(error));
        FailureKind::Policy
    })?;
    report_benchmark_inventory(report, &sample);
    let selected_indices = sample.selected_indices;
    let inventory_count = sample.inventory_count;
    let mut cases = sample.cases;
    let helper = bind_helper(&mut cases).map_err(|error| {
        report.check("native-benchmark-helper", Duration::ZERO, Err(error));
        FailureKind::Fixture
    })?;
    report_benchmark_artifact_identity(report, "helper", &helper).map_err(|error| {
        report.check(
            "native-benchmark-helper-identity",
            Duration::ZERO,
            Err(error),
        );
        FailureKind::Fixture
    })?;
    let workers = differential_worker_limit();
    let started = Instant::now();
    let batch = differential_batch_with_identities(
        &authority.oracle,
        &authority.candidate,
        &cases,
        workers,
    );
    let (metrics, result) =
        native_benchmark_result(report, &cases, &selected_indices, inventory_count, batch);
    report_benchmark_metrics(report, metrics);
    let passed = result.is_ok();
    report.check("native-differential-benchmark", started.elapsed(), result);
    passed.then_some(()).ok_or(FailureKind::Fixture)
}

struct NativeBenchmarkAuthority {
    oracle: ExecutableIdentity,
    candidate: ExecutableIdentity,
}

fn prepare_native_benchmark(
    report: &mut Report,
    oracle: &Path,
    candidate: &Path,
) -> Result<NativeBenchmarkAuthority, FailureKind> {
    let oracle = verify_executable(
        oracle,
        ExecutableRole::Oracle,
        None,
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| {
        report.check(
            "native-benchmark-oracle",
            Duration::ZERO,
            Err(format!("cannot verify benchmark oracle: {error}")),
        );
        FailureKind::Fixture
    })?;
    let candidate = verify_executable(
        candidate,
        ExecutableRole::Candidate,
        None,
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| {
        report.check(
            "native-benchmark-candidate",
            Duration::ZERO,
            Err(format!("cannot verify benchmark candidate: {error}")),
        );
        FailureKind::Fixture
    })?;
    report_benchmark_executable_identity(report, "oracle", &oracle).map_err(|error| {
        report.check(
            "native-benchmark-oracle-identity",
            Duration::ZERO,
            Err(error),
        );
        FailureKind::Fixture
    })?;
    report_benchmark_executable_identity(report, "candidate", &candidate).map_err(|error| {
        report.check(
            "native-benchmark-candidate-identity",
            Duration::ZERO,
            Err(error),
        );
        FailureKind::Fixture
    })?;
    report_candidate_compat_tracing_preflight(
        report,
        "native-benchmark-candidate-compat-tracing",
        &candidate,
    )
    .map_err(|_| FailureKind::Fixture)?;
    let driver = benchmark_current_driver().map_err(|error| {
        report.check(
            "native-benchmark-driver-identity",
            Duration::ZERO,
            Err(error),
        );
        FailureKind::Fixture
    })?;
    report_benchmark_artifact_identity(report, "driver", &driver).map_err(|error| {
        report.check(
            "native-benchmark-driver-identity",
            Duration::ZERO,
            Err(error),
        );
        FailureKind::Fixture
    })?;
    Ok(NativeBenchmarkAuthority { oracle, candidate })
}

fn native_benchmark_result(
    report: &mut Report,
    cases: &[DifferentialCase],
    selected_indices: &[usize],
    inventory_count: usize,
    batch: Result<
        hell_testkit::DifferentialBatchReport,
        Box<hell_testkit::DifferentialBatchFailure>,
    >,
) -> (DifferentialMetrics, Result<(), String>) {
    let (metrics, result) = match batch {
        Ok(batch) => {
            let metrics = DifferentialMetrics {
                timing: batch.timing,
            };
            report_benchmark_timings(
                report,
                cases,
                selected_indices,
                &batch.case_timings,
                batch.timing,
                inventory_count,
            );
            let mismatch = cases
                .iter()
                .zip(&batch.reports)
                .zip(selected_indices)
                .find(|((_, result), _)| !result.agrees())
                .map(|((case, result), inventory_index)| {
                    let details = result
                        .mismatches
                        .iter()
                        .enumerate()
                        .map(|(index, mismatch)| benchmark_mismatch_detail(index, mismatch))
                        .collect::<Vec<_>>()
                        .join("; ");
                    format!(
                        "representative case {} at authoritative index {} has {} mismatch(es): {}",
                        case.id,
                        inventory_index,
                        result.mismatches.len(),
                        details,
                    )
                });
            (metrics, mismatch.map_or(Ok(()), Err))
        }
        Err(error) => {
            let metrics = DifferentialMetrics {
                timing: error.timing,
            };
            (metrics, Err(error.to_string()))
        }
    };
    (metrics, result)
}

const BENCHMARK_MISMATCH_PREFIX_BYTES: usize = 128;

fn benchmark_mismatch_detail(index: usize, mismatch: &DifferentialMismatch) -> String {
    format!(
        "mismatch[{index}] kind={:?}, oracle[{}], candidate[{}]",
        mismatch.kind,
        benchmark_mismatch_bytes(&mismatch.oracle),
        benchmark_mismatch_bytes(&mismatch.candidate),
    )
}

fn benchmark_mismatch_bytes(bytes: &[u8]) -> String {
    let mut prefix = String::with_capacity(BENCHMARK_MISMATCH_PREFIX_BYTES.saturating_mul(2));
    for byte in bytes.iter().take(BENCHMARK_MISMATCH_PREFIX_BYTES) {
        write!(prefix, "{byte:02x}").expect("writing hexadecimal bytes to String cannot fail");
    }
    format!(
        "bytes={}, sha256={}, prefixHex={}, truncated={}",
        bytes.len(),
        sha256_bytes(bytes).hex(),
        prefix,
        bytes.len() > BENCHMARK_MISMATCH_PREFIX_BYTES,
    )
}

#[derive(Clone, Debug)]
struct BenchmarkArtifactIdentity {
    path: PathBuf,
    sha256: Digest,
    size: u64,
}

fn benchmark_current_driver() -> Result<BenchmarkArtifactIdentity, String> {
    let path = std::env::current_exe()
        .map_err(|error| format!("cannot locate benchmark driver: {error}"))?
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize benchmark driver: {error}"))?;
    let sha256 =
        sha256_file(&path).map_err(|error| format!("cannot hash benchmark driver: {error}"))?;
    let size = fs::metadata(&path)
        .map_err(|error| format!("cannot inspect benchmark driver: {error}"))?
        .len();
    Ok(BenchmarkArtifactIdentity { path, sha256, size })
}

fn report_benchmark_executable_identity(
    report: &mut Report,
    name: &str,
    identity: &ExecutableIdentity,
) -> Result<(), String> {
    let size = fs::metadata(&identity.path)
        .map_err(|error| format!("cannot inspect benchmark {name}: {error}"))?
        .len();
    report.measurement(
        format!("native-benchmark-{name}-identity"),
        Duration::ZERO,
        benchmark_executable_identity_detail(identity, size)?,
    );
    Ok(())
}

fn report_executable_identity(
    report: &mut Report,
    name: &str,
    identity: &ExecutableIdentity,
) -> Result<(), String> {
    let size = fs::metadata(&identity.path)
        .map_err(|error| format!("cannot inspect differential {name}: {error}"))?
        .len();
    report.evidence(
        format!("conformance-{name}-identity"),
        executable_identity_json(identity, size)?,
    );
    Ok(())
}

fn report_executable_invocation(
    report: &mut Report,
    name: &str,
    authority: &ExecutableInvocationAuthority,
) -> Result<(), String> {
    let role = match authority.execution().role {
        ExecutableRole::Oracle => "oracle",
        ExecutableRole::Candidate => "candidate",
    };
    if role != name {
        return Err(format!(
            "differential {name} invocation has unexpected {role} role"
        ));
    }
    let source = authority
        .source()
        .path
        .to_str()
        .ok_or_else(|| format!("differential {name} source path is not UTF-8"))?;
    let execution = authority
        .execution()
        .path
        .to_str()
        .ok_or_else(|| format!("differential {name} execution path is not UTF-8"))?;
    let invocation_name = authority
        .execution()
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("differential {name} invocation name is not UTF-8"))?;
    report.evidence(
        format!("conformance-{name}-invocation"),
        JsonValue::Object(BTreeMap::from([
            (
                "executionPath".to_owned(),
                JsonValue::String(execution.to_owned()),
            ),
            (
                "invocationName".to_owned(),
                JsonValue::String(invocation_name.to_owned()),
            ),
            ("role".to_owned(), JsonValue::String(role.to_owned())),
            ("schemaVersion".to_owned(), JsonValue::Number(1)),
            (
                "sha256".to_owned(),
                JsonValue::String(authority.execution().sha256.hex()),
            ),
            (
                "sourcePath".to_owned(),
                JsonValue::String(source.to_owned()),
            ),
        ])),
    );
    Ok(())
}

fn exact_oracle_invocation(
    output_root: &Path,
    source: &ExecutableIdentity,
) -> Result<ExecutableInvocationAuthority, String> {
    let exact_name = format!("hell{}", std::env::consts::EXE_SUFFIX);
    if source
        .path
        .file_name()
        .is_some_and(|name| name == std::ffi::OsStr::new(&exact_name))
    {
        return ExecutableInvocationAuthority::exact_hell(source, source)
            .map_err(|error| format!("cannot bind direct oracle invocation: {error}"));
    }
    #[cfg(not(unix))]
    {
        let _ = output_root;
        Err("a non-Unix oracle must already have the exact hell.exe name".to_owned())
    }
    #[cfg(unix)]
    {
        let directory = output_root.join("oracle-execution");
        if directory.exists() {
            return Err("oracle execution directory already exists".to_owned());
        }
        fs::create_dir(&directory)
            .map_err(|error| format!("cannot create oracle execution directory: {error}"))?;
        let directory = fs::canonicalize(&directory)
            .map_err(|error| format!("cannot bind oracle execution directory: {error}"))?;
        let alias = directory.join(exact_name);
        fs::hard_link(&source.path, &alias)
            .map_err(|error| format!("cannot create exact oracle execution alias: {error}"))?;
        let mut execution = source.clone();
        execution.path = fs::canonicalize(&alias)
            .map_err(|error| format!("cannot canonicalize oracle execution alias: {error}"))?;
        ExecutableInvocationAuthority::exact_hell(source, &execution)
            .map_err(|error| format!("cannot bind exact oracle execution alias: {error}"))
    }
}

fn executable_identity_json(identity: &ExecutableIdentity, size: u64) -> Result<JsonValue, String> {
    let role = match identity.role {
        ExecutableRole::Oracle => "oracle",
        ExecutableRole::Candidate => "candidate",
    };
    let path = identity
        .path
        .to_str()
        .ok_or_else(|| format!("differential {role} path is not UTF-8"))?;
    let optional_digest = |value: Option<Digest>| {
        value.map_or(JsonValue::Null, |digest| JsonValue::String(digest.hex()))
    };
    let build_info = identity.build_info.as_ref().map_or_else(
        || JsonValue::Array(Vec::new()),
        |info| {
            JsonValue::Array(
                info.lines
                    .iter()
                    .map(|line| JsonValue::String(line.to_string()))
                    .collect(),
            )
        },
    );
    let build_info_schema_version = identity
        .build_info
        .as_ref()
        .map_or(JsonValue::Null, |info| {
            JsonValue::Number(info.schema_version)
        });
    let compat_tracing = identity
        .build_info
        .as_ref()
        .map_or(JsonValue::Null, |info| JsonValue::Bool(info.compat_tracing));
    Ok(JsonValue::Object(BTreeMap::from([
        (
            "acquisitionAttestationSha256".to_owned(),
            optional_digest(identity.acquisition_attestation_sha256),
        ),
        (
            "acquisitionReceiptId".to_owned(),
            identity
                .acquisition_receipt_id
                .as_deref()
                .map_or(JsonValue::Null, |value| JsonValue::String(value.to_owned())),
        ),
        (
            "acquisitionReceiptSha256".to_owned(),
            optional_digest(identity.acquisition_receipt_sha256),
        ),
        (
            "assuranceEpochSha256".to_owned(),
            optional_digest(identity.assurance_epoch_sha256),
        ),
        ("buildInfoLines".to_owned(), build_info),
        (
            "buildInfoSchemaVersion".to_owned(),
            build_info_schema_version,
        ),
        (
            "canonicalPath".to_owned(),
            JsonValue::String(path.to_owned()),
        ),
        (
            "reportedVersion".to_owned(),
            JsonValue::String(identity.reported_version.to_string()),
        ),
        ("compatTracing".to_owned(), compat_tracing),
        ("role".to_owned(), JsonValue::String(role.to_owned())),
        ("schemaVersion".to_owned(), JsonValue::Number(2)),
        (
            "sha256".to_owned(),
            JsonValue::String(identity.sha256.hex()),
        ),
        ("sizeBytes".to_owned(), JsonValue::Number(size)),
    ])))
}

fn benchmark_executable_identity_detail(
    identity: &ExecutableIdentity,
    size: u64,
) -> Result<String, String> {
    let role = match identity.role {
        ExecutableRole::Oracle => "oracle",
        ExecutableRole::Candidate => "candidate",
    };
    let path = identity
        .path
        .to_str()
        .ok_or_else(|| format!("benchmark {role} path is not UTF-8"))?;
    let optional_digest =
        |value: Option<Digest>| value.map_or_else(|| "none".to_owned(), hell_digest::Digest::hex);
    let receipt_id = identity
        .acquisition_receipt_id
        .as_deref()
        .map_or_else(|| "none".to_owned(), |value| format!("{value:?}"));
    let build_info = identity
        .build_info
        .as_ref()
        .map_or_else(|| "none".to_owned(), |info| format!("{:?}", info.lines));
    let build_info_schema_version = identity
        .build_info
        .as_ref()
        .map_or_else(|| "none".to_owned(), |info| info.schema_version.to_string());
    let compat_tracing = identity
        .build_info
        .as_ref()
        .map_or_else(|| "none".to_owned(), |info| info.compat_tracing.to_string());
    Ok(format!(
        "role={role}, canonicalPath={path:?}, sizeBytes={size}, sha256={}, reportedVersion={:?}, assuranceEpochSha256={}, acquisitionReceiptId={}, acquisitionReceiptSha256={}, acquisitionAttestationSha256={}, buildInfoSchemaVersion={}, compatTracing={}, buildInfoLines={}",
        identity.sha256.hex(),
        identity.reported_version,
        optional_digest(identity.assurance_epoch_sha256),
        receipt_id,
        optional_digest(identity.acquisition_receipt_sha256),
        optional_digest(identity.acquisition_attestation_sha256),
        build_info_schema_version,
        compat_tracing,
        build_info,
    ))
}

fn report_candidate_compat_tracing_preflight(
    report: &mut Report,
    name: &str,
    identity: &ExecutableIdentity,
) -> Result<(), String> {
    match hell_testkit::verify_compat_tracing_candidate_identity(identity) {
        Ok(()) => {
            report.check(name, Duration::ZERO, Ok(()));
            Ok(())
        }
        Err(error) => {
            let detail = format!("candidate compatibility tracing attestation failed: {error}");
            report.check(name, Duration::ZERO, Err(detail.clone()));
            Err(detail)
        }
    }
}

fn report_benchmark_artifact_identity(
    report: &mut Report,
    name: &str,
    identity: &BenchmarkArtifactIdentity,
) -> Result<(), String> {
    let path = identity
        .path
        .to_str()
        .ok_or_else(|| format!("benchmark {name} path is not UTF-8"))?;
    report.measurement(
        format!("native-benchmark-{name}-identity"),
        Duration::ZERO,
        format!(
            "role={name}, canonicalPath={path:?}, sizeBytes={}, sha256={}",
            identity.size,
            identity.sha256.hex(),
        ),
    );
    Ok(())
}

fn report_artifact_identity(
    report: &mut Report,
    name: &str,
    identity: &BenchmarkArtifactIdentity,
) -> Result<(), String> {
    let path = identity
        .path
        .to_str()
        .ok_or_else(|| format!("differential {name} path is not UTF-8"))?;
    report.evidence(
        format!("conformance-{name}-identity"),
        JsonValue::Object(BTreeMap::from([
            (
                "canonicalPath".to_owned(),
                JsonValue::String(path.to_owned()),
            ),
            ("role".to_owned(), JsonValue::String(name.to_owned())),
            ("schemaVersion".to_owned(), JsonValue::Number(1)),
            (
                "sha256".to_owned(),
                JsonValue::String(identity.sha256.hex()),
            ),
            ("sizeBytes".to_owned(), JsonValue::Number(identity.size)),
        ])),
    );
    Ok(())
}

fn differential_mismatch_summary(
    authoritative_index: usize,
    case: &DifferentialCase,
    report: &DifferentialReport,
) -> Result<JsonValue, String> {
    let mismatch = report
        .mismatches
        .iter()
        .map(|mismatch| {
            Ok(JsonValue::Object(BTreeMap::from([
                (
                    "candidate".to_owned(),
                    mismatch_side_json(&mismatch.candidate)?,
                ),
                (
                    "kind".to_owned(),
                    JsonValue::String(mismatch_kind_name(mismatch.kind).to_owned()),
                ),
                ("oracle".to_owned(), mismatch_side_json(&mismatch.oracle)?),
            ])))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut summary = BTreeMap::from([
        (
            "authoritativeIndex".to_owned(),
            JsonValue::Number(
                authoritative_index
                    .try_into()
                    .map_err(|_| "differential authoritative index overflow")?,
            ),
        ),
        (
            "candidate".to_owned(),
            observation_status_json(&report.candidate),
        ),
        ("caseId".to_owned(), JsonValue::String(case.id.to_string())),
        ("mismatches".to_owned(), JsonValue::Array(mismatch)),
        ("oracle".to_owned(), observation_status_json(&report.oracle)),
    ]);
    if let Some(rejection) =
        hell_testkit::runtime_failure_projection_rejection(case, &report.oracle, &report.candidate)
    {
        summary.insert(
            "strictProjectionRejection".to_owned(),
            runtime_failure_projection_rejection_json(&rejection)?,
        );
    }
    if let Some(payload) =
        hell_testkit::runtime_failure_payload_diagnostic(case, &report.oracle, &report.candidate)
    {
        summary.insert(
            "strictProjectionPayloadDiagnostic".to_owned(),
            runtime_failure_payload_diagnostic_json(&payload),
        );
    }
    Ok(JsonValue::Object(summary))
}

#[cfg(any(windows, test))]
const WINDOWS_SUBSTANTIVE_SERIAL_PROBES: &[(usize, &str)] = &[
    (865, "runtime-typed-thread-delay-forced-argument-failure"),
    (1081, "runtime-directory-copy-file-failure"),
    (2658, "runtime-interaction-timeout-process"),
];

#[cfg(any(windows, test))]
fn windows_substantive_serial_probe_cases(
    cases: &[DifferentialCase],
) -> Result<Vec<(usize, DifferentialCase)>, String> {
    WINDOWS_SUBSTANTIVE_SERIAL_PROBES
        .iter()
        .map(|&(index, expected_id)| {
            let case = cases.get(index).ok_or_else(|| {
                format!("Windows substantive serial probe index {index} is absent")
            })?;
            if case.id.as_ref() != expected_id {
                return Err(format!(
                    "Windows substantive serial probe index {index} resolved to {:?}, expected {expected_id:?}",
                    case.id,
                ));
            }
            Ok((index, case.clone()))
        })
        .collect()
}

fn runtime_failure_projection_rejection_json(
    rejection: &hell_testkit::RuntimeFailureProjectionRejection,
) -> Result<JsonValue, String> {
    let count = |value: usize| {
        value
            .try_into()
            .map(JsonValue::Number)
            .map_err(|_| "runtime failure projection diagnostic count overflow".to_owned())
    };
    Ok(JsonValue::Object(BTreeMap::from([
        (
            "candidateStderrBytes".to_owned(),
            JsonValue::Number(rejection.candidate_stderr_bytes),
        ),
        (
            "candidateStderrSha256".to_owned(),
            JsonValue::String(rejection.candidate_stderr_sha256.hex()),
        ),
        (
            "causalOrderCount".to_owned(),
            count(rejection.causal_order_count)?,
        ),
        (
            "descriptorBuiltin".to_owned(),
            JsonValue::String(rejection.descriptor_builtin.to_owned()),
        ),
        (
            "descriptorDimension".to_owned(),
            JsonValue::String(
                compatibility_dimension_name(rejection.descriptor_dimension).to_owned(),
            ),
        ),
        (
            "descriptorObligation".to_owned(),
            JsonValue::String(rejection.descriptor_obligation.to_owned()),
        ),
        (
            "effectEventCount".to_owned(),
            count(rejection.effect_event_count)?,
        ),
        (
            "exceptionFamily".to_owned(),
            JsonValue::String(rejection.exception_family.descriptor_name().to_owned()),
        ),
        (
            "forceEventCount".to_owned(),
            count(rejection.force_event_count)?,
        ),
        (
            "obligationEventCount".to_owned(),
            count(rejection.obligation_event_count)?,
        ),
        (
            "oracleStderrBytes".to_owned(),
            JsonValue::Number(rejection.oracle_stderr_bytes),
        ),
        (
            "oracleStderrSha256".to_owned(),
            JsonValue::String(rejection.oracle_stderr_sha256.hex()),
        ),
        (
            "reason".to_owned(),
            JsonValue::String(rejection.reason.descriptor_name().to_owned()),
        ),
        (
            "resourceEventCount".to_owned(),
            count(rejection.resource_event_count)?,
        ),
        (
            "semanticCoverageCount".to_owned(),
            count(rejection.semantic_coverage_count)?,
        ),
        (
            "semanticPresent".to_owned(),
            JsonValue::Bool(rejection.semantic_present),
        ),
        (
            "taskEventCount".to_owned(),
            count(rejection.task_event_count)?,
        ),
        (
            "typedResultBuiltinPresent".to_owned(),
            JsonValue::Bool(rejection.typed_result_builtin_present),
        ),
        (
            "typedResultSha256Present".to_owned(),
            JsonValue::Bool(rejection.typed_result_sha256_present),
        ),
    ])))
}

fn runtime_failure_payload_component_json(
    component: &hell_testkit::RuntimeFailurePayloadComponentDiagnostic,
) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        ("bytes".to_owned(), JsonValue::Number(component.bytes)),
        (
            "prefixTruncated".to_owned(),
            JsonValue::Bool(component.prefix_truncated),
        ),
        (
            "sha256".to_owned(),
            JsonValue::String(component.sha256.hex()),
        ),
        (
            "utf8Prefix".to_owned(),
            JsonValue::String(component.utf8_prefix.clone()),
        ),
    ]))
}

fn runtime_failure_payload_diagnostic_json(
    diagnostic: &hell_testkit::RuntimeFailurePayloadDiagnostic,
) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        (
            "candidate".to_owned(),
            runtime_failure_payload_component_json(&diagnostic.candidate),
        ),
        (
            "handlingProjection".to_owned(),
            JsonValue::String(diagnostic.handling_projection.to_owned()),
        ),
        (
            "mismatchField".to_owned(),
            JsonValue::String(diagnostic.mismatch_field.to_owned()),
        ),
        (
            "oracleHandling".to_owned(),
            diagnostic
                .oracle_handling
                .as_ref()
                .map_or(JsonValue::Null, runtime_failure_payload_component_json),
        ),
        (
            "oracleOuter".to_owned(),
            runtime_failure_payload_component_json(&diagnostic.oracle_outer),
        ),
        (
            "oracleSelected".to_owned(),
            runtime_failure_payload_component_json(&diagnostic.oracle_selected),
        ),
        (
            "oracleSelection".to_owned(),
            JsonValue::String(diagnostic.oracle_selection.descriptor_name().to_owned()),
        ),
        (
            "relationship".to_owned(),
            JsonValue::String(diagnostic.relationship.descriptor_name().to_owned()),
        ),
    ]))
}

const fn compatibility_dimension_name(
    dimension: hell_builtins::CompatibilityDimension,
) -> &'static str {
    use hell_builtins::CompatibilityDimension;
    match dimension {
        CompatibilityDimension::Parse => "parse",
        CompatibilityDimension::StaticSemantics => "static-semantics",
        CompatibilityDimension::PureRuntime => "pure-runtime",
        CompatibilityDimension::Effects => "effects",
        CompatibilityDimension::Concurrency => "concurrency",
        CompatibilityDimension::Presentation => "presentation",
        CompatibilityDimension::Platform => "platform",
        CompatibilityDimension::ResourceBehavior => "resource-behavior",
    }
}

fn observation_status_json(observation: &hell_testkit::Observation) -> JsonValue {
    process_status_json(
        observation.timed_out,
        observation.status.success,
        observation.status.code,
    )
}

fn process_status_json(timed_out: bool, success: bool, code: Option<i32>) -> JsonValue {
    let code = code.map_or(JsonValue::Null, |code| JsonValue::String(code.to_string()));
    JsonValue::Object(BTreeMap::from([
        ("exitCode".to_owned(), code),
        ("success".to_owned(), JsonValue::Bool(success)),
        ("timedOut".to_owned(), JsonValue::Bool(timed_out)),
    ]))
}

fn mismatch_side_json(bytes: &[u8]) -> Result<JsonValue, String> {
    let mut prefix = String::with_capacity(BENCHMARK_MISMATCH_PREFIX_BYTES.saturating_mul(2));
    for byte in bytes.iter().take(BENCHMARK_MISMATCH_PREFIX_BYTES) {
        write!(prefix, "{byte:02x}").expect("writing hexadecimal bytes to String cannot fail");
    }
    Ok(JsonValue::Object(BTreeMap::from([
        (
            "bytes".to_owned(),
            JsonValue::Number(
                bytes
                    .len()
                    .try_into()
                    .map_err(|_| "differential mismatch side length overflow")?,
            ),
        ),
        ("prefixHex".to_owned(), JsonValue::String(prefix)),
        (
            "prefixTruncated".to_owned(),
            JsonValue::Bool(bytes.len() > BENCHMARK_MISMATCH_PREFIX_BYTES),
        ),
        (
            "sha256".to_owned(),
            JsonValue::String(sha256_bytes(bytes).hex()),
        ),
    ])))
}

fn mismatch_kind_name(kind: MismatchKind) -> &'static str {
    match kind {
        MismatchKind::Timeout => "timeout",
        MismatchKind::ExitStatus => "exit-status",
        MismatchKind::Stdout => "stdout",
        MismatchKind::Stderr => "stderr",
        MismatchKind::Diagnostic => "diagnostic",
        MismatchKind::Filesystem => "filesystem",
    }
}

struct DifferentialInventoryEvidence {
    authoritative_case_count: usize,
    authoritative_inventory_sha256: Digest,
    combined_inventory_count: usize,
    combined_inventory_sha256: Digest,
    generated_case_count: usize,
    generated_seed: u64,
    mismatches: Vec<JsonValue>,
}

fn differential_inventory_evidence_json(
    evidence: DifferentialInventoryEvidence,
) -> Result<JsonValue, String> {
    let mismatch_count = evidence.mismatches.len();
    Ok(JsonValue::Object(BTreeMap::from([
        (
            "authoritativeCaseCount".to_owned(),
            JsonValue::Number(
                evidence
                    .authoritative_case_count
                    .try_into()
                    .map_err(|_| "committed differential case count overflow")?,
            ),
        ),
        (
            "authoritativeInventorySha256".to_owned(),
            JsonValue::String(evidence.authoritative_inventory_sha256.hex()),
        ),
        ("cases".to_owned(), JsonValue::Array(evidence.mismatches)),
        (
            "combinedInventoryCount".to_owned(),
            JsonValue::Number(
                evidence
                    .combined_inventory_count
                    .try_into()
                    .map_err(|_| "combined differential case count overflow")?,
            ),
        ),
        (
            "combinedInventorySha256".to_owned(),
            JsonValue::String(evidence.combined_inventory_sha256.hex()),
        ),
        (
            "generatedCaseCount".to_owned(),
            JsonValue::Number(
                evidence
                    .generated_case_count
                    .try_into()
                    .map_err(|_| "generated differential case count overflow")?,
            ),
        ),
        (
            "generatedSeed".to_owned(),
            JsonValue::Number(evidence.generated_seed),
        ),
        (
            "mismatchCount".to_owned(),
            JsonValue::Number(
                mismatch_count
                    .try_into()
                    .map_err(|_| "committed mismatch count overflow")?,
            ),
        ),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
    ])))
}

fn native_benchmark_inventory() -> Vec<DifferentialCase> {
    let mut inventory = committed_differential_cases();
    inventory.extend(
        generated_typed_cases(0x4845_4c4c, 32)
            .into_iter()
            .map(|case| DifferentialCase {
                id: case.id,
                source: case.source,
                ..DifferentialCase::default()
            }),
    );
    inventory
}

fn report_benchmark_inventory(
    report: &mut Report,
    sample: &hell_testkit::RepresentativeDifferentialSample,
) {
    let selected = sample
        .selected_indices
        .iter()
        .zip(&sample.cases)
        .map(|(index, case)| format!("{index}:{:?}", case.id))
        .collect::<Vec<_>>()
        .join(",");
    report.measurement(
        "native-benchmark-inventory",
        Duration::ZERO,
        format!(
            "authoritative=false, inventoryCount={}, inventorySha256={}, sampleCount={}, selected=[{}]",
            sample.inventory_count,
            sample.inventory_sha256.hex(),
            sample.cases.len(),
            selected,
        ),
    );
}

fn report_benchmark_metrics(report: &mut Report, metrics: DifferentialMetrics) {
    report.measurement(
        "native-benchmark-oracle-execution",
        metrics.timing.oracle_process_sum,
        metrics.detail(),
    );
    report.measurement(
        "native-benchmark-candidate-execution",
        metrics.timing.candidate_process_sum,
        metrics.detail(),
    );
    report.measurement(
        "native-benchmark-driver-overhead",
        metrics.timing.driver_overhead_sum,
        metrics.detail(),
    );
}

fn report_benchmark_timings(
    report: &mut Report,
    cases: &[DifferentialCase],
    inventory_indices: &[usize],
    timings: &[DifferentialTiming],
    aggregate: DifferentialBatchTiming,
    inventory_count: usize,
) {
    debug_assert_eq!(cases.len(), inventory_indices.len());
    debug_assert_eq!(cases.len(), timings.len());
    for (sample_index, ((case, inventory_index), timing)) in
        cases.iter().zip(inventory_indices).zip(timings).enumerate()
    {
        let total = timing
            .oracle_process
            .saturating_add(timing.candidate_process)
            .saturating_add(timing.driver_overhead);
        report.measurement(
            format!("native-benchmark-case-{sample_index:03}"),
            total,
            format!(
                "authoritativeIndex={inventory_index}, caseId={:?}, oracleMicros={}, candidateMicros={}, driverMicros={}, totalMicros={}",
                case.id,
                timing.oracle_process.as_micros(),
                timing.candidate_process.as_micros(),
                timing.driver_overhead.as_micros(),
                total.as_micros(),
            ),
        );
    }
    let oracle = timings
        .iter()
        .map(|timing| timing.oracle_process.as_micros())
        .collect::<Vec<_>>();
    let candidate = timings
        .iter()
        .map(|timing| timing.candidate_process.as_micros())
        .collect::<Vec<_>>();
    let driver = timings
        .iter()
        .map(|timing| timing.driver_overhead.as_micros())
        .collect::<Vec<_>>();
    let total = timings
        .iter()
        .map(|timing| {
            timing
                .oracle_process
                .saturating_add(timing.candidate_process)
                .saturating_add(timing.driver_overhead)
                .as_micros()
        })
        .collect::<Vec<_>>();
    report.measurement(
        "native-benchmark-distribution",
        aggregate.wall,
        [
            timing_distribution_detail("oracle", &oracle, cases, inventory_indices),
            timing_distribution_detail("candidate", &candidate, cases, inventory_indices),
            timing_distribution_detail("driver", &driver, cases, inventory_indices),
            timing_distribution_detail("total", &total, cases, inventory_indices),
        ]
        .join("; "),
    );
    let projected_full_wall_micros = aggregate
        .wall
        .as_micros()
        .saturating_mul(inventory_count as u128)
        .div_ceil(cases.len() as u128);
    report.measurement(
        "native-benchmark-projection",
        aggregate.wall,
        format!(
            "sampleWallMicros={}, sampleCount={}, inventoryCount={}, projectedFullDifferentialWallMicros={}, workerCount={}; projection is non-authoritative and timing never participates in conformance",
            aggregate.wall.as_micros(),
            cases.len(),
            inventory_count,
            projected_full_wall_micros,
            aggregate.worker_count,
        ),
    );
}

fn timing_distribution_detail(
    role: &str,
    values: &[u128],
    cases: &[DifferentialCase],
    inventory_indices: &[usize],
) -> String {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let percentile = |percent: usize| {
        let rank = values.len().saturating_mul(percent).div_ceil(100);
        sorted[rank.clamp(1, sorted.len()) - 1]
    };
    let mut worst = 0;
    for index in 1..values.len() {
        if values[index] > values[worst] {
            worst = index;
        }
    }
    format!(
        "{role}Micros[p50={},p95={},p99={},max={},worstAuthoritativeIndex={},worstCaseId={:?}]",
        percentile(50),
        percentile(95),
        percentile(99),
        values[worst],
        inventory_indices[worst],
        cases[worst].id,
    )
}

pub(crate) fn release_native_oracle_shard(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    source: &Path,
    platform: &str,
    dependency: &Path,
    candidate_sha: Option<&str>,
) -> Result<(), FailureKind> {
    policy_suite(root, report)?;
    if !matches!(platform, "macos-arm64" | "windows-amd64") {
        report.check(
            "native-platform",
            Duration::ZERO,
            Err(format!("unsupported native platform {platform}")),
        );
        return Err(FailureKind::Policy);
    }
    crate::command::verify_pinned_oracle_checkout(source).map_err(|_| FailureKind::Fixture)?;
    let archive_adapter = crate::command::NativeArchiveAdapter::for_macos(
        platform == "macos-arm64",
        &root.join("target"),
        source,
        None,
    );
    let archive_adapter = match archive_adapter {
        Ok(adapter) => adapter,
        Err(error) => {
            report.check("native-archiver-setup", Duration::ZERO, Err(error));
            return Err(FailureKind::Child);
        }
    };
    let primary = (|| {
        if let Some(identity) = archive_adapter.identity_command() {
            run_spec(report, "native-archiver-identity", &identity)?;
        }
        let build = archive_adapter.stack_build(source, Duration::from_hours(2));
        let path = archive_adapter.stack_path(source);
        let provenance = archive_adapter.stack_provenance(source).map_err(|error| {
            report.check("native-stack-provenance", Duration::ZERO, Err(error));
            FailureKind::Fixture
        })?;
        report_native_stack_provenance(report, &provenance, &build, &path).map_err(|error| {
            report.check("native-stack-provenance", Duration::ZERO, Err(error));
            FailureKind::Fixture
        })?;
        run_spec(report, "native-oracle-build", &build)?;
        let oracle = stack_oracle(report, &path)?;
        crate::command::verify_pinned_oracle_checkout(source).map_err(|_| FailureKind::Fixture)?;
        let candidate = candidate_binary(root, true);
        differential_gate(
            report,
            &DifferentialExecution {
                root,
                failures,
                oracle: &oracle,
                oracle_digest: None,
                candidate: &candidate,
                dependency,
                candidate_sha,
            },
        )?;
        crate::command::verify_pinned_oracle_checkout(source).map_err(|_| FailureKind::Fixture)
    })();
    let cleanup = archive_adapter.close();
    if let Err(error) = cleanup {
        report.check("native-archiver-cleanup", Duration::ZERO, Err(error));
        if primary.is_ok() {
            return Err(FailureKind::Child);
        }
    }
    primary
}

fn report_native_stack_provenance(
    report: &mut Report,
    provenance: &crate::command::NativeStackProvenance,
    build: &CommandSpec,
    path: &CommandSpec,
) -> Result<(), String> {
    let utf8_path = |label: &str, value: &Path| {
        value
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("native {label} path is not UTF-8"))
    };
    let optional_path = provenance
        .llvm_ar
        .as_deref()
        .map(|value| utf8_path("LLVM archiver", value).map(JsonValue::String))
        .transpose()?
        .unwrap_or(JsonValue::Null);
    let optional_digest = provenance
        .llvm_ar_sha256
        .map_or(JsonValue::Null, |value| JsonValue::String(value.hex()));
    let optional_version = provenance
        .llvm_ar_version
        .as_ref()
        .map_or(JsonValue::Null, |value| JsonValue::String(value.clone()));
    report.evidence(
        "native-stack-provenance",
        JsonValue::Object(BTreeMap::from([
            ("buildCommand".to_owned(), command_json(build)),
            (
                "effectiveStackYaml".to_owned(),
                JsonValue::String(utf8_path(
                    "effective Stack configuration",
                    &provenance.effective_stack_yaml,
                )?),
            ),
            (
                "effectiveStackYamlSha256".to_owned(),
                JsonValue::String(provenance.effective_stack_yaml_sha256.hex()),
            ),
            ("llvmAr".to_owned(), optional_path),
            ("llvmArSha256".to_owned(), optional_digest),
            ("llvmArVersion".to_owned(), optional_version),
            ("pathCommand".to_owned(), command_json(path)),
            ("schemaVersion".to_owned(), JsonValue::Number(1)),
            (
                "sourceCommit".to_owned(),
                JsonValue::String(provenance.source_commit.to_owned()),
            ),
            (
                "sourcePath".to_owned(),
                JsonValue::String(utf8_path("oracle source", &provenance.source)?),
            ),
            (
                "stackLockSha256".to_owned(),
                JsonValue::String(provenance.stack_lock_sha256.hex()),
            ),
            (
                "stackYamlSha256".to_owned(),
                JsonValue::String(provenance.stack_yaml_sha256.hex()),
            ),
        ])),
    );
    Ok(())
}

fn command_json(spec: &CommandSpec) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        (
            "arguments".to_owned(),
            JsonValue::Array(
                spec.display_arguments()
                    .into_iter()
                    .map(JsonValue::String)
                    .collect(),
            ),
        ),
        (
            "program".to_owned(),
            JsonValue::String(spec.display_program()),
        ),
    ]))
}

pub(crate) fn examples(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    profile: &str,
) -> Result<(), FailureKind> {
    if !matches!(profile, "ci" | "release") {
        report.check(
            "examples-profile",
            Duration::ZERO,
            Err("invalid examples profile".to_owned()),
        );
        return Err(FailureKind::Policy);
    }
    let result = crate::fixtures::run_examples(root, profile, report, failures);
    let passed = result.is_ok();
    report.check("release-examples", Duration::ZERO, result);
    passed.then_some(()).ok_or(FailureKind::Fixture)
}

fn fixture_gate(root: &Path, report: &mut Report, failures: &Path) -> Result<(), FailureKind> {
    let started = Instant::now();
    let result = crate::fixtures::validate_inventory(root);
    let passed = result.is_ok();
    report.check("fixture-inventory", started.elapsed(), result);
    if !passed {
        fs::create_dir_all(failures).ok();
    }
    passed.then_some(()).ok_or(FailureKind::Fixture)
}

fn portability_fixture_gate(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    deadline: Instant,
) -> Result<(), FailureKind> {
    let started = Instant::now();
    let result = run_before_portability_deadline(deadline, "fixture inventory", || {
        crate::fixtures::validate_inventory(root)
    })
    .and_then(|()| require_portability_deadline(deadline, "fixture inventory completion"));
    let passed = result.is_ok();
    report.check("fixture-inventory", started.elapsed(), result);
    if !passed {
        fs::create_dir_all(failures).ok();
    }
    passed.then_some(()).ok_or(FailureKind::Fixture)
}

fn differential_gate(
    report: &mut Report,
    execution: &DifferentialExecution<'_>,
) -> Result<(), FailureKind> {
    let started = Instant::now();
    let result = run_differential(report, execution);
    let (metrics, result) = match result {
        Ok(outcome) => {
            let result = if outcome.committed_mismatches == 0 {
                Ok(())
            } else {
                Err(format!(
                    "{} committed differential cases mismatch",
                    outcome.committed_mismatches
                ))
            };
            (Some(outcome.metrics), result)
        }
        Err(error) => (None, Err(error)),
    };
    let passed = result.is_ok();
    if let Some(metrics) = metrics {
        report_differential_metrics(report, metrics);
    }
    report.check("conformance-differential", started.elapsed(), result);
    passed.then_some(()).ok_or(FailureKind::Fixture)
}

fn report_differential_metrics(report: &mut Report, metrics: DifferentialMetrics) {
    report.measurement(
        "conformance-oracle-execution",
        metrics.timing.oracle_process_sum,
        metrics.detail(),
    );
    report.measurement(
        "conformance-candidate-execution",
        metrics.timing.candidate_process_sum,
        metrics.detail(),
    );
    report.measurement(
        "conformance-driver-overhead",
        metrics.timing.driver_overhead_sum,
        metrics.detail(),
    );
}

#[derive(Clone, Copy, Debug, Default)]
struct DifferentialMetrics {
    timing: DifferentialBatchTiming,
}

#[derive(Clone, Copy, Debug, Default)]
struct DifferentialOutcome {
    metrics: DifferentialMetrics,
    committed_mismatches: usize,
}

impl DifferentialMetrics {
    fn add(&mut self, timing: DifferentialBatchTiming) {
        self.timing.case_count = self.timing.case_count.saturating_add(timing.case_count);
        self.timing.completed_count = self
            .timing
            .completed_count
            .saturating_add(timing.completed_count);
        self.timing.worker_count = self.timing.worker_count.max(timing.worker_count);
        self.timing.wall = self.timing.wall.saturating_add(timing.wall);
        self.timing.oracle_process_sum = self
            .timing
            .oracle_process_sum
            .saturating_add(timing.oracle_process_sum);
        self.timing.candidate_process_sum = self
            .timing
            .candidate_process_sum
            .saturating_add(timing.candidate_process_sum);
        self.timing.driver_overhead_sum = self
            .timing
            .driver_overhead_sum
            .saturating_add(timing.driver_overhead_sum);
    }

    fn detail(self) -> String {
        format!(
            "caseCount={}, completedCount={}, workerCount={}, batchWallMillis={}, oracleProcessSumMillis={}, candidateProcessSumMillis={}, driverOverheadSumMillis={}; process sums can exceed wall when workers overlap and timing never participates in conformance",
            self.timing.case_count,
            self.timing.completed_count,
            self.timing.worker_count,
            self.timing.wall.as_millis(),
            self.timing.oracle_process_sum.as_millis(),
            self.timing.candidate_process_sum.as_millis(),
            self.timing.driver_overhead_sum.as_millis(),
        )
    }
}

fn batch_failure(error: &hell_testkit::DifferentialBatchFailure) -> String {
    let timing = DifferentialMetrics {
        timing: error.timing,
    };
    format!("{error}; {}", timing.detail())
}

struct DifferentialExecution<'a> {
    root: &'a Path,
    failures: &'a Path,
    oracle: &'a Path,
    oracle_digest: Option<Digest>,
    candidate: &'a Path,
    dependency: &'a Path,
    candidate_sha: Option<&'a str>,
}

fn run_differential(
    report: &mut Report,
    execution: &DifferentialExecution<'_>,
) -> Result<DifferentialOutcome, String> {
    verify_dependency(
        execution.root,
        execution.dependency,
        execution.candidate_sha,
    )?;
    let oracle_source = verify_executable(
        execution.oracle,
        ExecutableRole::Oracle,
        execution.oracle_digest,
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| format!("cannot verify oracle: {error}"))?;
    let candidate_identity = verify_executable(
        execution.candidate,
        ExecutableRole::Candidate,
        None,
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| format!("cannot verify candidate: {error}"))?;
    let output_root = execution
        .failures
        .parent()
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(output_root)
        .map_err(|error| format!("cannot create differential output: {error}"))?;
    let oracle = exact_oracle_invocation(output_root, &oracle_source)?;
    let candidate =
        ExecutableInvocationAuthority::exact_hell(&candidate_identity, &candidate_identity)
            .map_err(|error| format!("cannot bind exact candidate invocation: {error}"))?;
    report_executable_identity(report, "oracle", &oracle_source)?;
    report_executable_identity(report, "candidate", &candidate_identity)?;
    report_executable_invocation(report, "oracle", &oracle)?;
    report_executable_invocation(report, "candidate", &candidate)?;
    report_candidate_compat_tracing_preflight(
        report,
        "conformance-candidate-compat-tracing",
        &candidate_identity,
    )?;
    let driver = benchmark_current_driver()?;
    report_artifact_identity(report, "driver", &driver)?;
    run_differential_identities(
        execution.root,
        report,
        execution.failures,
        &oracle,
        &candidate,
    )
}

fn run_differential_identities(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    oracle: &ExecutableInvocationAuthority,
    candidate: &ExecutableInvocationAuthority,
) -> Result<DifferentialOutcome, String> {
    const GENERATED_SEED: u64 = 0x4845_4c4c;
    let DifferentialInventories {
        mut cases,
        generated,
        committed_sha256,
        combined_count,
        combined_sha256,
    } = differential_inventories(GENERATED_SEED)?;
    let helper = bind_helper(&mut cases)?;
    report_artifact_identity(report, "helper", &helper)?;
    let output_root = failures.parent().unwrap_or_else(|| Path::new("."));
    let mut cells = reviewed_compatibility_cells();
    let reviewed_cells = cells.len();
    let mut committed_mismatches = Vec::new();
    let workers = differential_worker_limit();
    let committed = differential_batch_with_invocations(oracle, candidate, &cases, workers)
        .map_err(|error| batch_failure(&error))?;
    let mut metrics = DifferentialMetrics::default();
    metrics.add(committed.timing);
    record_committed_differential(
        &cases,
        committed.reports,
        &mut committed_mismatches,
        &mut cells,
    )?;
    let committed_mismatch_count = committed_mismatches.len();
    report.evidence(
        "conformance-differential-mismatches",
        differential_inventory_evidence_json(DifferentialInventoryEvidence {
            authoritative_case_count: cases.len(),
            authoritative_inventory_sha256: committed_sha256,
            combined_inventory_count: combined_count,
            combined_inventory_sha256: combined_sha256,
            generated_case_count: generated.len(),
            generated_seed: GENERATED_SEED,
            mismatches: committed_mismatches,
        })?,
    );
    #[cfg(windows)]
    {
        let probes = windows_substantive_serial_probe_cases(&cases)?;
        let probe_cases = probes
            .iter()
            .map(|(_, case)| case.clone())
            .collect::<Vec<_>>();
        let batch = differential_batch_with_invocations(&oracle, &candidate, &probe_cases, 1)
            .map_err(|error| batch_failure(&error))?;
        metrics.add(batch.timing);
        let observations = probes
            .iter()
            .zip(batch.reports)
            .map(|((index, case), observation)| {
                differential_mismatch_summary(*index, case, &observation)
            })
            .collect::<Result<Vec<_>, _>>()?;
        report.evidence(
            "conformance-substantive-serial-probes",
            JsonValue::Object(BTreeMap::from([
                ("cases".to_owned(), JsonValue::Array(observations)),
                ("schemaVersion".to_owned(), JsonValue::Number(1)),
                ("workerCount".to_owned(), JsonValue::Number(1)),
            ])),
        );
    }
    process_generated_differential(
        output_root,
        oracle,
        candidate,
        &generated,
        workers,
        &mut cells,
        &mut metrics,
    )?;
    write_differential_compatibility(
        root,
        output_root,
        cells,
        reviewed_cells,
        cases.len(),
        generated.len(),
        committed_mismatch_count,
    )?;
    Ok(DifferentialOutcome {
        metrics,
        committed_mismatches: committed_mismatch_count,
    })
}

fn record_committed_differential(
    cases: &[DifferentialCase],
    reports: Vec<DifferentialReport>,
    mismatches: &mut Vec<JsonValue>,
    cells: &mut Vec<JsonValue>,
) -> Result<(), String> {
    for (authoritative_index, (case, result)) in cases.iter().zip(reports).enumerate() {
        let status = if matches!(
            result.comparison_projection,
            hell_testkit::DifferentialComparisonProjection::ReviewedWindowsDivergence { .. }
        ) {
            "deliberate-divergence"
        } else if result.agrees() {
            "exact"
        } else {
            "unverified"
        };
        if !result.agrees() {
            mismatches.push(differential_mismatch_summary(
                authoritative_index,
                case,
                &result,
            )?);
        }
        cells.push(JsonValue::Object(BTreeMap::from([
            ("caseId".to_owned(), JsonValue::String(case.id.to_string())),
            ("status".to_owned(), JsonValue::String(status.to_owned())),
        ])));
    }
    Ok(())
}

struct DifferentialInventories {
    cases: Vec<DifferentialCase>,
    generated: Vec<GeneratedCase>,
    committed_sha256: Digest,
    combined_count: usize,
    combined_sha256: Digest,
}

fn differential_inventories(generated_seed: u64) -> Result<DifferentialInventories, String> {
    let cases = committed_differential_cases();
    let committed_sha256 = differential_inventory_sha256(&cases)?;
    let generated = generated_typed_cases(generated_seed, 32);
    let mut combined = cases.clone();
    combined.extend(generated.iter().map(|case| DifferentialCase {
        id: case.id.clone(),
        source: case.source.clone(),
        ..DifferentialCase::default()
    }));
    let combined_sha256 = differential_inventory_sha256(&combined)?;
    Ok(DifferentialInventories {
        cases,
        generated,
        committed_sha256,
        combined_count: combined.len(),
        combined_sha256,
    })
}

fn process_generated_differential(
    output_root: &Path,
    oracle: &ExecutableInvocationAuthority,
    candidate: &ExecutableInvocationAuthority,
    generated: &[GeneratedCase],
    workers: usize,
    cells: &mut Vec<JsonValue>,
    metrics: &mut DifferentialMetrics,
) -> Result<(), String> {
    let generated_cases = generated
        .iter()
        .map(|case| DifferentialCase {
            id: case.id.clone(),
            source: case.source.clone(),
            ..DifferentialCase::default()
        })
        .collect::<Vec<_>>();
    let batch = differential_batch_with_invocations(oracle, candidate, &generated_cases, workers)
        .map_err(|error| batch_failure(&error))?;
    metrics.add(batch.timing);
    let mut mismatches = Vec::new();
    for (case, result) in generated.iter().zip(batch.reports) {
        if !result.agrees() {
            retain_generated_mismatch(output_root, case)?;
            mismatches.push(case.id.to_string());
        }
        cells.push(JsonValue::Object(BTreeMap::from([
            ("caseId".to_owned(), JsonValue::String(case.id.to_string())),
            (
                "status".to_owned(),
                JsonValue::String("out-of-scope".to_owned()),
            ),
        ])));
    }
    write_generated_inventory(output_root, &mismatches)
}

fn write_differential_compatibility(
    root: &Path,
    output_root: &Path,
    cells: Vec<JsonValue>,
    reviewed_cells: usize,
    committed_case_count: usize,
    generated_count: usize,
    committed_mismatch_count: usize,
) -> Result<(), String> {
    let deliberate_divergences = count_status(&cells, "deliberate-divergence")?;
    let out_of_scope_cells = count_status(&cells, "out-of-scope")?;
    let unverified_cells = count_status(&cells, "unverified")?;
    let compatibility = JsonValue::Object(BTreeMap::from([
        (
            "baselineSha256".to_owned(),
            JsonValue::String(baseline_digest(root)?),
        ),
        ("cells".to_owned(), JsonValue::Array(cells)),
        (
            "committedCells".to_owned(),
            JsonValue::Number(
                (reviewed_cells + committed_case_count)
                    .try_into()
                    .map_err(|_| "case count overflow")?,
            ),
        ),
        (
            "deliberateDivergences".to_owned(),
            JsonValue::Number(deliberate_divergences),
        ),
        (
            "generatedObservations".to_owned(),
            JsonValue::Number(
                generated_count
                    .try_into()
                    .map_err(|_| "case count overflow")?,
            ),
        ),
        (
            "outOfScopeCells".to_owned(),
            JsonValue::Number(out_of_scope_cells),
        ),
        (
            "profile".to_owned(),
            JsonValue::String("bounded".to_owned()),
        ),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
        (
            "unverifiedCells".to_owned(),
            JsonValue::Number(unverified_cells),
        ),
    ]));
    crate::release::manifest::write_atomic(
        &output_root.join("compatibility-report.json"),
        &canonical_json_bytes(&compatibility)?,
    )?;
    crate::release::manifest::write_atomic(
        &output_root.join("compatibility-report.html"),
        format!(
            "<!doctype html>\n<meta charset=\"utf-8\">\n<title>Bounded compatibility</title>\n<p>{} committed observations agree; {} reviewed cells remain unverified; {} cells are out of scope.</p>\n",
            committed_case_count.saturating_sub(committed_mismatch_count),
            unverified_cells,
            out_of_scope_cells
        )
        .as_bytes(),
    )?;
    Ok(())
}

fn reviewed_compatibility_cells() -> Vec<JsonValue> {
    let mut cells = Vec::new();
    for claim in hell_builtins::compatibility_requirements() {
        for dimension in &claim.dimensions {
            for scope in dimension.scopes {
                for profile in scope.profiles {
                    for platform in scope.platforms {
                        let platform = match platform {
                            hell_builtins::RequirementPlatform::LinuxX86_64 => "linux-x86_64",
                            hell_builtins::RequirementPlatform::MacosAarch64 => "macos-aarch64",
                            hell_builtins::RequirementPlatform::WindowsX86_64 => "windows-x86_64",
                        };
                        cells.push(JsonValue::Object(BTreeMap::from([
                            (
                                "caseId".to_owned(),
                                JsonValue::String(format!(
                                    "claim-{}-{}-{}-{platform}",
                                    claim.builtin.0,
                                    dimension.dimension.as_str(),
                                    profile.as_str(),
                                )),
                            ),
                            (
                                "status".to_owned(),
                                JsonValue::String("unverified".to_owned()),
                            ),
                        ])));
                    }
                }
            }
        }
    }
    cells
}

fn count_status(cells: &[JsonValue], expected: &str) -> Result<u64, String> {
    cells.iter().try_fold(0_u64, |count, cell| {
        Ok(count
            + u64::from(crate::json::json_member(cell.object()?, "status")?.string()? == expected))
    })
}

fn retain_generated_mismatch(root: &Path, case: &GeneratedCase) -> Result<(), String> {
    let directory = root
        .join("mismatches/proposed-regressions")
        .join(case.id.as_ref());
    fs::create_dir_all(&directory)
        .map_err(|error| format!("cannot create generated mismatch directory: {error}"))?;
    crate::release::manifest::write_atomic(&directory.join("main.hell"), case.source.as_bytes())?;
    let descriptor = JsonValue::Object(BTreeMap::from([
        ("caseId".to_owned(), JsonValue::String(case.id.to_string())),
        (
            "sourceSha256".to_owned(),
            JsonValue::String(sha256_bytes(case.source.as_bytes()).hex()),
        ),
        (
            "state".to_owned(),
            JsonValue::String("unreviewed-nonclaim".to_owned()),
        ),
    ]));
    crate::release::manifest::write_atomic(
        &directory.join("descriptor.json"),
        &canonical_json_bytes(&descriptor)?,
    )
}

fn write_generated_inventory(root: &Path, ids: &[String]) -> Result<(), String> {
    let inventory = JsonValue::Object(BTreeMap::from([
        (
            "caseIds".to_owned(),
            JsonValue::Array(ids.iter().cloned().map(JsonValue::String).collect()),
        ),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
    ]));
    crate::release::manifest::write_atomic(
        &root.join("generated-regression-inventory.json"),
        &canonical_json_bytes(&inventory)?,
    )
}

fn baseline_digest(root: &Path) -> Result<String, String> {
    let bytes =
        crate::release::manifest::read_regular(&root.join("compat/upstream-2026-05-29.json"))?;
    Ok(sha256_bytes(&bytes).hex())
}

fn bind_helper(cases: &mut [DifferentialCase]) -> Result<BenchmarkArtifactIdentity, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot locate assurance driver: {error}"))?;
    let directory = executable
        .parent()
        .ok_or_else(|| "assurance driver has no directory".to_owned())?;
    let profile = if directory.file_name().is_some_and(|name| name == "deps") {
        directory.parent().unwrap_or(directory)
    } else {
        directory
    };
    let sha256 = bind_process_helper_directory(cases, profile)?;
    let path = profile
        .join(format!("hell-test-helper{}", std::env::consts::EXE_SUFFIX))
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize process helper: {error}"))?;
    let size = fs::metadata(&path)
        .map_err(|error| format!("cannot inspect process helper: {error}"))?
        .len();
    Ok(BenchmarkArtifactIdentity { path, sha256, size })
}

fn verify_dependency(root: &Path, path: &Path, candidate_sha: Option<&str>) -> Result<(), String> {
    let value = crate::release::manifest::read_json(path)?;
    let object = value.object()?;
    crate::json::require_exact_json_keys(
        object,
        &[
            "candidateSourceCommit",
            "cargoLockSha256",
            "denyPolicySha256",
            "result",
            "schemaVersion",
            "workflow",
        ],
    )?;
    require_git_sha(
        crate::json::json_member(object, "candidateSourceCommit")?.string()?,
        "dependency candidate commit",
    )?;
    if let Some(expected) = candidate_sha
        && crate::json::json_member(object, "candidateSourceCommit")?.string()? != expected
    {
        return Err("dependency attestation differs from planned candidate".to_owned());
    }
    let workflow = crate::json::json_member(object, "workflow")?.string()?;
    if crate::json::json_member(object, "cargoLockSha256")?.string()?
        != sha256_file(&root.join("Cargo.lock"))
            .map_err(|error| format!("cannot hash Cargo.lock: {error}"))?
            .hex()
        || crate::json::json_member(object, "denyPolicySha256")?.string()?
            != sha256_file(&root.join("deny.toml"))
                .map_err(|error| format!("cannot hash deny.toml: {error}"))?
                .hex()
        || crate::json::json_member(object, "result")?.string()? != "passed"
        || crate::json::json_member(object, "schemaVersion")?.number()? != 1
        || (candidate_sha.is_some() && workflow != "release.yml")
        || (candidate_sha.is_none() && !matches!(workflow, "nightly.yml" | "release.yml"))
    {
        return Err("dependency attestation does not bind Cargo.lock".to_owned());
    }
    Ok(())
}

fn candidate_binary(root: &Path, release: bool) -> PathBuf {
    release_candidate_target()
        .unwrap_or_else(|| root.join("target"))
        .join(if release { "release" } else { "debug" })
        .join(format!("hell{}", std::env::consts::EXE_SUFFIX))
}

fn stack_oracle(report: &mut Report, spec: &CommandSpec) -> Result<PathBuf, FailureKind> {
    let result = report
        .run_command("native-oracle-path", spec)
        .map_err(|_| FailureKind::Child)?;
    if !result.status.success() {
        return Err(FailureKind::Child);
    }
    let root = String::from_utf8(result.stdout).map_err(|_| FailureKind::Fixture)?;
    Ok(PathBuf::from(root.trim())
        .join("bin")
        .join(format!("hell{}", std::env::consts::EXE_SUFFIX)))
}

fn run_spec(report: &mut Report, name: &str, spec: &CommandSpec) -> Result<(), FailureKind> {
    let result = report
        .run_command(name, spec)
        .map_err(|_| FailureKind::Child)?;
    let passed = result.status.success() && !result.timed_out;
    passed.then_some(()).ok_or(FailureKind::Child)
}

fn run_cargo_command(
    root: &Path,
    report: &mut Report,
    name: &str,
    arguments: &[&str],
    timeout: Duration,
) -> Result<(), FailureKind> {
    let spec = CommandSpec::cargo(timeout)
        .arguments(arguments.iter().copied())
        .current_directory(root);
    let result = report
        .run_command(name, &spec)
        .map_err(|_| FailureKind::Child)?;
    let passed = result.status.success() && !result.timed_out;
    passed.then_some(()).ok_or(FailureKind::Child)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_substantive_serial_probes_bind_exact_inventory_positions() {
        let cases = committed_differential_cases();
        let probes = windows_substantive_serial_probe_cases(&cases).unwrap();
        assert_eq!(
            probes
                .iter()
                .map(|(index, case)| (*index, case.id.as_ref()))
                .collect::<Vec<_>>(),
            WINDOWS_SUBSTANTIVE_SERIAL_PROBES,
        );

        let mut substituted = cases;
        substituted[WINDOWS_SUBSTANTIVE_SERIAL_PROBES[0].0].id =
            std::sync::Arc::from("substituted");
        assert!(windows_substantive_serial_probe_cases(&substituted).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn oracle_execution_alias_is_exactly_named_and_reported_separately_from_source() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = std::env::temp_dir().join(format!(
            "hell-oracle-execution-report-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let source_path = root.join("linux-release-oracle");
        // Keep this reporting probe off the live test executable used by later
        // multicall launch tests.
        let oracle_fixture = b"dedicated oracle execution fixture";
        fs::write(&source_path, oracle_fixture).unwrap();
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o755)).unwrap();
        let source_path = source_path.canonicalize().unwrap();
        let source = ExecutableIdentity {
            sha256: sha256_bytes(oracle_fixture),
            path: source_path.clone(),
            reported_version: hell_builtins::LANGUAGE_VERSION.into(),
            build_info: None,
            role: ExecutableRole::Oracle,
            assurance_epoch_sha256: None,
            acquisition_receipt_id: Some("pinned-release".into()),
            acquisition_receipt_sha256: Some(sha256_bytes(b"receipt")),
            acquisition_attestation_sha256: Some(sha256_bytes(b"attestation")),
        };
        let authority = exact_oracle_invocation(&root, &source).unwrap();
        assert_eq!(authority.source(), &source);
        let expected_name = format!("hell{}", std::env::consts::EXE_SUFFIX);
        assert_eq!(
            authority.execution().path.file_name().unwrap(),
            std::ffi::OsStr::new(&expected_name)
        );
        assert_ne!(authority.source().path, authority.execution().path);
        let mut report = Report::new("oracle-execution-report");
        report_executable_identity(&mut report, "oracle", authority.source()).unwrap();
        report_executable_invocation(&mut report, "oracle", &authority).unwrap();
        let json = report.to_json();
        assert!(json.contains("\"name\": \"conformance-oracle-identity\""));
        assert!(json.contains("\"name\": \"conformance-oracle-invocation\""));
        assert!(json.contains(source_path.to_str().unwrap()));
        assert!(json.contains(authority.execution().path.to_str().unwrap()));
        assert!(json.contains("\"invocationName\":\"hell\""));
        assert!(exact_oracle_invocation(&root, &source).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn benchmark_inventory_is_the_exact_committed_then_generated_authority() {
        let committed = committed_differential_cases();
        let generated = generated_typed_cases(0x4845_4c4c, 32);
        let inventory = native_benchmark_inventory();
        assert_eq!(committed.len(), 2_662);
        assert_eq!(generated.len(), 32);
        assert_eq!(inventory.len(), 2_694);
        for strictness_case in [
            "runtime-typed-map-singleton-key-strict",
            "runtime-typed-map-singleton-value-nonforce",
            "runtime-typed-set-singleton-element-strict",
        ] {
            assert_eq!(
                committed
                    .iter()
                    .filter(|case| case.id.as_ref() == strictness_case)
                    .count(),
                1,
                "singleton strictness split case {strictness_case} is not exact"
            );
        }
        assert_eq!(inventory.first().unwrap().id, committed.first().unwrap().id);
        assert_eq!(inventory[committed.len()].id, generated.first().unwrap().id);
        assert_eq!(inventory.last().unwrap().id, generated.last().unwrap().id);
        let first = representative_differential_sample(&inventory, 256).unwrap();
        let second = representative_differential_sample(&inventory, 256).unwrap();
        assert_eq!(first.inventory_count, 2_694);
        assert_eq!(first.inventory_sha256, second.inventory_sha256);
        assert_eq!(
            first.inventory_sha256,
            differential_inventory_sha256(&inventory).unwrap()
        );
        assert_eq!(first.selected_indices, second.selected_indices);
        assert_eq!(first.selected_indices.first(), Some(&0));
        assert_eq!(first.selected_indices.last(), Some(&2_693));
        assert!(
            first
                .selected_indices
                .windows(2)
                .all(|indices| indices[0] < indices[1])
        );
    }

    #[test]
    fn signed_process_exit_codes_are_retained_without_loss() {
        let encoded =
            canonical_json_bytes(&process_status_json(false, false, Some(-1_073_741_510))).unwrap();
        assert_eq!(
            String::from_utf8(encoded).unwrap(),
            "{\"exitCode\":\"-1073741510\",\"success\":false,\"timedOut\":false}\n"
        );
    }

    #[test]
    fn strict_projection_rejection_diagnostic_is_bounded_and_reason_typed() {
        use hell_testkit::RuntimeFailureProjectionRejectionReason as Reason;

        let mut rejection = hell_testkit::RuntimeFailureProjectionRejection {
            reason: Reason::OracleFrameOrigin,
            exception_family: hell_testkit::RuntimeFailureExceptionFamily::IOException,
            descriptor_builtin: "Text.writeFile",
            descriptor_dimension: hell_builtins::CompatibilityDimension::Effects,
            descriptor_obligation: "effect-failure",
            oracle_stderr_sha256: sha256_bytes(b"secret oracle stderr"),
            oracle_stderr_bytes: 20,
            candidate_stderr_sha256: sha256_bytes(b"secret candidate stderr"),
            candidate_stderr_bytes: 23,
            semantic_present: true,
            typed_result_sha256_present: false,
            typed_result_builtin_present: false,
            semantic_coverage_count: 1,
            obligation_event_count: 2,
            causal_order_count: 3,
            force_event_count: 4,
            effect_event_count: 5,
            task_event_count: 6,
            resource_event_count: 7,
        };
        for reason in [
            Reason::OracleFrameGrammar,
            Reason::OracleFrameTerminalNewline,
            Reason::OracleFrameCount,
            Reason::OracleFrameFunction,
            Reason::OracleFrameOrigin,
            Reason::OraclePayloadHandlingMissing,
            Reason::OraclePayloadHandlingMismatch,
            Reason::OraclePayloadUnexpectedHandling,
            Reason::OraclePayloadEmpty,
            Reason::OraclePayloadMultiline,
            Reason::OraclePayloadControl,
        ] {
            rejection.reason = reason;
            let encoded = canonical_json_bytes(
                &runtime_failure_projection_rejection_json(&rejection).unwrap(),
            )
            .unwrap();
            let encoded = String::from_utf8(encoded).unwrap();
            assert!(encoded.contains(&format!("\"reason\":\"{}\"", reason.descriptor_name())));
            assert!(!encoded.contains("secret"));
        }
        rejection.reason = Reason::OracleFrameOrigin;
        let encoded =
            canonical_json_bytes(&runtime_failure_projection_rejection_json(&rejection).unwrap())
                .unwrap();
        let encoded = String::from_utf8(encoded).unwrap();
        assert!(encoded.contains("\"reason\":\"oracle-frame-origin\""));
        assert!(encoded.contains("\"descriptorBuiltin\":\"Text.writeFile\""));
        assert!(encoded.contains("\"semanticCoverageCount\":1"));
        assert!(encoded.contains("\"resourceEventCount\":7"));
    }

    #[test]
    fn red_differential_evidence_binds_both_inventories_and_generated_seed() {
        let authoritative = sha256_bytes(b"committed-inventory");
        let combined = sha256_bytes(b"combined-inventory");
        let encode = |seed| {
            canonical_json_bytes(
                &differential_inventory_evidence_json(DifferentialInventoryEvidence {
                    authoritative_case_count: 2_661,
                    authoritative_inventory_sha256: authoritative,
                    combined_inventory_count: 2_693,
                    combined_inventory_sha256: combined,
                    generated_case_count: 32,
                    generated_seed: seed,
                    mismatches: vec![JsonValue::Object(BTreeMap::from([(
                        "caseId".to_owned(),
                        JsonValue::String("red-case".to_owned()),
                    )]))],
                })
                .unwrap(),
            )
            .unwrap()
        };
        let encoded = encode(0x4845_4c4c);
        let text = String::from_utf8(encoded.clone()).unwrap();
        assert!(text.contains("\"authoritativeCaseCount\":2661"));
        assert!(text.contains(&format!(
            "\"authoritativeInventorySha256\":\"{}\"",
            authoritative.hex()
        )));
        assert!(text.contains("\"combinedInventoryCount\":2693"));
        assert!(text.contains(&format!(
            "\"combinedInventorySha256\":\"{}\"",
            combined.hex()
        )));
        assert!(text.contains("\"generatedCaseCount\":32"));
        assert!(text.contains("\"generatedSeed\":1212501068"));
        assert!(text.contains("\"mismatchCount\":1"));
        assert_ne!(encoded, encode(0x4845_4c4d));
    }

    #[test]
    fn timing_distribution_keeps_the_first_authoritative_worst_case() {
        let cases = [
            DifferentialCase {
                id: "first".into(),
                ..DifferentialCase::default()
            },
            DifferentialCase {
                id: "second".into(),
                ..DifferentialCase::default()
            },
            DifferentialCase {
                id: "third".into(),
                ..DifferentialCase::default()
            },
        ];
        let detail = timing_distribution_detail("oracle", &[5, 9, 9], &cases, &[0, 10, 20]);
        assert!(detail.contains("p50=9,p95=9,p99=9,max=9"));
        assert!(detail.contains("worstAuthoritativeIndex=10,worstCaseId=\"second\""));
    }

    #[test]
    fn benchmark_report_binds_every_executable_identity_field() {
        let digest = sha256_bytes(b"oracle");
        let identity = ExecutableIdentity {
            path: PathBuf::from("/fixed/oracle"),
            sha256: digest,
            reported_version: "2026-05-29".into(),
            build_info: None,
            role: ExecutableRole::Oracle,
            assurance_epoch_sha256: Some(sha256_bytes(b"epoch")),
            acquisition_receipt_id: Some("receipt-1".into()),
            acquisition_receipt_sha256: Some(sha256_bytes(b"receipt")),
            acquisition_attestation_sha256: Some(sha256_bytes(b"attestation")),
        };
        let mut report = Report::new("native-differential-benchmark");
        report.mark_non_authoritative();
        report.measurement(
            "native-benchmark-oracle-identity",
            Duration::ZERO,
            benchmark_executable_identity_detail(&identity, 123).unwrap(),
        );
        report_benchmark_artifact_identity(
            &mut report,
            "helper",
            &BenchmarkArtifactIdentity {
                path: PathBuf::from("/fixed/hell-test-helper"),
                sha256: sha256_bytes(b"helper"),
                size: 456,
            },
        )
        .unwrap();
        let json = report.to_json();
        assert!(json.contains("\"authoritative\": false"));
        assert!(json.contains("canonicalPath=\\\"/fixed/oracle\\\""));
        assert!(json.contains(&format!("sha256={}", digest.hex())));
        assert!(json.contains("reportedVersion=\\\"2026-05-29\\\""));
        assert!(json.contains("acquisitionReceiptId=\\\"receipt-1\\\""));
        assert!(json.contains("canonicalPath=\\\"/fixed/hell-test-helper\\\""));
        assert!(json.contains("sizeBytes=456"));
    }

    #[test]
    fn authoritative_identity_and_mismatch_evidence_is_typed_and_bounded() {
        let digest = sha256_bytes(b"candidate");
        let build_info_lines = [
            format!("hell-rs {}", env!("CARGO_PKG_VERSION")),
            format!("language baseline {}", hell_builtins::LANGUAGE_VERSION),
            format!("upstream {}", hell_builtins::UPSTREAM_COMMIT),
            "compatibility evidence schema 2".to_owned(),
            "compat tracing enabled true".to_owned(),
            format!(
                "compiler policy {:?}",
                hell_compiler::CompilerConfig::upstream()
            ),
            format!(
                "runtime policy {:?}",
                hell_runtime::policy::RuntimePolicy::upstream()
            ),
        ];
        let identity = ExecutableIdentity {
            path: PathBuf::from("/fixed/candidate"),
            sha256: digest,
            reported_version: "2026-05-29".into(),
            build_info: Some(
                hell_testkit::parse_candidate_build_info(
                    build_info_lines.iter().map(String::as_str),
                )
                .unwrap(),
            ),
            role: ExecutableRole::Candidate,
            assurance_epoch_sha256: None,
            acquisition_receipt_id: None,
            acquisition_receipt_sha256: None,
            acquisition_attestation_sha256: None,
        };
        let encoded =
            canonical_json_bytes(&executable_identity_json(&identity, 123).unwrap()).unwrap();
        let encoded = String::from_utf8(encoded).unwrap();
        assert!(encoded.contains("\"canonicalPath\":\"/fixed/candidate\""));
        assert!(encoded.contains(&format!("\"sha256\":\"{}\"", digest.hex())));
        assert!(encoded.contains("\"sizeBytes\":123"));
        assert!(encoded.contains("\"schemaVersion\":2"));
        assert!(encoded.contains("\"buildInfoSchemaVersion\":2"));
        assert!(encoded.contains("\"compatTracing\":true"));

        let disabled_lines = build_info_lines.map(|line| {
            if line == "compat tracing enabled true" {
                "compat tracing enabled false".to_owned()
            } else {
                line
            }
        });
        let path = std::env::current_exe().unwrap().canonicalize().unwrap();
        let disabled = ExecutableIdentity {
            sha256: sha256_file(&path).unwrap(),
            path,
            reported_version: "2026-05-29".into(),
            build_info: Some(
                hell_testkit::parse_candidate_build_info(disabled_lines.iter().map(String::as_str))
                    .unwrap(),
            ),
            role: ExecutableRole::Candidate,
            assurance_epoch_sha256: None,
            acquisition_receipt_id: None,
            acquisition_receipt_sha256: None,
            acquisition_attestation_sha256: None,
        };
        let mut preflight = Report::new("candidate-preflight");
        report_executable_identity(&mut preflight, "candidate", &disabled).unwrap();
        assert!(
            report_candidate_compat_tracing_preflight(
                &mut preflight,
                "conformance-candidate-compat-tracing",
                &disabled,
            )
            .is_err()
        );
        let encoded = preflight.to_json();
        assert!(encoded.contains("\"compatTracing\":false"));
        assert!(encoded.contains("\"name\": \"conformance-candidate-compat-tracing\""));
        assert!(encoded.contains("\"status\": \"failed\""));

        let bytes = vec![0x5a; BENCHMARK_MISMATCH_PREFIX_BYTES + 1];
        let encoded = canonical_json_bytes(&mismatch_side_json(&bytes).unwrap()).unwrap();
        let encoded = String::from_utf8(encoded).unwrap();
        assert!(encoded.contains(&format!("\"bytes\":{}", bytes.len())));
        assert!(encoded.contains(&format!("\"sha256\":\"{}\"", sha256_bytes(&bytes).hex())));
        assert!(encoded.contains("\"prefixTruncated\":true"));
        assert!(!encoded.contains(&"5a".repeat(BENCHMARK_MISMATCH_PREFIX_BYTES + 1)));
    }

    #[test]
    fn native_stack_provenance_binds_ephemeral_overlay_before_cleanup() {
        let mut report = Report::new("native-oracle-shard");
        let provenance = crate::command::NativeStackProvenance {
            source: PathBuf::from("/fixed/oracle-source"),
            source_commit: crate::command::PINNED_ORACLE_SOURCE_COMMIT,
            stack_yaml_sha256: sha256_bytes(b"stack-yaml"),
            stack_lock_sha256: sha256_bytes(b"stack-lock"),
            effective_stack_yaml: PathBuf::from("/fixed/adapter/stack.yaml"),
            effective_stack_yaml_sha256: sha256_bytes(b"overlay"),
            llvm_ar: Some(PathBuf::from("/fixed/llvm-ar")),
            llvm_ar_sha256: Some(sha256_bytes(b"llvm-ar")),
            llvm_ar_version: Some("Homebrew LLVM version 22.1.8".to_owned()),
        };
        let build = CommandSpec::new("stack", Duration::ZERO).arguments([
            "--stack-yaml",
            "/fixed/adapter/stack.yaml",
            "build",
        ]);
        let path = CommandSpec::new("stack", Duration::ZERO).arguments([
            "--stack-yaml",
            "/fixed/adapter/stack.yaml",
            "path",
        ]);
        report_native_stack_provenance(&mut report, &provenance, &build, &path).unwrap();
        let json = report.to_json();
        assert!(json.contains("\"name\": \"native-stack-provenance\""));
        assert!(json.contains(crate::command::PINNED_ORACLE_SOURCE_COMMIT));
        assert!(json.contains("/fixed/adapter/stack.yaml"));
        assert!(json.contains("Homebrew LLVM version 22.1.8"));
        assert!(
            json.contains(
                "\"arguments\":[\"--stack-yaml\",\"/fixed/adapter/stack.yaml\",\"build\"]"
            )
        );
    }

    #[test]
    fn dependency_attestation_is_release_bound() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let temporary =
            std::env::temp_dir().join(format!("hell-release-dependency-{}", std::process::id()));
        fs::create_dir_all(&temporary).unwrap();
        let output = temporary.join("dependency-policy.json");
        release_dependency_attestation(&root, &output, &"a".repeat(40)).unwrap();
        assert!(fs::read_to_string(output).unwrap().contains("release.yml"));
        fs::remove_dir_all(temporary).unwrap();
    }
}
