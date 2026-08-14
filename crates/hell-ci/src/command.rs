use std::cell::RefCell;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hell_testkit::{Digest, run_supervised_command, sha256_file};

#[derive(Clone, Debug)]
pub struct CommandSpec {
    pub program: OsString,
    pub arguments: Vec<OsString>,
    pub current_directory: Option<PathBuf>,
    pub environment: Vec<(OsString, OsString)>,
    pub clear_environment: bool,
    pub process_scope: ProcessScope,
    pub timeout: Duration,
    canonical_executable_identity: Option<PathBuf>,
    invocation_name: Option<OsString>,
    program_resolution_error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolvedCargoExecutable {
    invocation_path: PathBuf,
    canonical_identity: PathBuf,
    invocation_name: OsString,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessScope {
    IsolatedTree,
}

pub(crate) struct NativeArchiveAdapter {
    _directory: Option<AdapterDirectory>,
    llvm_ar: Option<PathBuf>,
    llvm_ar_version: Option<String>,
    path: Option<OsString>,
    stack_yaml: Option<PathBuf>,
}

pub(crate) struct NativeStackProvenance {
    pub(crate) source: PathBuf,
    pub(crate) source_commit: &'static str,
    pub(crate) stack_yaml_sha256: Digest,
    pub(crate) stack_lock_sha256: Digest,
    pub(crate) effective_stack_yaml: PathBuf,
    pub(crate) effective_stack_yaml_sha256: Digest,
    pub(crate) llvm_ar: Option<PathBuf>,
    pub(crate) llvm_ar_sha256: Option<Digest>,
    pub(crate) llvm_ar_version: Option<String>,
}

struct AdapterDirectory(PathBuf);

impl AdapterDirectory {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for AdapterDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

static ADAPTER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn create_adapter_directory(base: &Path) -> Result<AdapterDirectory, String> {
    for _ in 0..16 {
        let sequence = ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = base.join(format!(
            "hell-ci-archive-adapter-{}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(AdapterDirectory(path)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!("cannot create macOS archive adapter: {error}"));
            }
        }
    }
    Err("cannot allocate a collision-free macOS archive adapter directory".to_owned())
}

fn accepted_llvm_ar_version(output: &str) -> bool {
    output.lines().any(|line| {
        matches!(
            line.trim(),
            "Homebrew LLVM version 18.1.8" | "Homebrew LLVM version 22.1.8"
        )
    })
}

impl NativeArchiveAdapter {
    pub(crate) fn for_macos(enabled: bool, base: &Path, source: &Path) -> Result<Self, String> {
        if !enabled {
            return Ok(Self {
                _directory: None,
                llvm_ar: None,
                llvm_ar_version: None,
                path: None,
                stack_yaml: None,
            });
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (base, source);
            return Err("the macOS native archive adapter requires a macOS host".to_owned());
        }
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::symlink;

            let llvm_ar = resolve_path_executable(OsStr::new("llvm-ar"))?;
            let version = CommandSpec::new(llvm_ar.as_os_str(), Duration::from_secs(30))
                .argument("--version")
                .run()
                .map_err(|error| format!("cannot identify LLVM archiver: {error}"))?;
            if !version.status.success() || version.timed_out {
                return Err("LLVM archiver identity command failed".to_owned());
            }
            let version = std::str::from_utf8(&version.stdout)
                .map_err(|_| "LLVM archiver identity is not UTF-8".to_owned())?;
            if !accepted_llvm_ar_version(version) {
                return Err("LLVM archiver version differs from native CI policy".to_owned());
            }
            let llvm_ar_version = version.trim().to_owned();
            let inherited = std::env::var_os("PATH").ok_or_else(|| {
                "standard PATH is required for the macOS archive adapter".to_owned()
            })?;
            let current_directory = std::env::current_dir()
                .map_err(|error| format!("cannot resolve archive adapter PATH: {error}"))?;
            let directory = create_adapter_directory(base)?;
            let adapter_root = directory.path();
            prepare_adapter_work_directory(adapter_root)?;
            let executable = std::env::current_exe()
                .map_err(|error| format!("cannot locate CI driver executable: {error}"))?;
            symlink(&executable, adapter_root.join("ar"))
                .map_err(|error| format!("cannot install macOS archive adapter: {error}"))?;
            symlink(&llvm_ar, adapter_root.join("llvm-ar"))
                .map_err(|error| format!("cannot bind LLVM archiver: {error}"))?;
            fs::write(adapter_root.join("member.o"), b"native-archive-adapter\n")
                .map_err(|error| format!("cannot write archiver probe member: {error}"))?;
            let inner = CommandSpec::new(
                adapter_root.join("llvm-ar").as_os_str(),
                Duration::from_secs(30),
            )
            .arguments(["qcls", "inner.a", "member.o"])
            .current_directory(adapter_root)
            .run()
            .map_err(|error| format!("cannot build archiver probe input: {error}"))?;
            if !inner.status.success() || inner.timed_out {
                return Err("LLVM archiver cannot build the nested-archive probe".to_owned());
            }
            fs::write(adapter_root.join("response.rsp"), b"inner.a\n")
                .map_err(|error| format!("cannot write archiver response probe: {error}"))?;
            let probe =
                CommandSpec::new(adapter_root.join("ar").as_os_str(), Duration::from_secs(30))
                    .arguments(["qcls", "outer.a", "@response.rsp"])
                    .current_directory(adapter_root)
                    .run()
                    .map_err(|error| format!("cannot probe LLVM archiver: {error}"))?;
            if !probe.status.success() || probe.timed_out {
                return Err(
                    "LLVM archiver lacks required response-file/flattening support".to_owned(),
                );
            }
            let table = CommandSpec::new(
                adapter_root.join("llvm-ar").as_os_str(),
                Duration::from_secs(30),
            )
            .arguments(["t", "outer.a"])
            .current_directory(adapter_root)
            .run()
            .map_err(|error| format!("cannot inspect archiver flattening probe: {error}"))?;
            if !table.status.success() || table.timed_out || table.stdout != b"member.o\n" {
                return Err("LLVM archiver did not flatten the nested archive exactly".to_owned());
            }
            let path = native_archive_path(&inherited, adapter_root, &llvm_ar, &current_directory)?;
            let stack_yaml = write_native_stack_overlay(adapter_root, source)?;
            Ok(Self {
                _directory: Some(directory),
                llvm_ar: Some(llvm_ar),
                llvm_ar_version: Some(llvm_ar_version),
                path: Some(path),
                stack_yaml: Some(stack_yaml),
            })
        }
    }

    pub(crate) fn apply(&self, command: CommandSpec) -> CommandSpec {
        match &self.path {
            Some(path) => command.environment("PATH", path),
            None => command,
        }
    }

    pub(crate) fn identity_command(&self) -> Option<CommandSpec> {
        self.llvm_ar.as_ref().map(|llvm_ar| {
            CommandSpec::new(llvm_ar.as_os_str(), Duration::from_secs(30)).argument("--version")
        })
    }

    pub(crate) fn stack_build(&self, source: &Path, timeout: Duration) -> CommandSpec {
        self.apply(native_stack_build(source, self.stack_yaml_path(), timeout))
    }

    pub(crate) fn stack_path(&self, source: &Path) -> CommandSpec {
        self.apply(native_stack_path(source, self.stack_yaml_path()))
    }

    pub(crate) fn stack_ghc_version(&self, source: &Path) -> CommandSpec {
        self.apply(native_stack_ghc_version(source, self.stack_yaml_path()))
    }

    pub(crate) fn stack_provenance(&self, source: &Path) -> Result<NativeStackProvenance, String> {
        let source = fs::canonicalize(source)
            .map_err(|error| format!("cannot canonicalize native oracle source: {error}"))?;
        let stack_yaml = source.join("stack.yaml");
        let stack_lock = source.join("stack.yaml.lock");
        let effective_stack_yaml = self.stack_yaml_path().canonicalize().map_err(|error| {
            format!("cannot canonicalize effective native Stack configuration: {error}")
        })?;
        let llvm_ar = self
            .llvm_ar
            .as_deref()
            .map(fs::canonicalize)
            .transpose()
            .map_err(|error| format!("cannot canonicalize LLVM archiver: {error}"))?;
        let llvm_ar_sha256 = llvm_ar
            .as_deref()
            .map(sha256_file)
            .transpose()
            .map_err(|error| format!("cannot hash LLVM archiver: {error}"))?;
        Ok(NativeStackProvenance {
            stack_yaml_sha256: sha256_file(&stack_yaml)
                .map_err(|error| format!("cannot hash pinned Stack configuration: {error}"))?,
            stack_lock_sha256: sha256_file(&stack_lock)
                .map_err(|error| format!("cannot hash pinned Stack lock: {error}"))?,
            effective_stack_yaml_sha256: sha256_file(&effective_stack_yaml).map_err(|error| {
                format!("cannot hash effective native Stack configuration: {error}")
            })?,
            source,
            source_commit: PINNED_ORACLE_SOURCE_COMMIT,
            effective_stack_yaml,
            llvm_ar,
            llvm_ar_sha256,
            llvm_ar_version: self.llvm_ar_version.clone(),
        })
    }

    fn stack_yaml_path(&self) -> &Path {
        self.stack_yaml
            .as_deref()
            .unwrap_or_else(|| Path::new("stack.yaml"))
    }
}

pub(crate) const PINNED_ORACLE_SOURCE_COMMIT: &str = "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff";

#[cfg(unix)]
fn prepare_adapter_work_directory(adapter_root: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(adapter_root, fs::Permissions::from_mode(0o2755))
        .map_err(|error| format!("cannot confine macOS archive adapter directory: {error}"))?;
    let work_directory = adapter_root.join(".stack-work");
    fs::create_dir(&work_directory)
        .map_err(|error| format!("cannot create candidate Stack work directory: {error}"))?;
    fs::set_permissions(&work_directory, fs::Permissions::from_mode(0o2770))
        .map_err(|error| format!("cannot confine candidate Stack work directory: {error}"))
}

fn yaml_single_quoted_path(path: &Path) -> Result<String, String> {
    let value = path
        .to_str()
        .ok_or_else(|| "native Stack source path is not UTF-8".to_owned())?;
    if value.chars().any(char::is_control) {
        return Err("native Stack source path contains a control character".to_owned());
    }
    Ok(format!("'{}'", value.replace('\'', "''")))
}

fn write_native_stack_overlay(directory: &Path, source: &Path) -> Result<PathBuf, String> {
    const PINNED_STACK_YAML: &[u8] =
        include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml");
    const PINNED_STACK_LOCK: &[u8] =
        include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml.lock");
    let stack_yaml = fs::read(source.join("stack.yaml"))
        .map_err(|error| format!("cannot read pinned Stack configuration: {error}"))?;
    if stack_yaml != PINNED_STACK_YAML {
        return Err("pinned Stack configuration differs from native CI policy".to_owned());
    }
    let stack_lock = fs::read(source.join("stack.yaml.lock"))
        .map_err(|error| format!("cannot read pinned Stack lock: {error}"))?;
    if stack_lock != PINNED_STACK_LOCK {
        return Err("pinned Stack lock differs from native CI policy".to_owned());
    }
    let canonical_source = fs::canonicalize(source)
        .map_err(|error| format!("cannot canonicalize native Stack source: {error}"))?;
    let package = yaml_single_quoted_path(&canonical_source)?;
    let overlay = format!(
        "resolver: nightly-2024-10-21\npackages:\n  - {package}\nsystem-ghc: true\nallow-different-user: true\nghc-options:\n  \"$everything\": \"-split-sections -j\"\n  unix-time: \"-optl-all_load\"\n  network-control: \"-fforce-recomp\"\n"
    );
    let overlay_path = directory.join("stack.yaml");
    fs::write(&overlay_path, overlay)
        .map_err(|error| format!("cannot write native Stack overlay: {error}"))?;
    fs::write(directory.join("stack.yaml.lock"), stack_lock)
        .map_err(|error| format!("cannot copy pinned native Stack lock: {error}"))?;
    Ok(overlay_path)
}

fn native_archive_path(
    inherited: &OsStr,
    adapter_root: &Path,
    llvm_ar: &Path,
    current_directory: &Path,
) -> Result<OsString, String> {
    let llvm_ar = fs::canonicalize(llvm_ar)
        .map_err(|error| format!("cannot canonicalize LLVM archiver: {error}"))?;
    let provision_directory = llvm_ar
        .parent()
        .ok_or_else(|| "LLVM archiver has no provision directory".to_owned())?;
    let mut paths = vec![adapter_root.to_owned()];
    paths.extend(std::env::split_paths(inherited).filter(|entry| {
        let resolved = if entry.is_absolute() {
            entry.clone()
        } else {
            current_directory.join(entry)
        };
        let is_provision_directory =
            fs::canonicalize(&resolved).is_ok_and(|resolved| resolved == provision_directory);
        let exposes_selected_archiver =
            fs::canonicalize(resolved.join("llvm-ar")).is_ok_and(|candidate| candidate == llvm_ar);
        !is_provision_directory && !exposes_selected_archiver
    }));
    std::env::join_paths(paths)
        .map_err(|error| format!("cannot construct archive adapter PATH: {error}"))
}

const SENSITIVE_ENVIRONMENT: [&str; 9] = [
    "GITHUB_TOKEN",
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "GITHUB_OUTPUT",
    "GITHUB_ENV",
    "GITHUB_PATH",
    "GITHUB_STEP_SUMMARY",
    "GH_TOKEN",
];

#[derive(Clone)]
struct ReleaseCandidateEnvironment {
    target: OsString,
    source_date_epoch: OsString,
}

thread_local! {
    static RELEASE_CANDIDATE_ENVIRONMENT: RefCell<Option<ReleaseCandidateEnvironment>> = const { RefCell::new(None) };
}

pub(crate) fn with_release_candidate_environment<T>(
    target: &std::path::Path,
    source_date_epoch: u64,
    launch_policy: &hell_testkit::CandidateLaunchPolicy,
    operation: impl FnOnce() -> T,
) -> T {
    let environment = ReleaseCandidateEnvironment {
        target: target.as_os_str().to_owned(),
        source_date_epoch: source_date_epoch.to_string().into(),
    };
    RELEASE_CANDIDATE_ENVIRONMENT.with(|slot| {
        struct Restore<'a> {
            slot: &'a RefCell<Option<ReleaseCandidateEnvironment>>,
            previous: Option<ReleaseCandidateEnvironment>,
        }
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                self.slot.replace(self.previous.take());
            }
        }
        let previous = slot.replace(Some(environment));
        let _restore = Restore { slot, previous };
        hell_testkit::with_candidate_launch_policy(launch_policy, operation)
    })
}

pub(crate) fn release_candidate_target() -> Option<PathBuf> {
    RELEASE_CANDIDATE_ENVIRONMENT.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|environment| PathBuf::from(environment.target.clone()))
    })
}

#[derive(Debug)]
pub struct CommandResult {
    pub status: ExitStatus,
    pub duration: Duration,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_sha256: Digest,
    pub stderr_sha256: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandRunPhase {
    ProgramResolution,
    SupervisedExecution,
    StdoutRelay,
    StderrRelay,
}

impl CommandRunPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProgramResolution => "program-resolution",
            Self::SupervisedExecution => "supervised-execution",
            Self::StdoutRelay => "stdout-relay",
            Self::StderrRelay => "stderr-relay",
        }
    }
}

#[derive(Debug)]
pub struct CommandRunError {
    phase: CommandRunPhase,
    source: std::io::Error,
    completed: Option<Box<CommandResult>>,
}

impl CommandRunError {
    fn new(phase: CommandRunPhase, source: std::io::Error) -> Self {
        Self {
            phase,
            source,
            completed: None,
        }
    }

    fn after_completion(
        phase: CommandRunPhase,
        source: std::io::Error,
        completed: CommandResult,
    ) -> Self {
        Self {
            phase,
            source,
            completed: Some(Box::new(completed)),
        }
    }

    pub fn phase(&self) -> CommandRunPhase {
        self.phase
    }

    pub fn kind(&self) -> std::io::ErrorKind {
        self.source.kind()
    }

    pub fn raw_os_error(&self) -> Option<i32> {
        self.source.raw_os_error()
    }

    pub fn message(&self) -> String {
        self.source.to_string()
    }

    pub fn completed(&self) -> Option<&CommandResult> {
        self.completed.as_deref()
    }
}

impl std::fmt::Display for CommandRunError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.phase.as_str(), self.source)
    }
}

impl std::error::Error for CommandRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl CommandSpec {
    pub fn new(program: impl Into<OsString>, timeout: Duration) -> Self {
        let mut spec = Self {
            program: program.into(),
            arguments: Vec::new(),
            current_directory: None,
            environment: Vec::new(),
            clear_environment: false,
            process_scope: ProcessScope::IsolatedTree,
            timeout,
            canonical_executable_identity: None,
            invocation_name: None,
            program_resolution_error: None,
        };
        if let Some(release) = RELEASE_CANDIDATE_ENVIRONMENT.with(|slot| slot.borrow().clone()) {
            let isolated = PathBuf::from(&release.target).join("release-child-environment");
            spec = spec
                .release_candidate_environment()
                .environment("CARGO_TARGET_DIR", release.target.clone())
                .environment("CARGO_INCREMENTAL", "0")
                .environment("SOURCE_DATE_EPOCH", release.source_date_epoch.clone())
                .environment("HOME", isolated.join("home"))
                .environment("USERPROFILE", isolated.join("home"))
                .environment("CARGO_HOME", isolated.join("cargo"))
                .environment("SCCACHE_DIR", isolated.join("sccache"))
                .environment("TEMP", isolated.join("tmp"))
                .environment("TMP", isolated.join("tmp"))
                .environment("TMPDIR", isolated.join("tmp"));
        }
        spec
    }

    pub fn cargo(timeout: Duration) -> Self {
        Self::cargo_from_resolution(timeout, resolve_cargo_executable())
    }

    fn cargo_from_resolution(
        timeout: Duration,
        resolution: Result<ResolvedCargoExecutable, String>,
    ) -> Self {
        let mut spec = Self::new(OsString::from("cargo"), timeout);
        spec.invocation_name = Some(OsString::from("cargo"));
        match resolution {
            Ok(resolved) => {
                spec.program = resolved.invocation_path.into_os_string();
                spec.canonical_executable_identity = Some(resolved.canonical_identity);
                spec.invocation_name = Some(resolved.invocation_name);
            }
            Err(error) => spec.program_resolution_error = Some(error),
        }
        spec
    }

    #[cfg(test)]
    pub(crate) fn cargo_resolution_failure(timeout: Duration, error: &str) -> Self {
        Self::cargo_from_resolution(timeout, Err(error.to_owned()))
    }

    #[cfg(test)]
    pub(crate) fn cargo_resolution_success(
        timeout: Duration,
        invocation_path: PathBuf,
        canonical_identity: PathBuf,
    ) -> Self {
        Self::cargo_from_resolution(
            timeout,
            Ok(ResolvedCargoExecutable {
                invocation_path,
                canonical_identity,
                invocation_name: OsString::from("cargo"),
            }),
        )
    }

    pub fn argument(mut self, argument: impl Into<OsString>) -> Self {
        self.arguments.push(argument.into());
        self
    }

    pub fn arguments<I, S>(mut self, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.arguments.extend(arguments.into_iter().map(Into::into));
        self
    }

    pub fn current_directory(mut self, path: impl Into<PathBuf>) -> Self {
        self.current_directory = Some(path.into());
        self
    }

    pub fn release_candidate_environment(mut self) -> Self {
        self.environment = hell_testkit::RELEASE_CHILD_ENVIRONMENT_ALLOWLIST
            .iter()
            .filter_map(|name| std::env::var_os(name).map(|value| (name.into(), value)))
            .collect();
        self.clear_environment = true;
        self
    }

    pub fn environment(mut self, name: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        let name = name.into();
        assert!(
            !is_sensitive_environment(&name),
            "sensitive environment variables cannot be added to a supervised command"
        );
        self.environment.push((name, value.into()));
        self
    }

    #[cfg(test)]
    pub fn environment_names(&self) -> Vec<String> {
        self.environment
            .iter()
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect()
    }

    pub fn display_program(&self) -> String {
        self.program.to_string_lossy().into_owned()
    }

    pub fn display_invocation_name(&self) -> Option<String> {
        self.invocation_name
            .as_deref()
            .map(|name| name.to_string_lossy().into_owned())
    }

    pub fn display_canonical_executable_identity(&self) -> Option<String> {
        self.canonical_executable_identity
            .as_deref()
            .map(|path| path.to_string_lossy().into_owned())
    }

    pub fn display_arguments(&self) -> Vec<String> {
        self.arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    pub fn run(&self) -> Result<CommandResult, CommandRunError> {
        if let Some(error) = &self.program_resolution_error {
            return Err(CommandRunError::new(
                CommandRunPhase::ProgramResolution,
                std::io::Error::new(std::io::ErrorKind::NotFound, error.clone()),
            ));
        }
        if let Some(expected) = &self.canonical_executable_identity {
            revalidate_resolved_cargo(Path::new(&self.program), expected)
                .map_err(|error| CommandRunError::new(CommandRunPhase::ProgramResolution, error))?;
        }
        let mut command = Command::new(&self.program);
        command.args(&self.arguments);
        if self.clear_environment {
            command.env_clear();
        }
        for name in SENSITIVE_ENVIRONMENT {
            command.env_remove(name);
        }
        command.envs(self.environment.iter().cloned());
        for name in SENSITIVE_ENVIRONMENT {
            command.env_remove(name);
        }
        if let Some(directory) = &self.current_directory {
            command.current_dir(directory);
        }

        debug_assert_eq!(self.process_scope, ProcessScope::IsolatedTree);

        let started = Instant::now();
        let output = run_supervised_command(&mut command, &[], self.timeout)
            .map_err(|error| CommandRunError::new(CommandRunPhase::SupervisedExecution, error))?;
        let stdout = output.stdout.retained_bytes();
        let stderr = output.stderr.retained_bytes();
        let result = CommandResult {
            status: output.status,
            duration: started.elapsed(),
            timed_out: output.timed_out,
            stdout,
            stderr,
            stdout_truncated: output.stdout.truncated,
            stderr_truncated: output.stderr.truncated,
            stdout_bytes: output.stdout.total_bytes,
            stderr_bytes: output.stderr.total_bytes,
            stdout_sha256: output.stdout.sha256,
            stderr_sha256: output.stderr.sha256,
        };
        if let Err(error) = std::io::stdout().write_all(&result.stdout) {
            return Err(CommandRunError::after_completion(
                CommandRunPhase::StdoutRelay,
                error,
                result,
            ));
        }
        if let Err(error) = std::io::stderr().write_all(&result.stderr) {
            return Err(CommandRunError::after_completion(
                CommandRunPhase::StderrRelay,
                error,
                result,
            ));
        }
        Ok(result)
    }
}

fn is_sensitive_environment(name: &OsString) -> bool {
    SENSITIVE_ENVIRONMENT
        .iter()
        .any(|sensitive| name == sensitive)
}

fn resolve_path_executable(name: &OsStr) -> Result<PathBuf, String> {
    let path = std::env::var_os("PATH").ok_or_else(|| {
        format!(
            "cannot resolve {} without standard PATH",
            name.to_string_lossy()
        )
    })?;
    for directory in std::env::split_paths(&path) {
        let candidate = if directory.is_absolute() {
            directory.join(name)
        } else {
            std::env::current_dir()
                .map_err(|error| format!("cannot resolve relative PATH entry: {error}"))?
                .join(directory)
                .join(name)
        };
        let Ok(metadata) = fs::metadata(&candidate) else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o111 == 0 {
                continue;
            }
        }
        return fs::canonicalize(&candidate).map_err(|error| {
            format!(
                "cannot canonicalize {} executable: {error}",
                name.to_string_lossy()
            )
        });
    }
    Err(format!(
        "cannot resolve {} from standard PATH",
        name.to_string_lossy()
    ))
}

pub(crate) fn resolve_cargo_executable() -> Result<ResolvedCargoExecutable, String> {
    let configured = std::env::var_os("CARGO");
    let search = std::env::var_os("PATH")
        .map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
        .unwrap_or_default();
    let extensions = if cfg!(windows) {
        std::env::var_os("PATHEXT")
            .map(|value| windows_executable_extensions(&value))
            .unwrap_or_else(|| vec![OsString::from(".COM"), OsString::from(".EXE")])
    } else {
        Vec::new()
    };
    resolve_cargo_from(
        configured.as_deref(),
        &search,
        &extensions,
        cfg!(unix),
        cfg!(windows),
    )
}

pub(crate) fn resolve_cargo_from(
    configured: Option<&OsStr>,
    search: &[PathBuf],
    windows_extensions: &[OsString],
    require_unix_executable: bool,
    windows: bool,
) -> Result<ResolvedCargoExecutable, String> {
    let program = configured.unwrap_or_else(|| OsStr::new("cargo"));
    if program.is_empty() {
        return Err("CARGO names an empty executable".to_owned());
    }
    let path = Path::new(program);
    if path.is_absolute() {
        if windows && !has_native_windows_extension(path) {
            return Err("CARGO absolute path is not a native COM/EXE executable".to_owned());
        }
        return resolved_tool_candidate(path, require_unix_executable, windows)
            .ok_or_else(|| "CARGO does not name an executable file".to_owned());
    }
    if path.components().count() > 1 {
        return Err("CARGO relative component paths are not allowed".to_owned());
    }
    let names = executable_names(program, windows_extensions, windows)?;
    for directory in search.iter().filter(|directory| directory.is_absolute()) {
        for name in &names {
            let candidate = directory.join(name);
            if let Some(candidate) =
                resolved_tool_candidate(&candidate, require_unix_executable, windows)
            {
                return Ok(candidate);
            }
        }
    }
    Err("cannot resolve Cargo executable from standard CARGO or PATH".to_owned())
}

fn executable_names(
    program: &OsStr,
    windows_extensions: &[OsString],
    windows: bool,
) -> Result<Vec<OsString>, String> {
    if !windows {
        return Ok(vec![program.to_owned()]);
    }
    if Path::new(program).extension().is_some() {
        return has_native_windows_extension(Path::new(program))
            .then(|| vec![program.to_owned()])
            .ok_or_else(|| "CARGO name is not a native COM/EXE executable".to_owned());
    }
    if windows_extensions.is_empty() {
        return Err("PATHEXT contains no native COM/EXE extensions".to_owned());
    }
    Ok(windows_extensions
        .iter()
        .map(|extension| {
            let mut name = program.to_owned();
            name.push(extension);
            name
        })
        .collect())
}

pub(crate) fn windows_executable_extensions(value: &OsStr) -> Vec<OsString> {
    value
        .to_string_lossy()
        .split(';')
        .filter(|extension| !extension.is_empty())
        .filter(|extension| {
            extension.eq_ignore_ascii_case(".com") || extension.eq_ignore_ascii_case(".exe")
        })
        .map(OsString::from)
        .collect()
}

fn has_native_windows_extension(path: &Path) -> bool {
    path.extension().is_some_and(|extension| {
        let extension = extension.to_string_lossy();
        extension.eq_ignore_ascii_case("com") || extension.eq_ignore_ascii_case("exe")
    })
}

fn resolved_tool_candidate(
    path: &Path,
    require_unix_executable: bool,
    windows: bool,
) -> Option<ResolvedCargoExecutable> {
    let Ok(metadata) = fs::metadata(path) else {
        return None;
    };
    if !metadata.is_file() {
        return None;
    }
    #[cfg(unix)]
    if require_unix_executable {
        use nix::fcntl::AtFlags;
        use nix::unistd::{AccessFlags, faccessat};

        if faccessat(None, path, AccessFlags::X_OK, AtFlags::AT_EACCESS).is_err() {
            return None;
        }
    }
    let _ = require_unix_executable;
    let canonical_identity = fs::canonicalize(path).ok()?;
    if windows && !has_native_windows_extension(&canonical_identity) {
        return None;
    }
    let file_name = path.file_name()?;
    let canonical_parent = fs::canonicalize(path.parent()?).ok()?;
    let invocation_path = canonical_parent.join(file_name);
    Some(ResolvedCargoExecutable {
        invocation_path,
        canonical_identity,
        invocation_name: OsString::from("cargo"),
    })
}

fn revalidate_resolved_cargo(invocation: &Path, expected: &Path) -> std::io::Result<()> {
    let resolved =
        resolved_tool_candidate(invocation, cfg!(unix), cfg!(windows)).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "resolved Cargo invocation is no longer an executable file",
            )
        })?;
    if resolved.canonical_identity != expected {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "resolved Cargo executable identity changed before spawn",
        ));
    }
    Ok(())
}

fn native_stack_build(source: &Path, stack_yaml: &Path, timeout: Duration) -> CommandSpec {
    CommandSpec::new("stack", timeout)
        .arguments(["--lock-file", "error-on-write", "--stack-yaml"])
        .argument(stack_yaml)
        .argument("build")
        .current_directory(source)
}

fn native_stack_path(source: &Path, stack_yaml: &Path) -> CommandSpec {
    CommandSpec::new("stack", Duration::from_mins(5))
        .arguments(["--lock-file", "error-on-write", "--stack-yaml"])
        .argument(stack_yaml)
        .arguments(["path", "--local-install-root"])
        .current_directory(source)
}

fn native_stack_ghc_version(source: &Path, stack_yaml: &Path) -> CommandSpec {
    CommandSpec::new("stack", Duration::from_mins(5))
        .arguments(["--lock-file", "error-on-write", "--stack-yaml"])
        .argument(stack_yaml)
        .arguments(["exec", "--", "ghc", "--numeric-version"])
        .current_directory(source)
}

pub(crate) fn verify_pinned_oracle_checkout(source: &Path) -> Result<(), String> {
    verify_tracked_checkout(source, PINNED_ORACLE_SOURCE_COMMIT)
}

fn verify_tracked_checkout(source: &Path, expected: &str) -> Result<(), String> {
    let head = CommandSpec::new("git", Duration::from_secs(30))
        .arguments(["rev-parse", "HEAD"])
        .current_directory(source)
        .run()
        .map_err(|error| format!("cannot identify oracle checkout: {error}"))?;
    if !head.status.success()
        || head.timed_out
        || std::str::from_utf8(&head.stdout)
            .map_err(|_| "oracle checkout identity is not UTF-8".to_owned())?
            .trim()
            != expected
    {
        return Err("oracle source checkout differs from pinned commit".to_owned());
    }
    let status = CommandSpec::new("git", Duration::from_secs(30))
        .arguments(["status", "--porcelain=v1", "--untracked-files=all"])
        .current_directory(source)
        .run()
        .map_err(|error| format!("cannot inspect oracle checkout: {error}"))?;
    if !status.status.success() || status.timed_out || !status.stdout.is_empty() {
        return Err("oracle source has tracked or staged changes".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn run_native_archive_adapter(arguments: &[OsString]) -> std::process::ExitCode {
    let result = (|| {
        let invoked = std::env::args_os()
            .next()
            .ok_or_else(|| std::io::Error::other("archive adapter argv[0] is missing"))?;
        let directory = Path::new(&invoked)
            .parent()
            .ok_or_else(|| std::io::Error::other("archive adapter directory is missing"))?;
        let normalized = normalize_native_archive_arguments(arguments)?;
        Command::new(directory.join("llvm-ar"))
            .args(normalized)
            .status()
    })();
    match result {
        Ok(status) => status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .map_or(
                std::process::ExitCode::FAILURE,
                std::process::ExitCode::from,
            ),
        Err(error) => {
            eprintln!("native archive adapter failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(unix)]
fn normalize_native_archive_arguments(arguments: &[OsString]) -> std::io::Result<Vec<OsString>> {
    let Some(first) = arguments.first() else {
        return Err(std::io::Error::other(
            "archive adapter arguments are missing",
        ));
    };
    let replacement = match first.to_str() {
        Some("r") | Some("-r") => {
            let target = arguments
                .iter()
                .skip(1)
                .find(|argument| !argument.to_string_lossy().starts_with('-'))
                .ok_or_else(|| std::io::Error::other("replace archive target is missing"))?;
            if Path::new(target).exists() {
                return Err(std::io::Error::other(
                    "replace-to-append conversion requires a fresh archive target",
                ));
            }
            Some(if first == "r" { "qL" } else { "-qL" })
        }
        Some("q") => Some("qL"),
        Some("-q") => Some("-qL"),
        Some("qc") => Some("qLc"),
        Some("-qc") => Some("-qLc"),
        Some("qcls") => Some("qclsL"),
        Some("-qcls") => Some("-qclsL"),
        Some("qL" | "-qL" | "qLc" | "-qLc" | "qcL" | "-qcL" | "qclsL" | "-qclsL") => None,
        Some("t" | "-t") => None,
        Some(value) => {
            return Err(std::io::Error::other(format!(
                "archive adapter received unsupported operation {value:?}"
            )));
        }
        None => {
            return Err(std::io::Error::other(
                "archive adapter operation must be UTF-8",
            ));
        }
    };
    let mut normalized = arguments.to_vec();
    if let Some(replacement) = replacement {
        normalized[0] = replacement.into();
    }
    Ok(normalized)
}

#[cfg(unix)]
pub(crate) fn run_posix_release_child(arguments: &[OsString]) -> std::process::ExitCode {
    match posix_release_child(arguments) {
        Ok(status) => status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .map_or(
                std::process::ExitCode::FAILURE,
                std::process::ExitCode::from,
            ),
        Err(error) => {
            eprintln!("POSIX release child launcher failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(unix)]
fn posix_release_child(arguments: &[OsString]) -> std::io::Result<ExitStatus> {
    let (program, child_arguments) = arguments
        .split_first()
        .ok_or_else(|| std::io::Error::other("POSIX release child program is missing"))?;
    let retained = filtered_posix_release_environment(std::env::vars_os());
    Command::new(program)
        .args(child_arguments)
        .env_clear()
        .envs(retained)
        .status()
}

#[cfg(unix)]
fn filtered_posix_release_environment(
    environment: impl IntoIterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    environment
        .into_iter()
        .filter(|(name, _)| {
            hell_testkit::POSIX_RELEASE_CHILD_ENVIRONMENT_ALLOWLIST
                .iter()
                .any(|allowed| name == allowed)
        })
        .collect()
}

#[cfg(windows)]
pub(crate) fn run_windows_restricted_child(arguments: &[OsString]) -> std::process::ExitCode {
    match windows_restricted_child(arguments) {
        Ok(code) => std::process::ExitCode::from(u8::try_from(code).unwrap_or(u8::MAX)),
        Err(error) => {
            eprintln!("restricted child launcher failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(windows)]
fn windows_restricted_child(arguments: &[OsString]) -> std::io::Result<u32> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        CreateRestrictedToken, CreateWellKnownSid, DISABLE_MAX_PRIVILEGE, LUA_TOKEN,
        SID_AND_ATTRIBUTES, TOKEN_ALL_ACCESS, WinRestrictedCodeSid,
    };
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, INFINITE,
        OpenProcessToken, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOW,
        WaitForSingleObject,
    };

    let [encoded] = arguments else {
        return Err(std::io::Error::other(
            "restricted child requires one encoded argv token",
        ));
    };
    hell_testkit::decode_windows_argv(encoded)?;
    let launcher = std::env::current_exe()?;
    let mut command_line = "hell-ci __release-argv-child "
        .encode_utf16()
        .chain(encoded.encode_wide())
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let application = launcher
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    unsafe {
        let mut process_token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut process_token) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut sid_size = 68_u32;
        let mut restricted_sid = vec![0_u8; usize::try_from(sid_size).unwrap_or(68)];
        if CreateWellKnownSid(
            WinRestrictedCodeSid,
            std::ptr::null_mut(),
            restricted_sid.as_mut_ptr().cast(),
            &mut sid_size,
        ) == 0
        {
            CloseHandle(process_token);
            return Err(std::io::Error::last_os_error());
        }
        let restricted = SID_AND_ATTRIBUTES {
            Sid: restricted_sid.as_mut_ptr().cast(),
            Attributes: 0,
        };
        let mut token: HANDLE = std::ptr::null_mut();
        if CreateRestrictedToken(
            process_token,
            DISABLE_MAX_PRIVILEGE | LUA_TOKEN,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            1,
            &restricted,
            &mut token,
        ) == 0
        {
            CloseHandle(process_token);
            return Err(std::io::Error::last_os_error());
        }
        CloseHandle(process_token);
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            CloseHandle(token);
            return Err(std::io::Error::last_os_error());
        }
        let mut limits = JOB_OBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            std::ptr::addr_of!(limits).cast(),
            u32::try_from(std::mem::size_of_val(&limits)).unwrap_or(u32::MAX),
        ) == 0
        {
            CloseHandle(job);
            CloseHandle(token);
            return Err(std::io::Error::last_os_error());
        }
        let startup = STARTUPINFOW {
            cb: u32::try_from(std::mem::size_of::<STARTUPINFOW>()).unwrap_or(u32::MAX),
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: GetStdHandle(STD_INPUT_HANDLE),
            hStdOutput: GetStdHandle(STD_OUTPUT_HANDLE),
            hStdError: GetStdHandle(STD_ERROR_HANDLE),
            ..Default::default()
        };
        let mut process = PROCESS_INFORMATION::default();
        if CreateProcessAsUserW(
            token,
            application.as_ptr(),
            command_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_SUSPENDED,
            std::ptr::null(),
            std::ptr::null(),
            &startup,
            &mut process,
        ) == 0
        {
            CloseHandle(job);
            CloseHandle(token);
            return Err(std::io::Error::last_os_error());
        }
        if AssignProcessToJobObject(job, process.hProcess) == 0
            || ResumeThread(process.hThread) == u32::MAX
        {
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
            CloseHandle(job);
            CloseHandle(token);
            return Err(std::io::Error::last_os_error());
        }
        WaitForSingleObject(process.hProcess, INFINITE);
        let mut code = 1_u32;
        let ok = GetExitCodeProcess(process.hProcess, &mut code);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        CloseHandle(job);
        CloseHandle(token);
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(code)
    }
}

#[cfg(windows)]
pub(crate) fn run_windows_argv_child(arguments: &[OsString]) -> std::process::ExitCode {
    let result = (|| {
        let [encoded] = arguments else {
            return Err(std::io::Error::other(
                "Windows argv adapter requires one token",
            ));
        };
        let decoded = hell_testkit::decode_windows_argv(encoded)?;
        let (program, child_arguments) = decoded
            .split_first()
            .ok_or_else(|| std::io::Error::other("decoded Windows argv is empty"))?;
        Command::new(program).args(child_arguments).status()
    })();
    match result {
        Ok(status) => status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .map_or(
                std::process::ExitCode::FAILURE,
                std::process::ExitCode::from,
            ),
        Err(error) => {
            eprintln!("Windows argv adapter failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ResolverDirectory(PathBuf);

    impl ResolverDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "hell-cargo-resolver-{}-{}-{label}",
                std::process::id(),
                ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn tool(&self, name: &str, executable: bool) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, b"tool\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;

                let mode = if executable { 0o700 } else { 0o600 };
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            }
            let _ = executable;
            path
        }
    }

    impl Drop for ResolverDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn cargo_resolver_requires_an_explicit_absolute_search_path() {
        assert!(resolve_cargo_from(None, &[], &[], cfg!(unix), false).is_err());
        assert!(resolve_cargo_from(Some(OsStr::new("")), &[], &[], cfg!(unix), false).is_err());

        let root = ResolverDirectory::new("relative-path");
        root.tool("hell-cargo-relative-only", true);
        assert!(
            resolve_cargo_from(
                Some(OsStr::new("hell-cargo-relative-only")),
                &[
                    PathBuf::new(),
                    PathBuf::from("."),
                    PathBuf::from("relative")
                ],
                &[],
                cfg!(unix),
                false,
            )
            .is_err()
        );
        assert!(
            resolve_cargo_from(
                Some(OsStr::new("relative/cargo")),
                std::slice::from_ref(&root.0),
                &[],
                cfg!(unix),
                false,
            )
            .is_err()
        );
    }

    #[test]
    fn cargo_resolver_preserves_authority_order_and_fails_closed() {
        let first = ResolverDirectory::new("first");
        let second = ResolverDirectory::new("second");
        let first_cargo = first.tool("cargo", true);
        second.tool("cargo", true);
        let resolved = resolve_cargo_from(
            None,
            &[first.0.clone(), second.0.clone()],
            &[],
            cfg!(unix),
            false,
        )
        .unwrap();
        assert_eq!(
            resolved.invocation_path,
            fs::canonicalize(&first_cargo).unwrap()
        );
        assert_eq!(
            resolved.canonical_identity,
            fs::canonicalize(first_cargo).unwrap()
        );
        assert_eq!(resolved.invocation_name, "cargo");

        let proxy = second.tool("cargo-proxy", true);
        let resolved = resolve_cargo_from(
            Some(proxy.as_os_str()),
            std::slice::from_ref(&first.0),
            &[],
            cfg!(unix),
            false,
        )
        .unwrap();
        assert_eq!(resolved.invocation_path, fs::canonicalize(&proxy).unwrap());
        assert_eq!(
            resolved.canonical_identity,
            fs::canonicalize(proxy).unwrap()
        );

        let invalid_authority = second.path().join("missing-cargo");
        assert!(
            resolve_cargo_from(
                Some(invalid_authority.as_os_str()),
                std::slice::from_ref(&first.0),
                &[],
                cfg!(unix),
                false,
            )
            .is_err(),
            "an invalid authoritative CARGO path must not fall back to PATH"
        );
    }

    #[test]
    fn cargo_resolver_rejects_directories_and_non_executables() {
        let first = ResolverDirectory::new("invalid-candidate");
        let second = ResolverDirectory::new("valid-candidate");
        fs::create_dir(first.path().join("cargo")).unwrap();
        let expected = second.tool("cargo", true);
        let resolved = resolve_cargo_from(
            None,
            &[first.0.clone(), second.0.clone()],
            &[],
            cfg!(unix),
            false,
        )
        .unwrap();
        assert_eq!(
            resolved.invocation_path,
            fs::canonicalize(&expected).unwrap()
        );
        assert_eq!(
            resolved.canonical_identity,
            fs::canonicalize(expected).unwrap()
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let non_executable = first.tool("cargo-nonexec", false);
            fs::set_permissions(&non_executable, fs::Permissions::from_mode(0o001)).unwrap();
            assert!(
                resolve_cargo_from(Some(non_executable.as_os_str()), &[], &[], true, false,)
                    .is_err(),
                "another-user execute bit must not substitute for effective-user X_OK"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn cargo_resolver_retains_the_alias_and_binds_its_canonical_identity() {
        use std::os::unix::fs::symlink;

        let root = ResolverDirectory::new("symlink");
        let target = root.tool("cargo-target", true);
        let alias = root.path().join("cargo");
        symlink(&target, &alias).unwrap();
        let resolved =
            resolve_cargo_from(None, std::slice::from_ref(&root.0), &[], true, false).unwrap();
        assert_eq!(
            resolved.invocation_path,
            fs::canonicalize(root.path()).unwrap().join("cargo")
        );
        assert_eq!(
            resolved.canonical_identity,
            fs::canonicalize(target).unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn cargo_multicall_alias_preserves_invocation_name_and_exact_arguments() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let root = ResolverDirectory::new("multicall");
        let target = root.path().join("rustup");
        fs::write(
            &target,
            b"#!/bin/sh\ncase \"$0\" in */cargo) printf '%s\\n' \"$@\" ;; *) exit 91 ;; esac\n",
        )
        .unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let alias = root.path().join("cargo");
        symlink(&target, &alias).unwrap();

        let direct = CommandSpec::new(fs::canonicalize(&target).unwrap(), Duration::from_secs(1))
            .arguments(["test", "--workspace"])
            .run()
            .unwrap();
        assert_eq!(direct.status.code(), Some(91));

        let resolved = resolve_cargo_from(Some(alias.as_os_str()), &[], &[], true, false).unwrap();
        let spec = CommandSpec::cargo_from_resolution(Duration::from_secs(1), Ok(resolved));
        assert_eq!(spec.display_invocation_name().as_deref(), Some("cargo"));
        let result = spec.arguments(["test", "--workspace"]).run().unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout, b"test\n--workspace\n");
    }

    #[cfg(unix)]
    #[test]
    fn cargo_alias_identity_substitution_is_rejected_before_spawn() {
        use std::os::unix::fs::symlink;

        let root = ResolverDirectory::new("identity-substitution");
        let first = root.tool("first", true);
        let second = root.tool("second", true);
        let alias = root.path().join("cargo");
        symlink(first, &alias).unwrap();
        let resolved = resolve_cargo_from(Some(alias.as_os_str()), &[], &[], true, false).unwrap();
        fs::remove_file(&alias).unwrap();
        symlink(second, &alias).unwrap();
        let error = CommandSpec::cargo_from_resolution(Duration::from_secs(1), Ok(resolved))
            .argument("--version")
            .run()
            .unwrap_err();
        assert_eq!(error.phase(), CommandRunPhase::ProgramResolution);
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn windows_cargo_resolution_is_native_executable_only_and_ordered() {
        assert_eq!(
            windows_executable_extensions(OsStr::new(".BAT;.EXE;.com;.CMD;.exe")),
            [
                OsString::from(".EXE"),
                OsString::from(".com"),
                OsString::from(".exe")
            ]
        );
        let root = ResolverDirectory::new("windows-native");
        let exe = root.tool("cargo.EXE", false);
        root.tool("cargo.com", false);
        root.tool("cargo.BAT", false);
        root.tool("cargo.CMD", false);
        let extensions = windows_executable_extensions(OsStr::new(".BAT;.EXE;.com;.CMD"));
        let resolved = resolve_cargo_from(
            None,
            std::slice::from_ref(&root.0),
            &extensions,
            false,
            true,
        )
        .unwrap();
        assert_eq!(resolved.invocation_path, fs::canonicalize(&exe).unwrap());
        assert_eq!(resolved.canonical_identity, fs::canonicalize(exe).unwrap());
        assert!(
            resolve_cargo_from(
                Some(root.path().join("cargo.BAT").as_os_str()),
                &[],
                &extensions,
                false,
                true,
            )
            .is_err()
        );
        assert!(
            resolve_cargo_from(
                Some(OsStr::new("cargo.cmd")),
                std::slice::from_ref(&root.0),
                &extensions,
                false,
                true,
            )
            .is_err()
        );
        assert!(
            resolve_cargo_from(
                Some(root.path().join("cargo-without-extension").as_os_str()),
                &[],
                &extensions,
                false,
                true,
            )
            .is_err()
        );
        assert!(
            resolve_cargo_from(
                None,
                std::slice::from_ref(&root.0),
                &windows_executable_extensions(OsStr::new(".BAT;.CMD")),
                false,
                true,
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn windows_cargo_resolution_rechecks_the_canonical_target_extension() {
        use std::os::unix::fs::symlink;

        let root = ResolverDirectory::new("windows-reparse-target");
        let script = root.tool("actual.CMD", false);
        let alias = root.path().join("cargo.EXE");
        symlink(script, &alias).unwrap();
        assert!(
            resolve_cargo_from(
                Some(alias.as_os_str()),
                &[],
                &windows_executable_extensions(OsStr::new(".EXE;.COM")),
                false,
                true,
            )
            .is_err(),
            "an EXE alias must not authorize a canonical BAT/CMD target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn windows_cargo_resolution_keeps_a_native_alias_and_separate_identity() {
        use std::os::unix::fs::symlink;

        let root = ResolverDirectory::new("windows-native-alias");
        let target = root.tool("rustup.EXE", false);
        let alias = root.path().join("cargo.EXE");
        symlink(&target, &alias).unwrap();
        let resolved = resolve_cargo_from(
            Some(alias.as_os_str()),
            &[],
            &windows_executable_extensions(OsStr::new(".EXE;.COM")),
            false,
            true,
        )
        .unwrap();
        assert_eq!(
            resolved.invocation_path,
            fs::canonicalize(root.path()).unwrap().join("cargo.EXE")
        );
        assert_eq!(
            resolved.canonical_identity,
            fs::canonicalize(target).unwrap()
        );
        assert_eq!(resolved.invocation_name, "cargo");
    }

    #[test]
    fn environment_reporting_never_contains_values() {
        let spec = CommandSpec::new("program", Duration::from_secs(1))
            .environment("RUSTDOCFLAGS", "secret-value");
        assert_eq!(spec.environment_names(), ["RUSTDOCFLAGS"]);
        assert!(!format!("{:?}", spec.environment_names()).contains("secret-value"));
    }

    #[test]
    fn release_commands_default_to_isolated_tree_scope() {
        let spec = CommandSpec::new("program", Duration::from_secs(1));
        assert_eq!(spec.process_scope, ProcessScope::IsolatedTree);
    }

    #[test]
    fn native_stack_commands_keep_global_options_before_the_subcommand() {
        let source = Path::new("oracle-source");
        let stack_yaml = Path::new("stack.yaml");
        let build = native_stack_build(source, stack_yaml, Duration::from_secs(1));
        assert_eq!(
            build.display_arguments(),
            [
                "--lock-file",
                "error-on-write",
                "--stack-yaml",
                "stack.yaml",
                "build",
            ]
        );
        assert_eq!(build.current_directory.as_deref(), Some(source));
        let path = native_stack_path(source, stack_yaml);
        assert_eq!(
            path.display_arguments(),
            [
                "--lock-file",
                "error-on-write",
                "--stack-yaml",
                "stack.yaml",
                "path",
                "--local-install-root",
            ]
        );
        assert_eq!(path.current_directory.as_deref(), Some(source));
        let ghc = native_stack_ghc_version(source, stack_yaml);
        assert_eq!(
            ghc.display_arguments(),
            [
                "--lock-file",
                "error-on-write",
                "--stack-yaml",
                "stack.yaml",
                "exec",
                "--",
                "ghc",
                "--numeric-version",
            ]
        );
        assert_eq!(ghc.current_directory.as_deref(), Some(source));
    }

    #[test]
    fn native_stack_overlay_preserves_policy_and_scopes_the_link_fix() {
        let base = std::env::temp_dir().join(format!(
            "hell-native-stack-overlay-{}-{}",
            std::process::id(),
            ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let source = base.join("oracle's source");
        fs::create_dir_all(&source).unwrap();
        fs::write(
            source.join("stack.yaml"),
            include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml"),
        )
        .unwrap();
        fs::write(
            source.join("stack.yaml.lock"),
            include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml.lock"),
        )
        .unwrap();
        let directory = create_adapter_directory(&base).unwrap();
        let overlay = write_native_stack_overlay(directory.path(), &source).unwrap();
        let content = fs::read_to_string(&overlay).unwrap();
        assert!(content.starts_with("resolver: nightly-2024-10-21\npackages:\n"));
        assert!(content.contains("oracle''s source'\n"));
        assert!(content.contains("system-ghc: true\nallow-different-user: true\n"));
        assert!(content.contains("  \"$everything\": \"-split-sections -j\"\n"));
        assert!(content.contains("  unix-time: \"-optl-all_load\"\n"));
        assert!(content.contains("  network-control: \"-fforce-recomp\"\n"));
        assert_eq!(content.matches("all_load").count(), 1);
        assert_eq!(content.matches("network-control").count(), 1);
        assert_eq!(content.matches("-fforce-recomp").count(), 1);
        assert!(!content.contains("apply-ghc-options"));
        assert_eq!(
            fs::read(directory.path().join("stack.yaml.lock")).unwrap(),
            include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml.lock")
        );
        fs::write(source.join("stack.yaml"), b"resolver: changed\n").unwrap();
        assert!(
            write_native_stack_overlay(directory.path(), &source)
                .unwrap_err()
                .contains("configuration differs")
        );
        fs::write(
            source.join("stack.yaml"),
            include_bytes!("../../../compat/oracle-sources/hell-8e952cf9/stack.yaml"),
        )
        .unwrap();
        fs::write(source.join("stack.yaml.lock"), b"snapshots: []\n").unwrap();
        assert!(
            write_native_stack_overlay(directory.path(), &source)
                .unwrap_err()
                .contains("lock differs")
        );
        drop(directory);
        assert!(!overlay.parent().unwrap().exists());
        fs::remove_dir_all(base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn native_stack_overlay_rejects_control_and_non_utf8_paths() {
        use std::os::unix::ffi::OsStringExt as _;

        assert!(yaml_single_quoted_path(Path::new("line\nbreak")).is_err());
        assert!(yaml_single_quoted_path(Path::new(&OsString::from_vec(vec![0xff, b'x']))).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn native_archive_path_removes_only_the_provision_directory() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let base = std::env::temp_dir().join(format!(
            "hell-native-archive-path-{}-{}",
            std::process::id(),
            ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let adapter = base.join("adapter");
        let provision = base.join("llvm-keg/bin");
        let provision_alias = base.join("provision-alias");
        let broad = base.join("broad");
        let first = base.join("first");
        let second = base.join("second");
        for directory in [&adapter, &provision, &broad, &first, &second] {
            fs::create_dir_all(directory).unwrap();
        }
        symlink(&provision, &provision_alias).unwrap();
        let llvm_ar = provision.join("llvm-ar");
        for executable in [llvm_ar.clone(), broad.join("clang"), first.join("clang")] {
            fs::write(&executable, b"not executed\n").unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        }
        symlink(&llvm_ar, broad.join("llvm-ar")).unwrap();
        let inherited = std::env::join_paths([
            provision.as_path(),
            first.as_path(),
            provision_alias.as_path(),
            Path::new("broad"),
            second.as_path(),
            first.as_path(),
        ])
        .unwrap();
        let filtered = native_archive_path(&inherited, &adapter, &llvm_ar, &base).unwrap();
        let paths = std::env::split_paths(&filtered).collect::<Vec<_>>();
        assert_eq!(
            paths,
            [
                adapter.clone(),
                first.clone(),
                second.clone(),
                first.clone()
            ]
        );
        assert!(paths.iter().skip(1).all(|entry| {
            fs::canonicalize(entry).unwrap() != fs::canonicalize(&provision).unwrap()
        }));
        let clang = paths
            .iter()
            .map(|entry| entry.join("clang"))
            .find(|candidate| candidate.is_file())
            .unwrap();
        assert_eq!(clang, first.join("clang"));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    #[should_panic(expected = "sensitive environment variables")]
    fn sensitive_environment_cannot_be_reintroduced() {
        let _ = CommandSpec::new("program", Duration::from_secs(1))
            .environment("GITHUB_TOKEN", "secret-value");
    }

    #[cfg(unix)]
    #[test]
    fn posix_adapter_clears_sudo_environment_and_preserves_exact_names() {
        let retained = filtered_posix_release_environment([
            (OsString::from("HOME"), OsString::from("/isolated/home")),
            (
                OsString::from("CARGO_TARGET_DIR"),
                OsString::from("/isolated/target"),
            ),
            (OsString::from("SUDO_COMMAND"), OsString::from("forbidden")),
            (OsString::from("GITHUB_TOKEN"), OsString::from("forbidden")),
        ]);
        assert_eq!(
            retained,
            [
                (OsString::from("HOME"), OsString::from("/isolated/home")),
                (
                    OsString::from("CARGO_TARGET_DIR"),
                    OsString::from("/isolated/target")
                ),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn native_archive_adapter_uses_fixed_flattening_operations() {
        let fresh =
            std::env::temp_dir().join(format!("hell-archive-adapter-fresh-{}", std::process::id()));
        for (input, expected, target) in [
            ("r", "qL", fresh.as_os_str()),
            ("-r", "-qL", fresh.as_os_str()),
            ("q", "qL", OsStr::new("archive.a")),
            ("-q", "-qL", OsStr::new("archive.a")),
            ("qc", "qLc", OsStr::new("archive.a")),
            ("-qc", "-qLc", OsStr::new("archive.a")),
            ("qcL", "qcL", OsStr::new("archive.a")),
            ("-qcL", "-qcL", OsStr::new("archive.a")),
            ("qcls", "qclsL", OsStr::new("archive.a")),
            ("-qcls", "-qclsL", OsStr::new("archive.a")),
            ("qclsL", "qclsL", OsStr::new("archive.a")),
        ] {
            let normalized = normalize_native_archive_arguments(&[
                OsString::from(input),
                OsString::from(target),
                OsString::from("@objects.rsp"),
            ])
            .unwrap();
            assert_eq!(normalized[0], expected);
            assert_eq!(normalized[1], target);
            assert_eq!(normalized[2], "@objects.rsp");
        }
        fs::write(&fresh, b"existing\n").unwrap();
        assert!(
            normalize_native_archive_arguments(&[
                OsString::from("-r"),
                fresh.as_os_str().to_owned(),
                OsString::from("@objects.rsp"),
            ])
            .is_err()
        );
        fs::remove_file(fresh).unwrap();
        let unsupported = normalize_native_archive_arguments(&[OsString::from("qv")]).unwrap_err();
        assert_eq!(
            unsupported.to_string(),
            "archive adapter received unsupported operation \"qv\""
        );
        assert_eq!(
            normalize_native_archive_arguments(
                &[OsString::from("t"), OsString::from("archive.a"),]
            )
            .unwrap(),
            [OsString::from("t"), OsString::from("archive.a")]
        );
        for operation in ["x", "s", "--version"] {
            assert!(
                normalize_native_archive_arguments(&[OsString::from(operation)]).is_err(),
                "unsupported operation {operation:?} was accepted"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn native_adapter_has_one_group_writable_work_directory() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let base = std::env::temp_dir().join(format!(
            "hell-native-adapter-permissions-{}-{}",
            std::process::id(),
            ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o2770)).unwrap();
        let directory = create_adapter_directory(&base).unwrap();
        let path = directory.path().to_owned();
        prepare_adapter_work_directory(&path).unwrap();
        let root = fs::metadata(&path).unwrap();
        let work = fs::metadata(path.join(".stack-work")).unwrap();
        assert_eq!(root.permissions().mode() & 0o7777, 0o2755);
        assert_eq!(work.permissions().mode() & 0o7777, 0o2770);
        assert_eq!(root.gid(), work.gid());
        drop(directory);
        assert!(!path.exists());
        fs::remove_dir(base).unwrap();
    }

    #[test]
    fn native_archive_identity_accepts_only_policy_versions() {
        assert!(accepted_llvm_ar_version(
            "Homebrew LLVM version 18.1.8\n  Optimized build.\n"
        ));
        assert!(accepted_llvm_ar_version(
            "Homebrew LLVM version 22.1.8\n  Optimized build.\n"
        ));
        assert!(!accepted_llvm_ar_version("LLVM version 22.1.8\n"));
        assert!(!accepted_llvm_ar_version("Homebrew LLVM version 22.1.9\n"));
    }

    #[test]
    fn native_archive_adapter_directory_cleans_partial_setup() {
        let base = std::env::temp_dir().join(format!(
            "hell-archive-adapter-cleanup-{}",
            std::process::id()
        ));
        fs::create_dir_all(&base).unwrap();
        let directory = create_adapter_directory(&base).unwrap();
        let path = directory.path().to_owned();
        fs::write(path.join("member.o"), b"partial\n").unwrap();
        drop(directory);
        assert!(!path.exists());
        fs::remove_dir(base).unwrap();
    }

    #[test]
    fn tracked_oracle_checkout_rejects_modified_tracked_files() {
        let root = std::env::temp_dir().join(format!(
            "hell-oracle-checkout-{}-{}",
            std::process::id(),
            ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let git = |arguments: &[&str]| {
            let status = Command::new("git")
                .args(arguments)
                .current_dir(&root)
                .status()
                .unwrap();
            assert!(status.success());
        };
        git(&["init", "--quiet"]);
        fs::write(root.join("tracked"), b"original\n").unwrap();
        git(&["add", "tracked"]);
        git(&[
            "-c",
            "user.name=hell-ci",
            "-c",
            "user.email=hell-ci@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ]);
        let head = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&root)
            .output()
            .unwrap();
        let head = std::str::from_utf8(&head.stdout).unwrap().trim();
        verify_tracked_checkout(&root, head).unwrap();
        fs::write(root.join("untracked"), b"rejected\n").unwrap();
        assert!(verify_tracked_checkout(&root, head).is_err());
        fs::remove_file(root.join("untracked")).unwrap();
        fs::write(root.join("tracked"), b"changed\n").unwrap();
        assert!(verify_tracked_checkout(&root, head).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
