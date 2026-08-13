use std::cell::RefCell;
use std::ffi::OsString;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

use hell_testkit::{Digest, run_supervised_command};

#[derive(Clone, Debug)]
pub struct CommandSpec {
    pub program: OsString,
    pub arguments: Vec<OsString>,
    pub current_directory: Option<PathBuf>,
    pub environment: Vec<(OsString, OsString)>,
    pub removed_environment: Vec<OsString>,
    pub clear_environment: bool,
    pub process_scope: ProcessScope,
    pub timeout: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessScope {
    IsolatedTree,
}

const SENSITIVE_ENVIRONMENT: [&str; 9] = [
    "HELL_GITHUB_TOKEN",
    "GITHUB_TOKEN",
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "GITHUB_OUTPUT",
    "GITHUB_ENV",
    "GITHUB_PATH",
    "GITHUB_STEP_SUMMARY",
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

impl CommandSpec {
    pub fn new(program: impl Into<OsString>, timeout: Duration) -> Self {
        let mut spec = Self {
            program: program.into(),
            arguments: Vec::new(),
            current_directory: None,
            environment: Vec::new(),
            removed_environment: Vec::new(),
            clear_environment: false,
            process_scope: ProcessScope::IsolatedTree,
            timeout,
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

    pub fn environment_remove(mut self, name: impl Into<OsString>) -> Self {
        self.removed_environment.push(name.into());
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

    pub fn display_arguments(&self) -> Vec<String> {
        self.arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    pub fn run(&self) -> std::io::Result<CommandResult> {
        let mut command = Command::new(&self.program);
        command.args(&self.arguments);
        if self.clear_environment {
            command.env_clear();
        }
        for name in SENSITIVE_ENVIRONMENT {
            command.env_remove(name);
        }
        for name in &self.removed_environment {
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
        let output = run_supervised_command(&mut command, &[], self.timeout)?;
        let stdout = output.stdout.retained_bytes();
        let stderr = output.stderr.retained_bytes();
        std::io::stdout().write_all(&stdout)?;
        std::io::stderr().write_all(&stderr)?;
        Ok(CommandResult {
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
        })
    }
}

fn is_sensitive_environment(name: &OsString) -> bool {
    SENSITIVE_ENVIRONMENT
        .iter()
        .any(|sensitive| name == sensitive)
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

    let (program, child_arguments) = arguments
        .split_first()
        .ok_or_else(|| std::io::Error::other("restricted child program is missing"))?;
    let command_line = windows_command_line(program, child_arguments);
    let mut command_line = OsString::from(command_line)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let application = OsString::from(program)
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
fn windows_command_line(program: &std::ffi::OsStr, arguments: &[OsString]) -> OsString {
    use std::os::windows::ffi::OsStrExt as _;
    let mut output = Vec::<u16>::new();
    for argument in std::iter::once(program).chain(arguments.iter().map(OsString::as_os_str)) {
        if !output.is_empty() {
            output.push(u16::from(b' '));
        }
        output.push(u16::from(b'"'));
        let mut slashes = 0_usize;
        for unit in argument.encode_wide() {
            if unit == u16::from(b'\\') {
                slashes += 1;
            } else {
                if unit == u16::from(b'"') {
                    output.extend(std::iter::repeat_n(u16::from(b'\\'), slashes * 2 + 1));
                } else {
                    output.extend(std::iter::repeat_n(u16::from(b'\\'), slashes));
                }
                slashes = 0;
                output.push(unit);
            }
        }
        output.extend(std::iter::repeat_n(u16::from(b'\\'), slashes * 2));
        output.push(u16::from(b'"'));
    }
    OsString::from_wide(&output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_reporting_never_contains_values() {
        let spec = CommandSpec::new("program", Duration::from_secs(1))
            .environment("VISIBLE_NAME", "secret-value");
        assert_eq!(spec.environment_names(), ["VISIBLE_NAME"]);
        assert!(!format!("{:?}", spec.environment_names()).contains("secret-value"));
    }

    #[test]
    fn release_commands_default_to_isolated_tree_scope() {
        let spec = CommandSpec::new("program", Duration::from_secs(1));
        assert_eq!(spec.process_scope, ProcessScope::IsolatedTree);
    }

    #[test]
    #[should_panic(expected = "sensitive environment variables")]
    fn sensitive_environment_cannot_be_reintroduced() {
        let _ = CommandSpec::new("program", Duration::from_secs(1))
            .environment("HELL_GITHUB_TOKEN", "secret-value");
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
}
