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
    pub timeout: Duration,
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
        Self {
            program: program.into(),
            arguments: Vec::new(),
            current_directory: None,
            timeout,
        }
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
        if let Some(directory) = &self.current_directory {
            command.current_dir(directory);
        }

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
