use std::ffi::OsString;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const CAPTURE_LIMIT: usize = 1024 * 1024;

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
        command
            .args(&self.arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(directory) = &self.current_directory {
            command.current_dir(directory);
        }

        let started = Instant::now();
        let mut child = command.spawn()?;
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let stdout_reader = thread::spawn(move || read_bounded(stdout));
        let stderr_reader = thread::spawn(move || read_bounded(stderr));

        let (status, timed_out) = loop {
            if let Some(status) = child.try_wait()? {
                break (status, false);
            }
            if started.elapsed() >= self.timeout {
                child.kill()?;
                break (child.wait()?, true);
            }
            thread::sleep(Duration::from_millis(20));
        };

        let (stdout, stdout_truncated) = join_reader(stdout_reader)?;
        let (stderr, stderr_truncated) = join_reader(stderr_reader)?;
        std::io::stdout().write_all(&stdout)?;
        std::io::stderr().write_all(&stderr)?;
        Ok(CommandResult {
            status,
            duration: started.elapsed(),
            timed_out,
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
        })
    }
}

fn read_bounded(mut stream: impl std::io::Read) -> std::io::Result<(Vec<u8>, bool)> {
    let mut captured = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = CAPTURE_LIMIT.saturating_sub(captured.len());
        let retained = remaining.min(read);
        captured.extend_from_slice(&buffer[..retained]);
        truncated |= retained != read;
    }
    Ok((captured, truncated))
}

fn join_reader(
    reader: thread::JoinHandle<std::io::Result<(Vec<u8>, bool)>>,
) -> std::io::Result<(Vec<u8>, bool)> {
    reader
        .join()
        .map_err(|_| std::io::Error::other("output reader panicked"))?
}
