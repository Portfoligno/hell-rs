//! Bounded differential, compatibility-gate, and deterministic-fuzz support.

use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT_SANDBOX: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutputNormalization {
    pub stderr_replacements: Vec<(Vec<u8>, Vec<u8>)>,
    pub normalize_path_separators: bool,
}

#[derive(Clone, Debug)]
pub struct DifferentialCase {
    pub source: Arc<str>,
    pub arguments: Vec<OsString>,
    pub environment: Vec<(OsString, OsString)>,
    pub stdin: Vec<u8>,
    pub timeout: Duration,
    pub normalization: OutputNormalization,
}

impl Default for DifferentialCase {
    fn default() -> Self {
        Self {
            source: Arc::from("main = IO.pure ()\n"),
            arguments: Vec::new(),
            environment: Vec::new(),
            stdin: Vec::new(),
            timeout: Duration::from_secs(5),
            normalization: OutputNormalization::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilesystemEntryKind {
    Directory,
    File,
    SymbolicLink,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemEntry {
    pub relative_path: PathBuf,
    pub kind: FilesystemEntryKind,
    pub contents: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessStatus {
    pub success: bool,
    pub code: Option<i32>,
}

impl From<ExitStatus> for ProcessStatus {
    fn from(status: ExitStatus) -> Self {
        Self {
            success: status.success(),
            code: status.code(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub status: ProcessStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
    pub filesystem: Vec<FilesystemEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MismatchKind {
    Timeout,
    ExitStatus,
    Stdout,
    Stderr,
    Filesystem,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DifferentialMismatch {
    pub kind: MismatchKind,
    pub oracle: Vec<u8>,
    pub candidate: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DifferentialReport {
    pub oracle: Observation,
    pub candidate: Observation,
    pub mismatches: Vec<DifferentialMismatch>,
}

impl DifferentialReport {
    #[must_use]
    pub fn agrees(&self) -> bool {
        self.mismatches.is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DivergenceClass {
    RustBug,
    OracleEnvironment,
    DeliberateDivergence,
    RetainedUpstreamBug,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassifiedMismatch {
    pub mismatch: DifferentialMismatch,
    pub classification: Option<DivergenceClass>,
    pub explanation: Arc<str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseGateReport {
    pub cases_run: usize,
    pub minimum_cases: usize,
    pub unexplained_mismatches: usize,
    pub rust_bug_mismatches: usize,
}

impl ReleaseGateReport {
    #[must_use]
    pub fn passed(&self) -> bool {
        self.cases_run >= self.minimum_cases
            && self.unexplained_mismatches == 0
            && self.rust_bug_mismatches == 0
    }
}

/// Evaluates the deterministic differential release threshold.
#[must_use]
pub fn release_gate(
    cases_run: usize,
    minimum_cases: usize,
    mismatches: &[ClassifiedMismatch],
) -> ReleaseGateReport {
    ReleaseGateReport {
        cases_run,
        minimum_cases,
        unexplained_mismatches: mismatches
            .iter()
            .filter(|mismatch| {
                mismatch.classification.is_none() || mismatch.explanation.trim().is_empty()
            })
            .count(),
        rust_bug_mismatches: mismatches
            .iter()
            .filter(|mismatch| mismatch.classification == Some(DivergenceClass::RustBug))
            .count(),
    }
}

/// Runs one existing script and captures output with the case's bounded
/// timeout. This compatibility wrapper does not snapshot its working tree.
///
/// # Errors
///
/// Returns an I/O error when the child cannot be spawned, communicated with,
/// or collected, and a timed-out error after killing a child that exceeds the
/// configured bound.
pub fn run(executable: &Path, script: &Path, case: &DifferentialCase) -> std::io::Result<Output> {
    let working_directory = script.parent().unwrap_or_else(|| Path::new("."));
    let captured = capture_process(executable, script, working_directory, case)?;
    if captured.timed_out {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("child exceeded differential timeout of {:?}", case.timeout),
        ));
    }
    Ok(Output {
        status: captured.status,
        stdout: captured.stdout,
        stderr: captured.stderr,
    })
}

/// Runs the same source against an oracle and candidate in separate isolated
/// temporary directories, then compares all observable outputs.
///
/// # Errors
///
/// Returns an I/O error if either sandbox or child process cannot be managed.
pub fn differential(
    oracle: &Path,
    candidate: &Path,
    case: &DifferentialCase,
) -> std::io::Result<DifferentialReport> {
    let oracle = fs::canonicalize(oracle)?;
    let candidate = fs::canonicalize(candidate)?;
    let oracle_observation = observe_source(&oracle, case, "oracle")?;
    let candidate_observation = observe_source(&candidate, case, "candidate")?;
    let mismatches = compare(&oracle_observation, &candidate_observation);
    Ok(DifferentialReport {
        oracle: oracle_observation,
        candidate: candidate_observation,
        mismatches,
    })
}

#[must_use]
pub fn compare(oracle: &Observation, candidate: &Observation) -> Vec<DifferentialMismatch> {
    let mut mismatches = Vec::new();
    push_mismatch(
        &mut mismatches,
        MismatchKind::Timeout,
        &[u8::from(oracle.timed_out)],
        &[u8::from(candidate.timed_out)],
    );
    push_mismatch(
        &mut mismatches,
        MismatchKind::ExitStatus,
        format!("{:?}", oracle.status).as_bytes(),
        format!("{:?}", candidate.status).as_bytes(),
    );
    push_mismatch(
        &mut mismatches,
        MismatchKind::Stdout,
        &oracle.stdout,
        &candidate.stdout,
    );
    push_mismatch(
        &mut mismatches,
        MismatchKind::Stderr,
        &oracle.stderr,
        &candidate.stderr,
    );
    if oracle.filesystem != candidate.filesystem {
        mismatches.push(DifferentialMismatch {
            kind: MismatchKind::Filesystem,
            oracle: format!("{:?}", oracle.filesystem).into_bytes(),
            candidate: format!("{:?}", candidate.filesystem).into_bytes(),
        });
    }
    mismatches
}

fn push_mismatch(
    mismatches: &mut Vec<DifferentialMismatch>,
    kind: MismatchKind,
    oracle: &[u8],
    candidate: &[u8],
) {
    if oracle != candidate {
        mismatches.push(DifferentialMismatch {
            kind,
            oracle: oracle.to_vec(),
            candidate: candidate.to_vec(),
        });
    }
}

fn observe_source(
    executable: &Path,
    case: &DifferentialCase,
    label: &str,
) -> std::io::Result<Observation> {
    let sandbox = Sandbox::new(label)?;
    let script = sandbox.path.join("main.hell");
    fs::write(&script, case.source.as_bytes())?;
    let captured = capture_process(executable, &script, &sandbox.path, case)?;
    let mut stderr = replace_all(
        &captured.stderr,
        sandbox.path.to_string_lossy().as_bytes(),
        b"<SANDBOX>",
    );
    for (from, to) in &case.normalization.stderr_replacements {
        stderr = replace_all(&stderr, from, to);
    }
    if case.normalization.normalize_path_separators {
        for byte in &mut stderr {
            if *byte == b'\\' {
                *byte = b'/';
            }
        }
    }
    Ok(Observation {
        status: captured.status.into(),
        stdout: captured.stdout,
        stderr,
        timed_out: captured.timed_out,
        filesystem: snapshot_filesystem(&sandbox.path)?,
    })
}

struct CapturedProcess {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timed_out: bool,
}

fn capture_process(
    executable: &Path,
    script: &Path,
    working_directory: &Path,
    case: &DifferentialCase,
) -> std::io::Result<CapturedProcess> {
    let mut child = Command::new(executable)
        .arg(script)
        .args(&case.arguments)
        .env_clear()
        .envs(case.environment.iter().cloned())
        .current_dir(working_directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&case.stdin)?;
    }
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("piped child stdout was unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("piped child stderr was unavailable"))?;
    let stdout_reader = std::thread::spawn(move || read_to_end(stdout));
    let stderr_reader = std::thread::spawn(move || read_to_end(stderr));

    let started = Instant::now();
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait()? {
            break (status, false);
        }
        if started.elapsed() >= case.timeout {
            child.kill()?;
            break (child.wait()?, true);
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    let stdout = join_reader(stdout_reader, "stdout")?;
    let stderr = join_reader(stderr_reader, "stderr")?;
    Ok(CapturedProcess {
        status,
        stdout,
        stderr,
        timed_out,
    })
}

fn read_to_end(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn join_reader(
    reader: std::thread::JoinHandle<std::io::Result<Vec<u8>>>,
    stream: &str,
) -> std::io::Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| std::io::Error::other(format!("{stream} reader thread panicked")))?
}

fn snapshot_filesystem(root: &Path) -> std::io::Result<Vec<FilesystemEntry>> {
    let mut pending = vec![root.to_path_buf()];
    let mut entries = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            let relative_path = path
                .strip_prefix(root)
                .map_err(std::io::Error::other)?
                .to_path_buf();
            let metadata = fs::symlink_metadata(&path)?;
            let file_type = metadata.file_type();
            if file_type.is_dir() {
                pending.push(path);
                entries.push(FilesystemEntry {
                    relative_path,
                    kind: FilesystemEntryKind::Directory,
                    contents: Vec::new(),
                });
            } else if file_type.is_symlink() {
                entries.push(FilesystemEntry {
                    relative_path,
                    kind: FilesystemEntryKind::SymbolicLink,
                    contents: fs::read_link(path)?
                        .to_string_lossy()
                        .into_owned()
                        .into_bytes(),
                });
            } else {
                entries.push(FilesystemEntry {
                    relative_path,
                    kind: FilesystemEntryKind::File,
                    contents: fs::read(path)?,
                });
            }
        }
    }
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(entries)
}

fn replace_all(input: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    if from.is_empty() {
        return input.to_vec();
    }
    let mut output = Vec::with_capacity(input.len());
    let mut offset = 0;
    while let Some(relative) = input[offset..]
        .windows(from.len())
        .position(|window| window == from)
    {
        let found = offset + relative;
        output.extend_from_slice(&input[offset..found]);
        output.extend_from_slice(to);
        offset = found + from.len();
    }
    output.extend_from_slice(&input[offset..]);
    output
}

struct Sandbox {
    path: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> std::io::Result<Self> {
        let sequence = NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hell-rs-differential-{}-{sequence}-{label}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self { path })
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// A reproducible bounded byte corpus for parser/compiler fuzz smoke tests.
#[derive(Clone, Debug)]
pub struct DeterministicBytes {
    state: u64,
    remaining: usize,
    max_len: usize,
}

impl DeterministicBytes {
    #[must_use]
    pub fn new(seed: u64, cases: usize, max_len: usize) -> Self {
        Self {
            state: seed.max(1),
            remaining: cases,
            max_len,
        }
    }

    fn next_word(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }
}

impl Iterator for DeterministicBytes {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let length = if self.max_len == 0 {
            0
        } else {
            let maximum = u64::try_from(self.max_len).unwrap_or(u64::MAX);
            let length = if maximum == u64::MAX {
                self.next_word()
            } else {
                self.next_word() % (maximum + 1)
            };
            usize::try_from(length).expect("bounded corpus length fits usize")
        };
        Some(
            (0..length)
                .map(|_| self.next_word().to_le_bytes()[0])
                .collect(),
        )
    }
}

/// A reproducible bounded valid-UTF-8 corpus derived from deterministic bytes.
#[derive(Clone, Debug)]
pub struct DeterministicUtf8 {
    bytes: DeterministicBytes,
    max_bytes: usize,
}

impl DeterministicUtf8 {
    #[must_use]
    pub fn new(seed: u64, cases: usize, max_bytes: usize) -> Self {
        Self {
            bytes: DeterministicBytes::new(seed, cases, max_bytes),
            max_bytes,
        }
    }
}

impl Iterator for DeterministicUtf8 {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        self.bytes.next().map(|bytes| {
            let mut text = String::from_utf8_lossy(&bytes).into_owned();
            if text.len() > self.max_bytes {
                let mut boundary = self.max_bytes;
                while !text.is_char_boundary(boundary) {
                    boundary -= 1;
                }
                text.truncate(boundary);
            }
            text
        })
    }
}
