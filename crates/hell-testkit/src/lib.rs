//! Bounded differential, compatibility-gate, and deterministic-fuzz support.

mod artifact;
mod corpus;
mod digest;

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hell_platform::{SupervisedChild, TerminationReport, WaitOutcome};

pub use artifact::{
    EvidenceSummary, retain_mismatch_bundle, retain_observation_bundle, write_evidence_summary,
};
pub use corpus::{
    GeneratedCase, GeneratedType, committed_differential_cases, generated_typed_cases,
};
pub use digest::Digest;
use digest::Sha256;

static NEXT_SANDBOX: AtomicU64 = AtomicU64::new(0);
const COMPLETE_CAPTURE_BYTES: usize = 4 * 1024 * 1024;
const CAPTURE_EDGE_BYTES: usize = 256 * 1024;
const FILE_INLINE_BYTES: usize = 64 * 1024;
const FILESYSTEM_ENTRY_LIMIT: usize = 4_096;
const FILESYSTEM_HASH_BYTES: u64 = 64 * 1024 * 1024;

/// Computes the SHA-256 digest of in-memory evidence bytes.
#[must_use]
pub fn sha256_bytes(bytes: &[u8]) -> Digest {
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest.finish()
}

/// Computes the SHA-256 digest of a file without loading it into memory.
///
/// # Errors
///
/// Returns an I/O error when the file cannot be opened or read.
pub fn sha256_file(path: &Path) -> std::io::Result<Digest> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(digest.finish());
        }
        digest.update(&buffer[..read]);
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutputNormalization {
    pub stderr_replacements: Vec<(Vec<u8>, Vec<u8>)>,
    pub normalize_path_separators: bool,
}

#[derive(Clone, Debug)]
pub struct DifferentialCase {
    pub id: Arc<str>,
    pub source: Arc<str>,
    pub arguments: Vec<OsString>,
    pub environment: Vec<(OsString, OsString)>,
    pub stdin: Vec<u8>,
    pub timeout: Duration,
    pub normalization: OutputNormalization,
    pub environment_profile: EnvironmentProfile,
    pub process_helper_directory: Option<PathBuf>,
    pub mode: DifferentialMode,
}

impl Default for DifferentialCase {
    fn default() -> Self {
        Self {
            id: Arc::from("anonymous"),
            source: Arc::from("main = IO.pure ()\n"),
            arguments: Vec::new(),
            environment: Vec::new(),
            stdin: Vec::new(),
            timeout: Duration::from_secs(5),
            normalization: OutputNormalization::default(),
            environment_profile: EnvironmentProfile::Explicit,
            process_helper_directory: None,
            mode: DifferentialMode::Run,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DifferentialMode {
    Check,
    #[default]
    Run,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EnvironmentProfile {
    Minimal,
    ProcessCapable,
    NativePlatform,
    #[default]
    Explicit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutableRole {
    Oracle,
    Candidate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildInfo {
    pub lines: Arc<[Arc<str>]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutableIdentity {
    pub path: PathBuf,
    pub sha256: Digest,
    pub reported_version: Arc<str>,
    pub build_info: Option<BuildInfo>,
    pub role: ExecutableRole,
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
    pub size: u64,
    pub sha256: Option<Digest>,
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundedCapture {
    pub total_bytes: u64,
    pub sha256: Digest,
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
    pub complete: Option<Vec<u8>>,
    pub truncated: bool,
}

impl BoundedCapture {
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let mut digest = Sha256::new();
        digest.update(&bytes);
        let total_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let truncated = bytes.len() > COMPLETE_CAPTURE_BYTES;
        let prefix = bytes[..bytes.len().min(CAPTURE_EDGE_BYTES)].to_vec();
        let suffix_start = bytes.len().saturating_sub(CAPTURE_EDGE_BYTES);
        let suffix = bytes[suffix_start..].to_vec();
        Self {
            total_bytes,
            sha256: digest.finish(),
            prefix,
            suffix,
            complete: (!truncated).then_some(bytes),
            truncated,
        }
    }

    fn mismatch_bytes(&self) -> Vec<u8> {
        self.complete.clone().unwrap_or_else(|| {
            let mut bytes = self.prefix.clone();
            bytes.extend_from_slice(b"\n<TRUNCATED>\n");
            bytes.extend_from_slice(&self.suffix);
            bytes
        })
    }

    /// Returns the complete capture or its retained prefix/truncation marker/
    /// suffix representation.
    #[must_use]
    pub fn retained_bytes(&self) -> Vec<u8> {
        self.mismatch_bytes()
    }

    fn into_output(self) -> Vec<u8> {
        if let Some(bytes) = self.complete {
            bytes
        } else {
            let mut bytes = self.prefix;
            bytes.extend_from_slice(b"\n<TRUNCATED>\n");
            bytes.extend_from_slice(&self.suffix);
            bytes
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessStatus {
    pub success: bool,
    pub code: Option<i32>,
}

/// Compiler phase represented independently from diagnostic presentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticPhase {
    Parse,
    StaticSemantics,
}

/// Structural diagnostic fields shared by the pinned oracle and candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiagnosticObservation {
    pub phase: DiagnosticPhase,
    pub line: usize,
    pub column: usize,
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
    pub identity: ExecutableIdentity,
    pub case_id: Arc<str>,
    pub environment_profile: EnvironmentProfile,
    pub mode: DifferentialMode,
    pub status: ProcessStatus,
    pub stdout: BoundedCapture,
    pub stderr: BoundedCapture,
    pub timed_out: bool,
    pub diagnostic: Option<DiagnosticObservation>,
    pub filesystem: Vec<FilesystemEntry>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MismatchKind {
    Timeout,
    ExitStatus,
    Stdout,
    Stderr,
    Diagnostic,
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
    PlatformDifference,
    PresentationNormalization,
    DeliberateDivergence,
    RetainedUpstreamBug,
    HarnessFailure,
    Nondeterministic,
    OracleFailure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassifiedMismatch {
    pub mismatch: DifferentialMismatch,
    pub classification: Option<DivergenceClass>,
    pub explanation: Arc<str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseGateReport {
    pub differential_observations: usize,
    pub candidate_stress_cases: usize,
    pub minimum_differential_observations: usize,
    pub harness_failures: usize,
    pub unexpected_timeouts: usize,
    pub unexplained_mismatches: usize,
    pub rust_bug_mismatches: usize,
    pub stale_exact_claims: usize,
    pub missing_evidence_references: usize,
    pub required_platform_skips: usize,
    pub leaked_resources: usize,
    pub dependency_failures: usize,
}

impl ReleaseGateReport {
    /// Whether evidence collection completed without an implementation,
    /// harness, policy, resource, or dependency failure.
    #[must_use]
    pub fn collection_passed(&self) -> bool {
        self.differential_observations >= self.minimum_differential_observations
            && self.harness_failures == 0
            && self.unexpected_timeouts == 0
            && self.unexplained_mismatches == 0
            && self.rust_bug_mismatches == 0
            && self.stale_exact_claims == 0
            && self.leaked_resources == 0
            && self.dependency_failures == 0
    }

    /// Whether validated evidence is also ready for a compatibility promotion.
    #[must_use]
    pub fn promotion_ready(&self) -> bool {
        self.collection_passed()
            && self.missing_evidence_references == 0
            && self.required_platform_skips == 0
    }

    /// Applies the fail-closed promotion gate.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.promotion_ready()
    }
}

pub struct ReleaseGateInput<'a> {
    pub differential_observations: usize,
    pub candidate_stress_cases: usize,
    pub harness_failures: usize,
    pub unexpected_timeouts: usize,
    pub mismatches: &'a [ClassifiedMismatch],
    pub stale_exact_claims: usize,
    pub missing_evidence_references: usize,
    pub required_platform_skips: usize,
    pub leaked_resources: usize,
    pub dependency_failures: usize,
}

/// Evaluates the deterministic differential release threshold.
#[must_use]
pub fn release_gate(
    differential_observations: usize,
    minimum_differential_observations: usize,
    mismatches: &[ClassifiedMismatch],
) -> ReleaseGateReport {
    evaluate_release_gate(
        &ReleaseGateInput {
            differential_observations,
            candidate_stress_cases: 0,
            harness_failures: 0,
            unexpected_timeouts: 0,
            mismatches,
            stale_exact_claims: 0,
            missing_evidence_references: 0,
            required_platform_skips: 0,
            leaked_resources: 0,
            dependency_failures: 0,
        },
        minimum_differential_observations,
    )
}

#[must_use]
pub fn evaluate_release_gate(
    input: &ReleaseGateInput<'_>,
    minimum_differential_observations: usize,
) -> ReleaseGateReport {
    ReleaseGateReport {
        differential_observations: input.differential_observations,
        candidate_stress_cases: input.candidate_stress_cases,
        minimum_differential_observations,
        harness_failures: input.harness_failures,
        unexpected_timeouts: input.unexpected_timeouts,
        unexplained_mismatches: input
            .mismatches
            .iter()
            .filter(|mismatch| {
                mismatch.classification.is_none() || mismatch.explanation.trim().is_empty()
            })
            .count(),
        rust_bug_mismatches: input
            .mismatches
            .iter()
            .filter(|mismatch| mismatch.classification == Some(DivergenceClass::RustBug))
            .count(),
        stale_exact_claims: input.stale_exact_claims,
        missing_evidence_references: input.missing_evidence_references,
        required_platform_skips: input.required_platform_skips,
        leaked_resources: input.leaked_resources,
        dependency_failures: input.dependency_failures,
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
        stdout: captured.stdout.into_output(),
        stderr: captured.stderr.into_output(),
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
    let oracle = inspect_executable(oracle, ExecutableRole::Oracle)?;
    let candidate = inspect_executable(candidate, ExecutableRole::Candidate)?;
    differential_with_identities(&oracle, &candidate, case)
}

/// Runs a case using executable identities that were verified before the
/// corpus, avoiding identity drift and repeated hashing between cases.
///
/// # Errors
///
/// Returns an I/O error if either sandbox or child process cannot be managed.
pub fn differential_with_identities(
    oracle: &ExecutableIdentity,
    candidate: &ExecutableIdentity,
    case: &DifferentialCase,
) -> std::io::Result<DifferentialReport> {
    let oracle_observation = observe_source(oracle, case, "oracle")?;
    let candidate_observation = observe_source(candidate, case, "candidate")?;
    let mismatches = compare(&oracle_observation, &candidate_observation);
    Ok(DifferentialReport {
        oracle: oracle_observation,
        candidate: candidate_observation,
        mismatches,
    })
}

/// Resolves, hashes, and probes one executable through structured arguments.
///
/// # Errors
///
/// Returns an error when the file cannot be hashed, `--version` fails, its
/// output is not one nonempty UTF-8 line, or the probe exceeds five seconds.
pub fn inspect_executable(
    path: &Path,
    role: ExecutableRole,
) -> std::io::Result<ExecutableIdentity> {
    let (path, sha256) = resolve_and_hash(path)?;
    probe_identity(path, sha256, role)
}

/// Verifies the pinned digest and reported language version before a corpus.
///
/// # Errors
///
/// Returns an error if identity inspection fails or either expected identity
/// component differs. No differential case should run after such an error.
pub fn verify_executable(
    path: &Path,
    role: ExecutableRole,
    expected_sha256: Option<Digest>,
    expected_version: &str,
) -> std::io::Result<ExecutableIdentity> {
    let (path, sha256) = resolve_and_hash(path)?;
    if let Some(expected) = expected_sha256
        && sha256 != expected
    {
        return Err(std::io::Error::other(format!(
            "{:?} executable digest mismatch: expected {}, observed {}",
            role,
            expected.hex(),
            sha256.hex()
        )));
    }
    let identity = probe_identity(path, sha256, role)?;
    if identity.reported_version.as_ref() != expected_version {
        return Err(std::io::Error::other(format!(
            "{:?} executable version mismatch: expected {expected_version:?}, observed {:?}",
            role, identity.reported_version
        )));
    }
    Ok(identity)
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
    push_capture_mismatch(
        &mut mismatches,
        MismatchKind::Stdout,
        &oracle.stdout,
        &candidate.stdout,
    );
    if oracle.mode == DifferentialMode::Check && candidate.mode == DifferentialMode::Check {
        push_mismatch(
            &mut mismatches,
            MismatchKind::Diagnostic,
            format!("{:?}", oracle.diagnostic).as_bytes(),
            format!("{:?}", candidate.diagnostic).as_bytes(),
        );
    } else {
        push_capture_mismatch(
            &mut mismatches,
            MismatchKind::Stderr,
            &oracle.stderr,
            &candidate.stderr,
        );
    }
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

fn push_capture_mismatch(
    mismatches: &mut Vec<DifferentialMismatch>,
    kind: MismatchKind,
    oracle: &BoundedCapture,
    candidate: &BoundedCapture,
) {
    if oracle.total_bytes != candidate.total_bytes || oracle.sha256 != candidate.sha256 {
        mismatches.push(DifferentialMismatch {
            kind,
            oracle: oracle.mismatch_bytes(),
            candidate: candidate.mismatch_bytes(),
        });
    }
}

fn observe_source(
    identity: &ExecutableIdentity,
    case: &DifferentialCase,
    label: &str,
) -> std::io::Result<Observation> {
    let sandbox = Sandbox::new(label)?;
    let script = sandbox.path.join("main.hell");
    fs::write(&script, case.source.as_bytes())?;
    let captured = capture_process(&identity.path, &script, &sandbox.path, case)?;
    let stderr = captured
        .stderr
        .complete
        .ok_or_else(|| std::io::Error::other("stderr exceeded the normalization capture bound"))?;
    let mut stderr = scrub_diagnostic_paths(&stderr, &sandbox.path, &script);
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
    let diagnostic = (case.mode == DifferentialMode::Check && !captured.status.success())
        .then(|| parse_diagnostic_observation(&stderr))
        .transpose()?;
    Ok(Observation {
        identity: identity.clone(),
        case_id: Arc::clone(&case.id),
        environment_profile: case.environment_profile,
        mode: case.mode,
        status: captured.status.into(),
        stdout: captured.stdout,
        stderr: BoundedCapture::from_bytes(stderr),
        timed_out: captured.timed_out,
        diagnostic,
        filesystem: snapshot_filesystem(&sandbox.path)?,
    })
}

fn scrub_diagnostic_paths(stderr: &[u8], sandbox: &Path, script: &Path) -> Vec<u8> {
    let sandbox = sandbox.to_string_lossy();
    let script = script.to_string_lossy();
    scrub_diagnostic_path_bytes(stderr, sandbox.as_bytes(), script.as_bytes())
}

fn scrub_diagnostic_path_bytes(stderr: &[u8], sandbox: &[u8], script: &[u8]) -> Vec<u8> {
    let mut scrubbed = stderr.to_vec();
    if let Some(escaped_script) = haskell_show_escaped_windows_path(script) {
        let mut quoted_script = Vec::new();
        quoted_script.push(b'"');
        quoted_script.extend_from_slice(&escaped_script);
        quoted_script.push(b'"');
        scrubbed = replace_all(&scrubbed, &quoted_script, b"\"<SANDBOX>\\main.hell\"");
    }
    replace_all(&scrubbed, sandbox, b"<SANDBOX>")
}

fn haskell_show_escaped_windows_path(path: &[u8]) -> Option<Vec<u8>> {
    path.contains(&b'\\').then(|| {
        let mut escaped = Vec::new();
        for byte in path {
            if *byte == b'\\' {
                escaped.push(b'\\');
            }
            escaped.push(*byte);
        }
        escaped
    })
}

fn parse_diagnostic_observation(stderr: &[u8]) -> std::io::Result<DiagnosticObservation> {
    const SANDBOX_MARKER: &str = "<SANDBOX>";
    const SCRIPT_NAME: &str = "main.hell";
    let text = std::str::from_utf8(stderr)
        .map_err(|_| std::io::Error::other("check diagnostic was not UTF-8"))?;
    let phase = if text.contains("Parse error:") || text.contains("error[H02") {
        DiagnosticPhase::Parse
    } else {
        DiagnosticPhase::StaticSemantics
    };
    let remainder = text
        .split(SANDBOX_MARKER)
        .skip(1)
        .find_map(|remainder| {
            remainder
                .strip_prefix('/')
                .or_else(|| remainder.strip_prefix('\\'))
                .and_then(|path| path.strip_prefix(SCRIPT_NAME))
        })
        .ok_or_else(|| std::io::Error::other("check diagnostic did not identify main.hell"))?;
    let (line, column) = if let Some(location) = remainder.strip_prefix(':') {
        let mut fields = location.split(':');
        let line = parse_location_field(fields.next(), "line")?;
        let column = parse_location_field(fields.next(), "column")?;
        (line, column)
    } else {
        let location = remainder
            .strip_prefix('"')
            .ok_or_else(|| std::io::Error::other("oracle diagnostic had no SrcSpan location"))?;
        let mut fields = location.split_whitespace();
        let line = parse_location_field(fields.next(), "line")?;
        let column = parse_location_field(fields.next(), "column")?;
        (line, column)
    };
    Ok(DiagnosticObservation {
        phase,
        line,
        column,
    })
}

fn parse_location_field(value: Option<&str>, name: &str) -> std::io::Result<usize> {
    value
        .ok_or_else(|| std::io::Error::other(format!("diagnostic had no {name}")))?
        .parse()
        .map_err(|_| std::io::Error::other(format!("diagnostic {name} was not an integer")))
}

fn resolve_and_hash(path: &Path) -> std::io::Result<(PathBuf, Digest)> {
    let path = fs::canonicalize(path)?;
    let sha256 = sha256_file(&path)?;
    Ok((path, sha256))
}

fn probe_identity(
    path: PathBuf,
    sha256: Digest,
    role: ExecutableRole,
) -> std::io::Result<ExecutableIdentity> {
    let reported_version = probe_lines(&path, "--version")?;
    let reported_version: Arc<str> = reported_version
        .first()
        .ok_or_else(|| std::io::Error::other("--version produced no output"))?
        .clone();
    let build_info = if role == ExecutableRole::Candidate {
        probe_lines(&path, "--build-info")
            .ok()
            .map(|lines| BuildInfo {
                lines: lines.into(),
            })
    } else {
        None
    };
    Ok(ExecutableIdentity {
        path,
        sha256,
        reported_version,
        build_info,
        role,
    })
}

fn probe_lines(path: &Path, argument: &str) -> std::io::Result<Vec<Arc<str>>> {
    let mut command = Command::new(path);
    command
        .arg(argument)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = SupervisedChild::spawn(&mut command)?;
    let stdout = child
        .take_stdout()
        .ok_or_else(|| std::io::Error::other("version probe stdout was unavailable"))?;
    let stderr = child
        .take_stderr()
        .ok_or_else(|| std::io::Error::other("version probe stderr was unavailable"))?;
    let stdout_reader = std::thread::spawn(move || read_bounded(stdout));
    let stderr_reader = std::thread::spawn(move || read_bounded(stderr));
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(5))
        .ok_or_else(|| std::io::Error::other("version probe deadline overflowed"))?;
    let status = match child.wait_until(deadline)? {
        WaitOutcome::Exited(status) => {
            let _ = child.terminate()?;
            status
        }
        WaitOutcome::DeadlineExpired => {
            let _ = child.terminate()?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "version probe exceeded five seconds",
            ));
        }
    };
    let stdout = join_reader(stdout_reader, "version stdout")?;
    let stderr = join_reader(stderr_reader, "version stderr")?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "{argument} failed with status {:?}: {}",
            status.code(),
            String::from_utf8_lossy(&stderr.mismatch_bytes())
        )));
    }
    let complete = stdout
        .complete
        .ok_or_else(|| std::io::Error::other("version probe exceeded its capture bound"))?;
    let text = std::str::from_utf8(&complete)
        .map_err(|_| std::io::Error::other("version probe output was not UTF-8"))?;
    let lines: Vec<Arc<str>> = text.lines().map(Arc::<str>::from).collect();
    if lines.is_empty() || lines.iter().any(|line| line.trim().is_empty()) {
        return Err(std::io::Error::other(
            "version probe output must contain nonempty lines",
        ));
    }
    Ok(lines)
}

struct CapturedProcess {
    status: ExitStatus,
    stdout: BoundedCapture,
    stderr: BoundedCapture,
    timed_out: bool,
}

/// Result of a structured host command run under process-tree supervision.
#[derive(Clone, Debug)]
pub struct SupervisedOutput {
    pub status: ExitStatus,
    pub stdout: BoundedCapture,
    pub stderr: BoundedCapture,
    pub timed_out: bool,
    pub termination: Option<TerminationReport>,
}

/// Runs an already-structured command with concurrent bounded capture.
///
/// The caller supplies program and arguments through [`Command`]; this helper
/// never performs shell parsing. It drains both output streams to EOF, retains
/// their complete SHA-256 digests, and terminates the full process group or Job
/// Object at the deadline.
///
/// # Errors
///
/// Returns an error when the process tree, input writer, capture reader, or
/// cleanup operation fails.
pub fn run_supervised_command(
    command: &mut Command,
    input: &[u8],
    timeout: Duration,
) -> std::io::Result<SupervisedOutput> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = SupervisedChild::spawn(command)?;

    let stdout = child
        .take_stdout()
        .ok_or_else(|| std::io::Error::other("piped child stdout was unavailable"))?;
    let stderr = child
        .take_stderr()
        .ok_or_else(|| std::io::Error::other("piped child stderr was unavailable"))?;
    let stdout_reader = std::thread::spawn(move || read_bounded(stdout));
    let stderr_reader = std::thread::spawn(move || read_bounded(stderr));
    let stdin = child.take_stdin();
    let input = input.to_vec();
    let stdin_writer = std::thread::spawn(move || {
        if let Some(mut stdin) = stdin {
            stdin.write_all(&input)?;
        }
        Ok::<(), std::io::Error>(())
    });

    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| std::io::Error::other("process deadline overflowed"))?;
    let (status, timed_out, termination) = match child.wait_until(deadline)? {
        WaitOutcome::Exited(status) => {
            // A leader may exit while descendants retain pipe handles. Close
            // the complete group/job before joining readers, while preserving
            // the leader's status as the observed result.
            let (_, cleanup) = child.terminate()?;
            (status, false, Some(cleanup))
        }
        WaitOutcome::DeadlineExpired => {
            let (status, termination) = child.terminate()?;
            if !termination.reaped {
                return Err(std::io::Error::other(
                    "timed-out process tree was not completely reaped",
                ));
            }
            (status, true, Some(termination))
        }
    };
    let stdout = join_reader(stdout_reader, "stdout")?;
    let stderr = join_reader(stderr_reader, "stderr")?;
    stdin_writer
        .join()
        .map_err(|_| std::io::Error::other("stdin writer thread panicked"))??;
    Ok(SupervisedOutput {
        status,
        stdout,
        stderr,
        timed_out,
        termination,
    })
}

fn capture_process(
    executable: &Path,
    script: &Path,
    working_directory: &Path,
    case: &DifferentialCase,
) -> std::io::Result<CapturedProcess> {
    let mut command = Command::new(executable);
    match case.mode {
        DifferentialMode::Check => {
            command.arg("--check").arg(script);
        }
        DifferentialMode::Run => {
            command.arg(script).args(&case.arguments);
        }
    }
    command.env_clear();
    match case.environment_profile {
        EnvironmentProfile::Minimal => {}
        EnvironmentProfile::ProcessCapable => {
            let helper_directory = case.process_helper_directory.as_ref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "ProcessCapable requires process_helper_directory",
                )
            })?;
            if !helper_directory.is_absolute() || !helper_directory.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "ProcessCapable helper directory must be an existing absolute directory",
                ));
            }
            let path = std::env::join_paths([helper_directory])
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
            command.env("PATH", path);
        }
        EnvironmentProfile::NativePlatform => {
            command.envs(std::env::vars_os());
        }
        EnvironmentProfile::Explicit => {
            command.envs(case.environment.iter().cloned());
        }
    }
    command.current_dir(working_directory);
    let captured = run_supervised_command(&mut command, &case.stdin, case.timeout)?;
    Ok(CapturedProcess {
        status: captured.status,
        stdout: captured.stdout,
        stderr: captured.stderr,
        timed_out: captured.timed_out,
    })
}

fn read_bounded(mut reader: impl Read) -> std::io::Result<BoundedCapture> {
    let mut digest = Sha256::new();
    let mut complete = Vec::new();
    let mut prefix = Vec::with_capacity(CAPTURE_EDGE_BYTES);
    let mut suffix = VecDeque::with_capacity(CAPTURE_EDGE_BYTES);
    let mut total_bytes = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let bytes = &buffer[..read];
        digest.update(bytes);
        total_bytes = total_bytes
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or_else(|| std::io::Error::other("captured byte count overflowed"))?;
        if complete.len() <= COMPLETE_CAPTURE_BYTES.saturating_sub(read) {
            complete.extend_from_slice(bytes);
        } else {
            complete.clear();
        }
        let prefix_remaining = CAPTURE_EDGE_BYTES.saturating_sub(prefix.len());
        prefix.extend_from_slice(&bytes[..bytes.len().min(prefix_remaining)]);
        suffix.extend(bytes.iter().copied());
        while suffix.len() > CAPTURE_EDGE_BYTES {
            suffix.pop_front();
        }
    }
    let truncated = total_bytes > u64::try_from(COMPLETE_CAPTURE_BYTES).unwrap_or(u64::MAX);
    Ok(BoundedCapture {
        total_bytes,
        sha256: digest.finish(),
        prefix,
        suffix: suffix.into(),
        complete: (!truncated).then_some(complete),
        truncated,
    })
}

fn join_reader(
    reader: std::thread::JoinHandle<std::io::Result<BoundedCapture>>,
    stream: &str,
) -> std::io::Result<BoundedCapture> {
    reader
        .join()
        .map_err(|_| std::io::Error::other(format!("{stream} reader thread panicked")))?
}

fn snapshot_filesystem(root: &Path) -> std::io::Result<Vec<FilesystemEntry>> {
    let mut pending = vec![root.to_path_buf()];
    let mut entries = Vec::new();
    let mut hashed_bytes = 0_u64;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            if entries.len() >= FILESYSTEM_ENTRY_LIMIT {
                return Err(std::io::Error::other(
                    "filesystem observation exceeded its entry limit",
                ));
            }
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
                    size: 0,
                    sha256: None,
                    truncated: false,
                });
            } else if file_type.is_symlink() {
                let target = fs::read_link(path)?
                    .to_string_lossy()
                    .into_owned()
                    .into_bytes();
                entries.push(FilesystemEntry {
                    relative_path,
                    kind: FilesystemEntryKind::SymbolicLink,
                    size: u64::try_from(target.len()).unwrap_or(u64::MAX),
                    contents: target,
                    sha256: None,
                    truncated: false,
                });
            } else {
                let size = metadata.len();
                hashed_bytes = hashed_bytes.checked_add(size).ok_or_else(|| {
                    std::io::Error::other("filesystem hashed-byte count overflowed")
                })?;
                if hashed_bytes > FILESYSTEM_HASH_BYTES {
                    return Err(std::io::Error::other(
                        "filesystem observation exceeded its hashed-byte limit",
                    ));
                }
                let capture = read_bounded(fs::File::open(path)?)?;
                entries.push(FilesystemEntry {
                    relative_path,
                    kind: FilesystemEntryKind::File,
                    contents: capture.complete.as_ref().map_or_else(
                        || capture.prefix.clone(),
                        |bytes| bytes[..bytes.len().min(FILE_INLINE_BYTES)].to_vec(),
                    ),
                    size,
                    sha256: Some(capture.sha256),
                    truncated: size > u64::try_from(FILE_INLINE_BYTES).unwrap_or(u64::MAX),
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

#[cfg(test)]
mod diagnostic_tests {
    use super::{
        DiagnosticObservation, DiagnosticPhase, parse_diagnostic_observation,
        scrub_diagnostic_path_bytes,
    };

    #[test]
    fn diagnostic_path_scrubbing_handles_exact_windows_show_quoting_only() {
        let sandbox = br"C:\work\sandbox";
        let script = br"C:\work\sandbox\main.hell";
        let escaped = br#"SrcSpan "C:\\work\\sandbox\\main.hell" 1 17 1 33"#;
        let scrubbed = scrub_diagnostic_path_bytes(escaped, sandbox, script);
        assert_eq!(scrubbed, br#"SrcSpan "<SANDBOX>\main.hell" 1 17 1 33"#);
        assert_eq!(
            parse_diagnostic_observation(&scrubbed).expect("scrubbed Show diagnostic"),
            DiagnosticObservation {
                phase: DiagnosticPhase::StaticSemantics,
                line: 1,
                column: 17,
            }
        );
        assert_eq!(
            scrub_diagnostic_path_bytes(
                br"C:\work\sandbox\main.hell:1:17: error[H0402]",
                sandbox,
                script,
            ),
            br"<SANDBOX>\main.hell:1:17: error[H0402]"
        );

        for near_match in [
            br#"SrcSpan "C:\\work\\sandbox\\main.hellish" 1 17"#.as_slice(),
            br#"SrcSpan "C:\\work\\sandbox-other\\main.hell" 1 17"#.as_slice(),
            br"unquoted C:\\work\\sandbox\\main.hell 1 17".as_slice(),
        ] {
            assert_eq!(
                scrub_diagnostic_path_bytes(near_match, sandbox, script),
                near_match
            );
        }
    }

    #[test]
    fn oracle_and_candidate_diagnostics_reduce_to_the_same_structure() {
        let parse_diagnostics: [&[u8]; 4] = [
            b"hell: Parse error: <SANDBOX>/main.hell:2:1: Parse error: ;\n",
            b"<SANDBOX>/main.hell:2:1: error[H0200]: expected expression\n",
            b"hell: Parse error: <SANDBOX>\\main.hell:2:1: Parse error: ;\n",
            b"<SANDBOX>\\main.hell:2:1: error[H0200]: expected expression\n",
        ];
        for diagnostic in parse_diagnostics {
            assert_eq!(
                parse_diagnostic_observation(diagnostic).expect("parse diagnostic"),
                DiagnosticObservation {
                    phase: DiagnosticPhase::Parse,
                    line: 2,
                    column: 1,
                }
            );
        }

        let static_diagnostics: [&[u8]; 4] = [
            b"hell: Invalid variable: Qual (SrcSpanInfo {srcInfoSpan = SrcSpan \"<SANDBOX>/main.hell\" 1 17 1 33})\n",
            b"<SANDBOX>/main.hell:1:17: error[H0402]: unknown global `Main.missingName`\n",
            b"hell: Invalid variable: Qual (SrcSpanInfo {srcInfoSpan = SrcSpan \"<SANDBOX>\\main.hell\" 1 17 1 33})\n",
            b"<SANDBOX>\\main.hell:1:17: error[H0402]: unknown global `Main.missingName`\n",
        ];
        for diagnostic in static_diagnostics {
            assert_eq!(
                parse_diagnostic_observation(diagnostic).expect("static diagnostic"),
                DiagnosticObservation {
                    phase: DiagnosticPhase::StaticSemantics,
                    line: 1,
                    column: 17,
                }
            );
        }
    }

    #[test]
    fn diagnostic_script_marker_rejects_near_match_paths() {
        for diagnostic in [
            b"<SANDBOX>main.hell:1:1: error[H0200]".as_slice(),
            b"<SANDBOX>//main.hell:1:1: error[H0200]".as_slice(),
            b"<SANDBOX>\\\\main.hell:1:1: error[H0200]".as_slice(),
            b"<SANDBOX>/other/main.hell:1:1: error[H0200]".as_slice(),
            b"<SANDBOX>\\other\\main.hell:1:1: error[H0200]".as_slice(),
            b"<SANDBOX>/main.hellish:1:1: error[H0200]".as_slice(),
        ] {
            assert!(parse_diagnostic_observation(diagnostic).is_err());
        }
        assert_eq!(
            parse_diagnostic_observation(
                b"noise <SANDBOX>wrong <SANDBOX>\\main.hell:3:4: error[H0200]"
            )
            .expect("later exact marker"),
            DiagnosticObservation {
                phase: DiagnosticPhase::Parse,
                line: 3,
                column: 4,
            }
        );
    }
}
