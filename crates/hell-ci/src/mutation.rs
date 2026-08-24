use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use hell_testkit::{SupervisedProgressObserver, sha256_bytes, sha256_file};

use crate::command::CommandSpec;
use crate::identity::require_git_sha;
use crate::json::{JsonValue, canonical_json_bytes};
use crate::release::manifest::write_atomic;

const ASSURANCE_FAILURE_EVIDENCE_EDGE_BYTES: usize = 1_024;
const ASSURANCE_COMMAND_EXECUTION_TIMEOUT: Duration = Duration::from_mins(15);
const ASSURANCE_COMMAND_COMPLETION_RESERVE: Duration = Duration::from_secs(30);
const ASSURANCE_COMMAND_FAILURE_SCHEMA_VERSION: u64 = 1;

#[derive(Clone)]
struct Mutant {
    id: String,
    family: String,
    class: String,
    criticality: String,
    package: String,
    target: String,
    test: String,
    site: String,
    obligation: String,
    claim_group: String,
}

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments.first().and_then(|value| value.to_str()) == Some("mutation")
}

pub(crate) fn active(id: &str) -> bool {
    if !cfg!(feature = "mutation-testing") {
        return false;
    }
    let arguments = std::env::args_os().collect::<Vec<_>>();
    let selected = selected_mutant(&arguments);
    selected
        .as_deref()
        .is_some_and(|selected| selection_activates(selected, id))
}

/// Returns the exact typed mutation suffix selected for this test process.
///
/// The returned values are intended to be appended as separate argv tokens to
/// a feature-matched child binary. An ordinary non-mutation process returns an
/// empty vector.
///
/// # Errors
///
/// Returns an error if the selected mutation ID is not valid UTF-8.
pub fn test_activation_suffix() -> Result<Vec<OsString>, String> {
    #[cfg(feature = "mutation-testing")]
    {
        let arguments = std::env::args_os().collect::<Vec<_>>();
        try_selected_mutant(&arguments)?
            .map(|id| {
                ["--skip", "__hell_mutant", "--skip"]
                    .map(OsString::from)
                    .into_iter()
                    .chain([OsString::from(id)])
                    .collect()
            })
            .map_or_else(|| Ok(Vec::new()), Ok)
    }
    #[cfg(not(feature = "mutation-testing"))]
    Ok(Vec::new())
}

#[cfg(feature = "mutation-testing")]
pub(crate) fn without_test_activation_suffix(
    arguments: &[OsString],
) -> Result<&[OsString], String> {
    let marker_count = arguments
        .iter()
        .filter(|argument| *argument == "__hell_mutant")
        .count();
    if marker_count == 0 {
        return Ok(arguments);
    }
    if marker_count != 1 || arguments.len() < 4 {
        return Err("mutation argv suffix is malformed".to_owned());
    }
    let suffix = &arguments[arguments.len() - 4..];
    if suffix[0] != "--skip"
        || suffix[1] != "__hell_mutant"
        || suffix[2] != "--skip"
        || suffix[3].to_str().is_none()
    {
        return Err("mutation argv suffix is malformed".to_owned());
    }
    let selected = std::env::args_os().collect::<Vec<_>>();
    if try_selected_mutant(&selected)?.as_deref() != suffix[3].to_str() {
        return Err("mutation argv suffix differs from process activation".to_owned());
    }
    Ok(&arguments[..arguments.len() - 4])
}

#[cfg(not(feature = "mutation-testing"))]
pub(crate) fn without_test_activation_suffix(arguments: &[OsString]) -> &[OsString] {
    arguments
}

fn selection_activates(selected: &str, site: &str) -> bool {
    selected == site
        || matches!(
            (selected, site),
            ("drop-final-cell", "required-cell-omitted-from-plan")
                | ("accept-duplicate-cell", "duplicate-cell-accepted")
                | (
                    "ignore-evidence-platform",
                    "native-platform-evidence-substitution"
                )
                | ("use-wall-clock-for-exemption", "exemption-expiry-bypassed")
        )
}

fn selected_mutant(arguments: &[OsString]) -> Option<String> {
    try_selected_mutant(arguments).unwrap_or_else(|error| panic!("{error}"))
}

fn try_selected_mutant(arguments: &[OsString]) -> Result<Option<String>, String> {
    let marker_count = arguments
        .iter()
        .filter(|argument| *argument == "__hell_mutant")
        .count();
    if marker_count == 0 {
        return Ok(None);
    }
    let selections = arguments
        .windows(4)
        .filter(|window| {
            window[0] == "--skip" && window[1] == "__hell_mutant" && window[2] == "--skip"
        })
        .collect::<Vec<_>>();
    if marker_count != 1 {
        return Err("mutation argv marker must be unique".to_owned());
    }
    if selections.len() != 1 {
        return Err("mutation argv is malformed".to_owned());
    }
    Ok(Some(
        selections[0][3]
            .to_str()
            .ok_or_else(|| "mutation id must be UTF-8".to_owned())?
            .to_owned(),
    ))
}

pub(crate) fn run_cli(root: &Path, arguments: &[OsString]) -> ExitCode {
    let result = match arguments.get(1).and_then(|value| value.to_str()) {
        Some("run") => parse_output(arguments).and_then(|output| {
            let candidate = git_head(root)?;
            release_mutation_catalog(root, &output, &candidate)
        }),
        Some("assurance") => {
            parse_assurance_options(arguments).and_then(|options| run_assurance(&options))
        }
        _ => Err("mutation requires `run` or `assurance`".to_owned()),
    };
    match result {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(10)
        }
    }
}

#[derive(Debug)]
struct AssuranceOptions {
    manifest: PathBuf,
    repository_root: PathBuf,
    output: PathBuf,
}

#[derive(Debug)]
struct AssuranceMutant {
    id: String,
    claim: String,
    module: String,
    source: PathBuf,
    symbol: String,
    test_command: Vec<String>,
    vectors: Vec<String>,
}

fn run_assurance(options: &AssuranceOptions) -> Result<String, String> {
    let root = canonical_regular_directory(&options.repository_root, "mutation repository root")?;
    if options.output.exists() {
        return Err(format!(
            "mutation assurance output {} already exists",
            options.output.display()
        ));
    }
    let (catalog_id, mutants, manifest_bytes) = read_assurance_manifest(&options.manifest)?;
    if mutants.len() != 13 {
        return Err(format!(
            "mutation assurance requires exactly 13 mutants, observed {}",
            mutants.len()
        ));
    }
    let mut ids = BTreeSet::new();
    let mut records = Vec::new();
    for mutant in &mutants {
        if !ids.insert(mutant.id.clone()) {
            return Err(format!("duplicate assurance mutant {}", mutant.id));
        }
        validate_assurance_binding(&root, mutant)?;
        records.push(run_assurance_mutant(&catalog_id, &root, mutant)?);
    }
    fs::create_dir_all(&options.output)
        .map_err(|error| format!("cannot create {}: {error}", options.output.display()))?;
    let report = JsonValue::Object(BTreeMap::from([
        ("catalogId".to_owned(), JsonValue::String(catalog_id)),
        (
            "catalogSha256".to_owned(),
            JsonValue::String(sha256_bytes(&manifest_bytes).hex()),
        ),
        ("mutants".to_owned(), JsonValue::Array(records)),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
        ("state".to_owned(), JsonValue::String("passed".to_owned())),
    ]));
    write_atomic(
        &options.output.join("assurance.json"),
        &canonical_json_bytes(&report)?,
    )?;
    Ok(format!(
        "killed {} source-bound assurance mutants",
        mutants.len()
    ))
}

fn run_assurance_mutant(
    catalog_id: &str,
    root: &Path,
    mutant: &AssuranceMutant,
) -> Result<JsonValue, String> {
    let (program, arguments) = mutant
        .test_command
        .split_first()
        .ok_or_else(|| format!("mutant {} has an empty test command", mutant.id))?;
    if program != "cargo" {
        return Err(format!(
            "mutant {} test command executable must be cargo",
            mutant.id
        ));
    }
    validate_argument_vector(&mutant.id, arguments)?;
    let command =
        CommandSpec::new(program, ASSURANCE_COMMAND_EXECUTION_TIMEOUT).current_directory(root);
    let baseline = run_assurance_command(&command, arguments)
        .map_err(|error| format!("cannot run assurance baseline {}: {error}", mutant.id))?;
    if !baseline.status.success() || baseline.timed_out {
        return Err(assurance_command_failure(
            catalog_id,
            AssuranceCommandPhase::Baseline,
            &mutant.id,
            program,
            arguments,
            root,
            &baseline,
        )?);
    }
    let mut mutant_arguments = arguments.to_vec();
    if !mutant_arguments.iter().any(|argument| argument == "--") {
        mutant_arguments.push("--".to_owned());
    }
    mutant_arguments.extend([
        "--skip".to_owned(),
        "__hell_mutant".to_owned(),
        "--skip".to_owned(),
        mutant.id.clone(),
    ]);
    let activated = run_assurance_command(&command, &mutant_arguments)
        .map_err(|error| format!("cannot run assurance mutant {}: {error}", mutant.id))?;
    if activated.status.success() || activated.timed_out {
        return Err(assurance_command_failure(
            catalog_id,
            AssuranceCommandPhase::Activated,
            &mutant.id,
            program,
            &mutant_arguments,
            root,
            &activated,
        )?);
    }
    Ok(JsonValue::Object(BTreeMap::from([
        ("claim".to_owned(), JsonValue::String(mutant.claim.clone())),
        ("detected".to_owned(), JsonValue::Bool(true)),
        ("id".to_owned(), JsonValue::String(mutant.id.clone())),
        (
            "module".to_owned(),
            JsonValue::String(mutant.module.clone()),
        ),
        (
            "source".to_owned(),
            JsonValue::String(mutant.source.to_string_lossy().into_owned()),
        ),
        (
            "symbol".to_owned(),
            JsonValue::String(mutant.symbol.clone()),
        ),
        (
            "vectors".to_owned(),
            JsonValue::Array(
                mutant
                    .vectors
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        ),
    ])))
}

fn run_assurance_command(
    command: &CommandSpec,
    arguments: &[String],
) -> Result<crate::command::CommandResult, crate::command::CommandRunError> {
    let execution_deadline = Instant::now()
        .checked_add(ASSURANCE_COMMAND_EXECUTION_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let completion_deadline = execution_deadline
        .checked_add(ASSURANCE_COMMAND_COMPLETION_RESERVE)
        .unwrap_or(execution_deadline);
    let (progress, _receiver) = SupervisedProgressObserver::bounded(1);
    command
        .clone()
        .arguments(arguments.iter().map(String::as_str))
        .run_until(execution_deadline, completion_deadline, progress)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AssuranceCommandPhase {
    Baseline,
    Activated,
}

impl AssuranceCommandPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Activated => "activated",
        }
    }

    const fn policy_failure(self) -> &'static str {
        match self {
            Self::Baseline => "baseline-not-green",
            Self::Activated => "activated-survived",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AssuranceOutputEvidence {
    Complete {
        bytes: Vec<u8>,
    },
    PrefixSuffix {
        prefix: Vec<u8>,
        suffix: Vec<u8>,
        omitted_bytes: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AssuranceStreamFailureReceipt {
    total_bytes: u64,
    sha256: String,
    capture_truncated: bool,
    evidence: AssuranceOutputEvidence,
}

impl AssuranceStreamFailureReceipt {
    fn new(
        total_bytes: u64,
        sha256: String,
        capture_truncated: bool,
        retained: &[u8],
    ) -> Result<Self, String> {
        let retained_bytes = u64::try_from(retained.len())
            .map_err(|_| "assurance retained output length overflowed".to_owned())?;
        if retained_bytes > total_bytes {
            return Err("assurance retained output exceeds its total byte count".to_owned());
        }
        let edge = ASSURANCE_FAILURE_EVIDENCE_EDGE_BYTES;
        let evidence = if !capture_truncated
            && retained_bytes == total_bytes
            && retained.len() <= edge.saturating_mul(2)
        {
            AssuranceOutputEvidence::Complete {
                bytes: retained.to_vec(),
            }
        } else {
            let prefix_len = retained.len().min(edge);
            let suffix_len = retained.len().saturating_sub(prefix_len).min(edge);
            let omitted_bytes = total_bytes
                .checked_sub(u64::try_from(prefix_len + suffix_len).unwrap_or(u64::MAX))
                .ok_or_else(|| "assurance output evidence exceeds its total bytes".to_owned())?;
            AssuranceOutputEvidence::PrefixSuffix {
                prefix: retained[..prefix_len].to_vec(),
                suffix: retained[retained.len() - suffix_len..].to_vec(),
                omitted_bytes,
            }
        };
        Ok(Self {
            total_bytes,
            sha256,
            capture_truncated,
            evidence,
        })
    }

    fn validate(&self) -> Result<(), String> {
        if self.sha256.len() != 64 || !self.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("assurance output digest is invalid".to_owned());
        }
        match &self.evidence {
            AssuranceOutputEvidence::Complete { bytes } => {
                if self.capture_truncated
                    || u64::try_from(bytes.len()).ok() != Some(self.total_bytes)
                    || bytes.len() > ASSURANCE_FAILURE_EVIDENCE_EDGE_BYTES.saturating_mul(2)
                {
                    return Err("assurance complete output evidence is inconsistent".to_owned());
                }
            }
            AssuranceOutputEvidence::PrefixSuffix {
                prefix,
                suffix,
                omitted_bytes,
            } => {
                if prefix.len() > ASSURANCE_FAILURE_EVIDENCE_EDGE_BYTES
                    || suffix.len() > ASSURANCE_FAILURE_EVIDENCE_EDGE_BYTES
                    || u64::try_from(prefix.len())
                        .ok()
                        .and_then(|prefix| {
                            u64::try_from(suffix.len())
                                .ok()
                                .and_then(|suffix| prefix.checked_add(suffix))
                        })
                        .and_then(|retained| retained.checked_add(*omitted_bytes))
                        != Some(self.total_bytes)
                {
                    return Err(
                        "assurance prefix/suffix output evidence is inconsistent".to_owned()
                    );
                }
            }
        }
        Ok(())
    }

    fn json(&self) -> JsonValue {
        let evidence = match &self.evidence {
            AssuranceOutputEvidence::Complete { bytes } => JsonValue::Object(BTreeMap::from([
                ("bytesHex".to_owned(), JsonValue::String(hex_bytes(bytes))),
                ("kind".to_owned(), JsonValue::String("complete".to_owned())),
                ("omittedBytes".to_owned(), JsonValue::Number(0)),
                (
                    "renderedUtf8Lossy".to_owned(),
                    JsonValue::String(String::from_utf8_lossy(bytes).into_owned()),
                ),
            ])),
            AssuranceOutputEvidence::PrefixSuffix {
                prefix,
                suffix,
                omitted_bytes,
            } => JsonValue::Object(BTreeMap::from([
                (
                    "kind".to_owned(),
                    JsonValue::String("prefix-suffix".to_owned()),
                ),
                ("omittedBytes".to_owned(), JsonValue::Number(*omitted_bytes)),
                (
                    "prefixBytesHex".to_owned(),
                    JsonValue::String(hex_bytes(prefix)),
                ),
                (
                    "prefixRenderedUtf8Lossy".to_owned(),
                    JsonValue::String(String::from_utf8_lossy(prefix).into_owned()),
                ),
                (
                    "suffixBytesHex".to_owned(),
                    JsonValue::String(hex_bytes(suffix)),
                ),
                (
                    "suffixRenderedUtf8Lossy".to_owned(),
                    JsonValue::String(String::from_utf8_lossy(suffix).into_owned()),
                ),
            ])),
        };
        JsonValue::Object(BTreeMap::from([
            (
                "captureTruncated".to_owned(),
                JsonValue::Bool(self.capture_truncated),
            ),
            ("evidence".to_owned(), evidence),
            ("sha256".to_owned(), JsonValue::String(self.sha256.clone())),
            ("totalBytes".to_owned(), JsonValue::Number(self.total_bytes)),
        ]))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AssuranceStatusFailureReceipt {
    kind: String,
    value: Option<String>,
    success: bool,
    timed_out: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AssuranceLifecycleFailureReceipt {
    cleanup_id: Option<u64>,
    forced: bool,
    reaped: bool,
    candidate_quiescence_complete: bool,
    phase_timings: Vec<(&'static str, u64)>,
}

struct AssuranceCommandInvocation<'a> {
    catalog_id: &'a str,
    phase: AssuranceCommandPhase,
    mutant_id: &'a str,
    program: &'a str,
    arguments: &'a [String],
    root: &'a Path,
    execution_timeout: Duration,
    completion_reserve: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AssuranceCommandFailureReceipt {
    schema_version: u64,
    catalog_id: String,
    mutant_id: String,
    phase: AssuranceCommandPhase,
    program: String,
    arguments: Vec<String>,
    cwd_encoding: String,
    cwd_hex: String,
    cwd_rendered: String,
    duration_millis: u64,
    execution_deadline_offset_millis: u64,
    completion_deadline_offset_millis: u64,
    status: AssuranceStatusFailureReceipt,
    stdout: AssuranceStreamFailureReceipt,
    stderr: AssuranceStreamFailureReceipt,
    lifecycle: AssuranceLifecycleFailureReceipt,
}

impl AssuranceCommandFailureReceipt {
    fn new(
        invocation: &AssuranceCommandInvocation<'_>,
        result: &crate::command::CommandResult,
    ) -> Result<Self, String> {
        let (cwd_encoding, cwd_bytes) = native_path_bytes(invocation.root);
        let (status_kind, status_value) = command_status(result.status);
        let receipt = Self {
            schema_version: ASSURANCE_COMMAND_FAILURE_SCHEMA_VERSION,
            catalog_id: invocation.catalog_id.to_owned(),
            mutant_id: invocation.mutant_id.to_owned(),
            phase: invocation.phase,
            program: invocation.program.to_owned(),
            arguments: invocation.arguments.to_vec(),
            cwd_encoding: cwd_encoding.to_owned(),
            cwd_hex: hex_bytes(&cwd_bytes),
            cwd_rendered: invocation.root.to_string_lossy().into_owned(),
            duration_millis: duration_millis(result.duration),
            execution_deadline_offset_millis: duration_millis(invocation.execution_timeout),
            completion_deadline_offset_millis: duration_millis(
                invocation.execution_timeout + invocation.completion_reserve,
            ),
            status: AssuranceStatusFailureReceipt {
                kind: status_kind.to_owned(),
                value: status_value,
                success: result.status.success(),
                timed_out: result.timed_out,
            },
            stdout: AssuranceStreamFailureReceipt::new(
                result.stdout_bytes,
                result.stdout_sha256.hex(),
                result.stdout_truncated,
                &result.stdout,
            )?,
            stderr: AssuranceStreamFailureReceipt::new(
                result.stderr_bytes,
                result.stderr_sha256.hex(),
                result.stderr_truncated,
                &result.stderr,
            )?,
            lifecycle: AssuranceLifecycleFailureReceipt {
                cleanup_id: result.termination.cleanup_id,
                forced: result.termination.forced,
                reaped: result.termination.reaped,
                candidate_quiescence_complete: result.termination.candidate_quiescence_complete,
                phase_timings: result
                    .phase_timings
                    .iter()
                    .map(|timing| (timing.name, duration_millis(timing.elapsed)))
                    .collect(),
            },
        };
        receipt.validate()?;
        Ok(receipt)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != ASSURANCE_COMMAND_FAILURE_SCHEMA_VERSION
            || self.catalog_id.is_empty()
            || self.mutant_id.is_empty()
            || self.program.is_empty()
            || self.arguments.is_empty()
            || self.cwd_hex.is_empty()
            || !matches!(
                self.cwd_encoding.as_str(),
                "unix-bytes" | "windows-utf16le" | "utf8-lossy"
            )
            || !matches!(
                self.status.kind.as_str(),
                "exit-code" | "signal" | "unknown"
            )
            || (self.status.kind == "unknown") != self.status.value.is_none()
            || self.execution_deadline_offset_millis == 0
            || self.completion_deadline_offset_millis < self.execution_deadline_offset_millis
            || self.duration_millis > self.completion_deadline_offset_millis
            || (self.phase == AssuranceCommandPhase::Baseline
                && self.status.success
                && !self.status.timed_out)
            || (self.phase == AssuranceCommandPhase::Activated
                && !self.status.success
                && !self.status.timed_out)
        {
            return Err("assurance command failure receipt differs from schema".to_owned());
        }
        self.stdout.validate()?;
        self.stderr.validate()?;
        let phases = self
            .lifecycle
            .phase_timings
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>();
        if !["stdout-joined", "stderr-joined", "stdin-joined"]
            .iter()
            .all(|expected| phases.contains(expected))
            || phases.last() != Some(&"stdin-joined")
        {
            return Err("assurance command failure receipt lacks terminal I/O phases".to_owned());
        }
        Ok(())
    }

    fn json(&self) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            (
                "catalogId".to_owned(),
                JsonValue::String(self.catalog_id.clone()),
            ),
            ("command".to_owned(), self.command_json()),
            (
                "durationMillis".to_owned(),
                JsonValue::Number(self.duration_millis),
            ),
            ("lifecycle".to_owned(), self.lifecycle_json()),
            (
                "mutantId".to_owned(),
                JsonValue::String(self.mutant_id.clone()),
            ),
            (
                "phase".to_owned(),
                JsonValue::String(self.phase.as_str().to_owned()),
            ),
            (
                "policyFailure".to_owned(),
                JsonValue::String(self.phase.policy_failure().to_owned()),
            ),
            (
                "schemaVersion".to_owned(),
                JsonValue::Number(self.schema_version),
            ),
            ("status".to_owned(), self.status_json()),
            ("stderr".to_owned(), self.stderr.json()),
            ("stdout".to_owned(), self.stdout.json()),
            (
                "timedOut".to_owned(),
                JsonValue::Bool(self.status.timed_out),
            ),
        ]))
    }

    fn command_json(&self) -> JsonValue {
        let cwd = JsonValue::Object(BTreeMap::from([
            (
                "encoding".to_owned(),
                JsonValue::String(self.cwd_encoding.clone()),
            ),
            ("hex".to_owned(), JsonValue::String(self.cwd_hex.clone())),
            (
                "rendered".to_owned(),
                JsonValue::String(self.cwd_rendered.clone()),
            ),
        ]));
        JsonValue::Object(BTreeMap::from([
            (
                "argv".to_owned(),
                JsonValue::Array(
                    std::iter::once(self.program.clone())
                        .chain(self.arguments.iter().cloned())
                        .map(JsonValue::String)
                        .collect(),
                ),
            ),
            (
                "completionDeadlineOffsetMillis".to_owned(),
                JsonValue::Number(self.completion_deadline_offset_millis),
            ),
            ("cwd".to_owned(), cwd),
            (
                "executionDeadlineOffsetMillis".to_owned(),
                JsonValue::Number(self.execution_deadline_offset_millis),
            ),
            (
                "program".to_owned(),
                JsonValue::String(self.program.clone()),
            ),
        ]))
    }

    fn lifecycle_json(&self) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            (
                "candidateQuiescenceComplete".to_owned(),
                JsonValue::Bool(self.lifecycle.candidate_quiescence_complete),
            ),
            (
                "cleanupId".to_owned(),
                self.lifecycle
                    .cleanup_id
                    .map_or(JsonValue::Null, JsonValue::Number),
            ),
            ("forced".to_owned(), JsonValue::Bool(self.lifecycle.forced)),
            (
                "phaseTimings".to_owned(),
                JsonValue::Array(
                    self.lifecycle
                        .phase_timings
                        .iter()
                        .map(|(name, elapsed)| {
                            JsonValue::Object(BTreeMap::from([
                                ("elapsedMillis".to_owned(), JsonValue::Number(*elapsed)),
                                ("name".to_owned(), JsonValue::String((*name).to_owned())),
                            ]))
                        })
                        .collect(),
                ),
            ),
            ("reaped".to_owned(), JsonValue::Bool(self.lifecycle.reaped)),
            (
                "stderrJoined".to_owned(),
                JsonValue::Bool(
                    self.lifecycle
                        .phase_timings
                        .iter()
                        .any(|(name, _)| *name == "stderr-joined"),
                ),
            ),
            (
                "stdinJoined".to_owned(),
                JsonValue::Bool(
                    self.lifecycle
                        .phase_timings
                        .last()
                        .is_some_and(|(name, _)| *name == "stdin-joined"),
                ),
            ),
            (
                "stdoutJoined".to_owned(),
                JsonValue::Bool(
                    self.lifecycle
                        .phase_timings
                        .iter()
                        .any(|(name, _)| *name == "stdout-joined"),
                ),
            ),
        ]))
    }

    fn status_json(&self) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            (
                "kind".to_owned(),
                JsonValue::String(self.status.kind.clone()),
            ),
            ("success".to_owned(), JsonValue::Bool(self.status.success)),
            (
                "value".to_owned(),
                self.status
                    .value
                    .as_ref()
                    .map_or(JsonValue::Null, |value| JsonValue::String(value.clone())),
            ),
        ]))
    }
}

fn assurance_command_failure(
    catalog_id: &str,
    phase: AssuranceCommandPhase,
    mutant_id: &str,
    program: &str,
    arguments: &[String],
    root: &Path,
    result: &crate::command::CommandResult,
) -> Result<String, String> {
    let invocation = AssuranceCommandInvocation {
        catalog_id,
        phase,
        mutant_id,
        program,
        arguments,
        root,
        execution_timeout: ASSURANCE_COMMAND_EXECUTION_TIMEOUT,
        completion_reserve: ASSURANCE_COMMAND_COMPLETION_RESERVE,
    };
    let receipt = AssuranceCommandFailureReceipt::new(&invocation, result)?;
    let encoded = canonical_json_bytes(&receipt.json())?;
    let rendered = String::from_utf8(encoded)
        .map_err(|_| "assurance command failure receipt is not UTF-8".to_owned())?;
    Ok(format!(
        "assurance {} policy failure for {mutant_id}; assuranceCommandFailureReceipt={rendered}",
        phase.as_str()
    ))
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(unix)]
fn native_path_bytes(path: &Path) -> (&'static str, Vec<u8>) {
    use std::os::unix::ffi::OsStrExt as _;
    ("unix-bytes", path.as_os_str().as_bytes().to_vec())
}

#[cfg(windows)]
fn native_path_bytes(path: &Path) -> (&'static str, Vec<u8>) {
    use std::os::windows::ffi::OsStrExt as _;
    (
        "windows-utf16le",
        path.as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect(),
    )
}

#[cfg(not(any(unix, windows)))]
fn native_path_bytes(path: &Path) -> (&'static str, Vec<u8>) {
    ("utf8-lossy", path.to_string_lossy().as_bytes().to_vec())
}

#[cfg(unix)]
fn command_status(status: std::process::ExitStatus) -> (&'static str, Option<String>) {
    use std::os::unix::process::ExitStatusExt as _;
    status.code().map_or_else(
        || {
            status.signal().map_or(("unknown", None), |signal| {
                ("signal", Some(signal.to_string()))
            })
        },
        |code| ("exit-code", Some(code.to_string())),
    )
}

#[cfg(not(unix))]
fn command_status(status: std::process::ExitStatus) -> (&'static str, Option<String>) {
    status
        .code()
        .map(|code| ("exit-code", Some(code.to_string())))
        .unwrap_or(("unknown", None))
}

pub(crate) fn run_assurance_receipt_child_for_integration(mode: &str) -> ExitCode {
    match mode {
        "baseline-failure" => {
            println!("baseline-stdout-tail");
            eprintln!("baseline-stderr-tail");
            ExitCode::from(23)
        }
        "activated-survival" => {
            println!("activated-survival-stdout");
            ExitCode::SUCCESS
        }
        "timeout" => loop {
            std::thread::park();
        },
        "long-output" => {
            let mut stdout = std::io::stdout().lock();
            let mut stderr = std::io::stderr().lock();
            let mut stdout_bytes = vec![b'o'; 5 * 1024 * 1024];
            let mut stderr_bytes = vec![b'e'; 5 * 1024 * 1024];
            stdout_bytes.extend_from_slice(b"long-stdout-tail\n");
            stderr_bytes.extend_from_slice(b"long-stderr-tail\n");
            if stdout.write_all(&stdout_bytes).is_err()
                || stdout.flush().is_err()
                || stderr.write_all(&stderr_bytes).is_err()
                || stderr.flush().is_err()
            {
                return ExitCode::FAILURE;
            }
            ExitCode::from(29)
        }
        _ => ExitCode::FAILURE,
    }
}

pub(crate) fn verify_assurance_command_failure_receipts_for_integration() -> Result<String, String>
{
    let program_path = std::env::current_exe()
        .map_err(|error| format!("cannot resolve assurance receipt verifier: {error}"))?;
    let program = program_path
        .to_str()
        .ok_or_else(|| "assurance receipt verifier path is not UTF-8".to_owned())?
        .to_owned();
    let root = fs::canonicalize(
        std::env::current_dir()
            .map_err(|error| format!("cannot resolve assurance receipt cwd: {error}"))?,
    )
    .map_err(|error| format!("cannot canonicalize assurance receipt cwd: {error}"))?;
    let scenarios = [
        AssuranceReceiptScenario::new(
            "baseline-failure",
            AssuranceCommandPhase::Baseline,
            Duration::from_secs(5),
            Duration::from_secs(2),
        ),
        AssuranceReceiptScenario::new(
            "activated-survival",
            AssuranceCommandPhase::Activated,
            Duration::from_secs(5),
            Duration::from_secs(2),
        ),
        AssuranceReceiptScenario::new(
            "timeout",
            AssuranceCommandPhase::Baseline,
            Duration::from_millis(100),
            Duration::from_secs(5),
        ),
        AssuranceReceiptScenario::new(
            "long-output",
            AssuranceCommandPhase::Baseline,
            Duration::from_secs(10),
            Duration::from_secs(5),
        ),
    ];
    let mut rendered = Vec::new();
    for scenario in scenarios {
        let receipt = run_assurance_receipt_scenario(&program_path, &program, &root, scenario)?;
        reject_assurance_receipt_drift(&receipt)?;
        rendered.push(receipt.json());
    }
    let summary = JsonValue::Object(BTreeMap::from([
        ("receipts".to_owned(), JsonValue::Array(rendered)),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
        ("state".to_owned(), JsonValue::String("verified".to_owned())),
    ]));
    String::from_utf8(canonical_json_bytes(&summary)?)
        .map_err(|_| "assurance receipt verifier summary is not UTF-8".to_owned())
}

#[derive(Clone, Copy)]
struct AssuranceReceiptScenario {
    mode: &'static str,
    phase: AssuranceCommandPhase,
    execution_timeout: Duration,
    completion_reserve: Duration,
}

impl AssuranceReceiptScenario {
    const fn new(
        mode: &'static str,
        phase: AssuranceCommandPhase,
        execution_timeout: Duration,
        completion_reserve: Duration,
    ) -> Self {
        Self {
            mode,
            phase,
            execution_timeout,
            completion_reserve,
        }
    }
}

fn run_assurance_receipt_scenario(
    program_path: &Path,
    program: &str,
    root: &Path,
    scenario: AssuranceReceiptScenario,
) -> Result<AssuranceCommandFailureReceipt, String> {
    let arguments = vec![
        "__verify-assurance-command-failure-receipt-child".to_owned(),
        scenario.mode.to_owned(),
    ];
    let execution_deadline = Instant::now()
        .checked_add(scenario.execution_timeout)
        .ok_or_else(|| "assurance receipt execution deadline overflowed".to_owned())?;
    let completion_deadline = execution_deadline
        .checked_add(scenario.completion_reserve)
        .ok_or_else(|| "assurance receipt completion deadline overflowed".to_owned())?;
    let (progress, _receiver) = SupervisedProgressObserver::bounded(1);
    let result = CommandSpec::new(program_path, scenario.execution_timeout)
        .arguments(arguments.iter().map(String::as_str))
        .current_directory(root)
        .run_until(execution_deadline, completion_deadline, progress)
        .map_err(|error| {
            format!(
                "cannot run assurance receipt scenario {}: {error}",
                scenario.mode
            )
        })?;
    let invocation = AssuranceCommandInvocation {
        catalog_id: "integration-assurance-catalog-v1",
        phase: scenario.phase,
        mutant_id: scenario.mode,
        program,
        arguments: &arguments,
        root,
        execution_timeout: scenario.execution_timeout,
        completion_reserve: scenario.completion_reserve,
    };
    let receipt = AssuranceCommandFailureReceipt::new(&invocation, &result)?;
    validate_assurance_receipt_scenario(scenario.mode, &receipt, &result)?;
    Ok(receipt)
}

fn validate_assurance_receipt_scenario(
    mode: &str,
    receipt: &AssuranceCommandFailureReceipt,
    result: &crate::command::CommandResult,
) -> Result<(), String> {
    let valid = match mode {
        "baseline-failure" => {
            result.status.code() == Some(23)
                && !result.timed_out
                && receipt_contains(&receipt.stdout, b"baseline-stdout-tail")
                && receipt_contains(&receipt.stderr, b"baseline-stderr-tail")
        }
        "activated-survival" => result.status.success() && !result.timed_out,
        "timeout" => result.timed_out && receipt.lifecycle.forced && receipt.lifecycle.reaped,
        "long-output" => long_output_receipt_is_bounded(receipt),
        _ => return Err("unknown assurance receipt scenario".to_owned()),
    };
    if valid {
        Ok(())
    } else {
        Err(format!("{mode} assurance failure receipt differs"))
    }
}

fn long_output_receipt_is_bounded(receipt: &AssuranceCommandFailureReceipt) -> bool {
    receipt.stdout.capture_truncated
        && receipt.stderr.capture_truncated
        && matches!(
            &receipt.stdout.evidence,
            AssuranceOutputEvidence::PrefixSuffix {
                omitted_bytes: 1..,
                ..
            }
        )
        && matches!(
            &receipt.stderr.evidence,
            AssuranceOutputEvidence::PrefixSuffix {
                omitted_bytes: 1..,
                ..
            }
        )
        && receipt_contains(&receipt.stdout, b"long-stdout-tail")
        && receipt_contains(&receipt.stderr, b"long-stderr-tail")
}

fn reject_assurance_receipt_drift(receipt: &AssuranceCommandFailureReceipt) -> Result<(), String> {
    let mut schema_drift = receipt.clone();
    schema_drift.schema_version += 1;
    if schema_drift.validate().is_ok() {
        return Err("assurance receipt schema drift was accepted".to_owned());
    }
    let mut ordering_drift = receipt.clone();
    ordering_drift.lifecycle.phase_timings.reverse();
    if ordering_drift.validate().is_ok() {
        return Err("assurance receipt terminal phase ordering drift was accepted".to_owned());
    }
    Ok(())
}

fn receipt_contains(receipt: &AssuranceStreamFailureReceipt, needle: &[u8]) -> bool {
    match &receipt.evidence {
        AssuranceOutputEvidence::Complete { bytes } => {
            bytes.windows(needle.len()).any(|part| part == needle)
        }
        AssuranceOutputEvidence::PrefixSuffix { prefix, suffix, .. } => {
            prefix.windows(needle.len()).any(|part| part == needle)
                || suffix.windows(needle.len()).any(|part| part == needle)
        }
    }
}

fn validate_argument_vector(id: &str, arguments: &[String]) -> Result<(), String> {
    if arguments.is_empty()
        || !arguments.iter().any(|argument| argument == "test")
        || !arguments.iter().any(|argument| argument == "--locked")
    {
        return Err(format!(
            "mutant {id} test command must be a locked cargo test invocation"
        ));
    }
    for argument in arguments {
        if argument.is_empty()
            || argument.contains(['\0', '\n', '\r'])
            || ["sh", "bash", "-c", "&&", "||", ";", "|"].contains(&argument.as_str())
        {
            return Err(format!("mutant {id} contains an invalid test argument"));
        }
    }
    Ok(())
}

fn validate_assurance_binding(root: &Path, mutant: &AssuranceMutant) -> Result<(), String> {
    let source = safe_relative_path(root, &mutant.source, "mutant source")?;
    let bytes = read_bounded_regular(&source, 4 * 1024 * 1024, "mutant source")?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| format!("{} is not UTF-8", source.display()))?;
    if !contains_symbol(text, &mutant.symbol) {
        return Err(format!(
            "mutant {} symbol {} is absent from {}",
            mutant.id,
            mutant.symbol,
            source.display()
        ));
    }
    if mutant.vectors.is_empty()
        || mutant.vectors.iter().collect::<BTreeSet<_>>().len() != mutant.vectors.len()
    {
        return Err(format!(
            "mutant {} requires distinct vector bindings",
            mutant.id
        ));
    }
    for vector in &mutant.vectors {
        if vector.is_empty() || vector.contains(['\0', '\n', '\r']) {
            return Err(format!("mutant {} has an invalid vector id", mutant.id));
        }
    }
    Ok(())
}

fn contains_symbol(source: &str, expected: &str) -> bool {
    let expected = expected.split("::").collect::<Vec<_>>();
    if expected.is_empty() || expected.iter().any(|part| part.is_empty()) {
        return false;
    }
    if let [type_name, method_name] = expected.as_slice() {
        let impl_marker = format!("impl {type_name} {{");
        let method_marker = format!("fn {method_name}(");
        return source.split(&impl_marker).skip(1).any(|tail| {
            tail.split_once("\n}\n")
                .map_or(tail, |(body, _)| body)
                .contains(&method_marker)
        });
    }
    let identifiers = source
        .split(|character: char| !(character == '_' || character.is_ascii_alphanumeric()))
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    identifiers
        .windows(expected.len())
        .any(|window| window == expected)
        || (expected.len() == 1 && identifiers.contains(&expected[0]))
}

fn read_assurance_manifest(path: &Path) -> Result<(String, Vec<AssuranceMutant>, Vec<u8>), String> {
    let bytes = read_bounded_regular(path, 1024 * 1024, "assurance manifest")?;
    if !bytes.ends_with(b"\n") {
        return Err(format!("{} has no trailing newline", path.display()));
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| format!("{} is not UTF-8", path.display()))?;
    let mut root = BTreeMap::new();
    let mut records = Vec::<BTreeMap<String, String>>::new();
    let mut current = None::<BTreeMap<String, String>>;
    for (line_index, original) in text.lines().enumerate() {
        let line = strip_toml_comment(original)?.trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[mutant]]" {
            if let Some(record) = current.take() {
                records.push(record);
            }
            current = Some(BTreeMap::new());
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("invalid assurance manifest line {}", line_index + 1))?;
        let key = key.trim();
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(format!("invalid assurance key at line {}", line_index + 1));
        }
        let destination = current.as_mut().unwrap_or(&mut root);
        if destination
            .insert(key.to_owned(), value.trim().to_owned())
            .is_some()
        {
            return Err(format!("duplicate assurance key {key}"));
        }
    }
    if let Some(record) = current {
        records.push(record);
    }
    require_exact_keys(
        &root,
        &["catalog-id", "execution-strategy", "schema-version"],
        "assurance root",
    )?;
    if take_integer(&mut root, "schema-version")? != 1
        || take_string(&mut root, "execution-strategy")? != "baseline-pass-mutant-fail"
    {
        return Err("unsupported assurance manifest protocol".to_owned());
    }
    let catalog_id = take_string(&mut root, "catalog-id")?;
    let mut mutants = Vec::new();
    for mut record in records {
        require_exact_keys(
            &record,
            &[
                "claim",
                "id",
                "module",
                "source",
                "symbol",
                "test-command",
                "vectors",
            ],
            "assurance mutant",
        )?;
        mutants.push(AssuranceMutant {
            id: take_string(&mut record, "id")?,
            claim: take_string(&mut record, "claim")?,
            module: take_string(&mut record, "module")?,
            source: PathBuf::from(take_string(&mut record, "source")?),
            symbol: take_string(&mut record, "symbol")?,
            test_command: take_string_array(&mut record, "test-command")?,
            vectors: take_string_array(&mut record, "vectors")?,
        });
    }
    Ok((catalog_id, mutants, bytes))
}

fn parse_assurance_options(arguments: &[OsString]) -> Result<AssuranceOptions, String> {
    let mut manifest = None;
    let mut repository_root = None;
    let mut output = None;
    let mut index = 2_usize;
    while index < arguments.len() {
        let flag = arguments[index]
            .to_str()
            .ok_or_else(|| "mutation assurance option must be UTF-8".to_owned())?;
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("{flag} requires a value"))?;
        let slot = match flag {
            "--manifest" => &mut manifest,
            "--repository-root" => &mut repository_root,
            "--output" => &mut output,
            _ => return Err(format!("unknown mutation assurance option {flag}")),
        };
        if slot.is_some() {
            return Err(format!("{flag} was provided more than once"));
        }
        *slot = Some(PathBuf::from(value));
        index += 2;
    }
    Ok(AssuranceOptions {
        manifest: manifest.ok_or_else(|| "mutation assurance requires --manifest".to_owned())?,
        repository_root: repository_root
            .ok_or_else(|| "mutation assurance requires --repository-root".to_owned())?,
        output: output.ok_or_else(|| "mutation assurance requires --output".to_owned())?,
    })
}

fn require_exact_keys(
    values: &BTreeMap<String, String>,
    expected: &[&str],
    label: &str,
) -> Result<(), String> {
    let observed = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if observed == expected {
        Ok(())
    } else {
        Err(format!(
            "{label} keys differ: expected {expected:?}, observed {observed:?}"
        ))
    }
}

fn take_string(values: &mut BTreeMap<String, String>, key: &str) -> Result<String, String> {
    crate::strict_toml::string(&values.remove(key).ok_or_else(|| format!("missing {key}"))?)
}

fn take_string_array(
    values: &mut BTreeMap<String, String>,
    key: &str,
) -> Result<Vec<String>, String> {
    crate::strict_toml::string_array(&values.remove(key).ok_or_else(|| format!("missing {key}"))?)
}

fn take_integer(values: &mut BTreeMap<String, String>, key: &str) -> Result<u64, String> {
    let value = values.remove(key).ok_or_else(|| format!("missing {key}"))?;
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{key} must be a canonical unsigned integer"))?;
    if value != parsed.to_string() {
        return Err(format!("{key} must be a canonical unsigned integer"));
    }
    Ok(parsed)
}

fn strip_toml_comment(line: &str) -> Result<&str, String> {
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            '#' if !quoted => return Ok(&line[..index]),
            _ => {}
        }
    }
    if quoted {
        Err("unterminated assurance TOML string".to_owned())
    } else {
        Ok(line)
    }
}

fn canonical_regular_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve {label} {}: {error}", path.display()))?;
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|error| format!("cannot inspect {label}: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("{label} is not a regular directory"));
    }
    Ok(canonical)
}

fn safe_relative_path(root: &Path, relative: &Path, label: &str) -> Result<PathBuf, String> {
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "{label} must be a normalized repository-relative path"
        ));
    }
    let joined = root.join(relative);
    let canonical = fs::canonicalize(&joined)
        .map_err(|error| format!("cannot resolve {label} {}: {error}", joined.display()))?;
    if !canonical.starts_with(root) {
        return Err(format!("{label} escapes the repository"));
    }
    Ok(canonical)
}

fn read_bounded_regular(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(format!(
            "{label} {} is not a bounded regular file",
            path.display()
        ));
    }
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read {label} {}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(format!("{label} changed while being read"));
    }
    Ok(bytes)
}

pub(crate) fn release_mutation_catalog(
    root: &Path,
    output: &Path,
    candidate_sha: &str,
) -> Result<String, String> {
    require_git_sha(candidate_sha, "release mutation candidate")?;
    if git_head(root)? != candidate_sha {
        return Err("release mutation checkout differs from the planned candidate".to_owned());
    }
    let catalog_path = root.join("compat/mutants.toml");
    let catalog = fs::read_to_string(&catalog_path)
        .map_err(|error| format!("cannot read mutation catalog: {error}"))?;
    if catalog.as_bytes() != include_bytes!("../../../compat/mutants.toml") {
        return Err("candidate mutation catalog differs from trusted automation".to_owned());
    }
    let values = crate::strict_toml::assignments(&catalog)?;
    let ids = strings(&values, "ids")?;
    let required = booleans(&values, "release_required")?;
    let required_ids = required_mutant_ids_from_values(&values)?;
    let columns = [
        strings(&values, "families")?,
        strings(&values, "classes")?,
        strings(&values, "criticalities")?,
        strings(&values, "packages")?,
        strings(&values, "targets")?,
        strings(&values, "tests")?,
        strings(&values, "mutation_sites")?,
        strings(&values, "obligation_ids")?,
        strings(&values, "claim_group_ids")?,
    ];
    if required.len() != ids.len()
        || columns.iter().any(|column| column.len() != ids.len())
        || ids.iter().collect::<BTreeSet<_>>().len() != ids.len()
        || !required.iter().any(|value| *value)
    {
        return Err("release mutation catalog columns disagree".to_owned());
    }
    let results = output
        .parent()
        .ok_or_else(|| "release mutation output has no directory".to_owned())?
        .join("mutation-results");
    fs::create_dir_all(&results)
        .map_err(|error| format!("cannot create mutation results: {error}"))?;
    let mut records = Vec::new();
    for (index, selected) in required.iter().copied().enumerate() {
        if !selected {
            continue;
        }
        let mutant = Mutant {
            id: ids[index].clone(),
            family: columns[0][index].clone(),
            class: columns[1][index].clone(),
            criticality: columns[2][index].clone(),
            package: columns[3][index].clone(),
            target: columns[4][index].clone(),
            test: columns[5][index].clone(),
            site: columns[6][index].clone(),
            obligation: columns[7][index].clone(),
            claim_group: columns[8][index].clone(),
        };
        records.push(run_mutant(root, &results, index, &mutant)?);
    }
    let report = JsonValue::Object(BTreeMap::from([
        (
            "candidateSha".to_owned(),
            JsonValue::String(candidate_sha.to_owned()),
        ),
        (
            "catalogSha256".to_owned(),
            JsonValue::String(
                sha256_file(&catalog_path)
                    .map_err(|error| format!("cannot hash mutation catalog: {error}"))?
                    .hex(),
            ),
        ),
        (
            "detected".to_owned(),
            JsonValue::Number(
                records
                    .len()
                    .try_into()
                    .map_err(|_| "mutant count overflow")?,
            ),
        ),
        ("mutants".to_owned(), JsonValue::Array(records)),
        (
            "required".to_owned(),
            JsonValue::Number(
                required
                    .iter()
                    .filter(|value| **value)
                    .count()
                    .try_into()
                    .map_err(|_| "mutant count overflow")?,
            ),
        ),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
        ("state".to_owned(), JsonValue::String("passed".to_owned())),
    ]));
    write_atomic(output, &canonical_json_bytes(&report)?)?;
    Ok(format!(
        "killed {} release-required mutants",
        required_ids.len()
    ))
}

pub(crate) fn trusted_required_mutant_ids() -> Result<BTreeSet<String>, String> {
    let trusted = std::str::from_utf8(include_bytes!("../../../compat/mutants.toml"))
        .map_err(|_| "trusted mutation catalog is not UTF-8".to_owned())?;
    let values = crate::strict_toml::assignments(trusted)?;
    required_mutant_ids_from_values(&values)
}

fn required_mutant_ids_from_values(
    values: &BTreeMap<String, String>,
) -> Result<BTreeSet<String>, String> {
    let ids = strings(values, "ids")?;
    let required = booleans(values, "release_required")?;
    if ids.len() != required.len() || ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err("release mutation catalog ID/selection columns disagree".to_owned());
    }
    let selected = ids
        .into_iter()
        .zip(required)
        .filter_map(|(id, selected)| selected.then_some(id))
        .collect::<BTreeSet<_>>();
    if selected.is_empty() {
        return Err("release mutation catalog selects no required mutants".to_owned());
    }
    Ok(selected)
}

fn run_mutant(
    root: &Path,
    results: &Path,
    index: usize,
    mutant: &Mutant,
) -> Result<JsonValue, String> {
    let arguments = cargo_arguments(mutant)?;
    let cargo = CommandSpec::cargo(Duration::from_mins(10)).current_directory(root);
    let baseline = cargo
        .clone()
        .arguments(arguments.iter().map(String::as_str))
        .run()
        .map_err(|error| format!("cannot run mutation baseline {}: {error}", mutant.id))?;
    let mut activated_arguments = arguments.clone();
    activated_arguments.extend([
        "--skip".to_owned(),
        "__hell_mutant".to_owned(),
        "--skip".to_owned(),
        mutant.id.clone(),
    ]);
    let activated = cargo
        .arguments(activated_arguments.iter().map(String::as_str))
        .run()
        .map_err(|error| format!("cannot run mutation {}: {error}", mutant.id))?;
    if !exact_result(&baseline.stdout, &mutant.test, true)?
        || exact_result(&activated.stdout, &mutant.test, true)?
        || activated.status.success()
    {
        return Err(format!("release-required mutant survived: {}", mutant.id));
    }
    let result_path = results.join(format!("mutant-{index}.json"));
    let detail = JsonValue::Object(BTreeMap::from([
        (
            "baselineStatus".to_owned(),
            JsonValue::Number(u64::try_from(baseline.status.code().unwrap_or(255)).unwrap_or(255)),
        ),
        (
            "mutantStatus".to_owned(),
            JsonValue::Number(u64::try_from(activated.status.code().unwrap_or(255)).unwrap_or(255)),
        ),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
    ]));
    let detail_bytes = canonical_json_bytes(&detail)?;
    write_atomic(&result_path, &detail_bytes)?;
    let identity = mutation_identity(mutant, &arguments);
    Ok(JsonValue::Object(BTreeMap::from([
        ("class".to_owned(), JsonValue::String(mutant.class.clone())),
        (
            "criticality".to_owned(),
            JsonValue::String(mutant.criticality.clone()),
        ),
        ("detected".to_owned(), JsonValue::Bool(true)),
        (
            "family".to_owned(),
            JsonValue::String(mutant.family.clone()),
        ),
        ("id".to_owned(), JsonValue::String(mutant.id.clone())),
        (
            "mutationIdentitySha256".to_owned(),
            JsonValue::String(identity),
        ),
        (
            "resultSha256".to_owned(),
            JsonValue::String(sha256_bytes(&detail_bytes).hex()),
        ),
        (
            "strategy".to_owned(),
            JsonValue::String("baseline-pass-mutant-fail".to_owned()),
        ),
        ("test".to_owned(), JsonValue::String(mutant.test.clone())),
    ])))
}

fn cargo_arguments(mutant: &Mutant) -> Result<Vec<String>, String> {
    let mut arguments = vec![
        "test".to_owned(),
        "--locked".to_owned(),
        "-p".to_owned(),
        mutant.package.clone(),
        "--features".to_owned(),
        "mutation-testing".to_owned(),
    ];
    if mutant.target == "lib" {
        arguments.push("--lib".to_owned());
    } else if let Some(name) = mutant.target.strip_prefix("bin:") {
        arguments.extend(["--bin".to_owned(), name.to_owned()]);
    } else if let Some(name) = mutant.target.strip_prefix("test:") {
        arguments.extend(["--test".to_owned(), name.to_owned()]);
    } else {
        return Err(format!("mutation target is invalid: {}", mutant.target));
    }
    arguments.extend([mutant.test.clone(), "--".to_owned(), "--exact".to_owned()]);
    Ok(arguments)
}

fn exact_result(stdout: &[u8], test: &str, passed: bool) -> Result<bool, String> {
    let stdout_text =
        std::str::from_utf8(stdout).map_err(|_| "mutation test output is not UTF-8".to_owned())?;
    let suffix = if passed { " ... ok" } else { " ... FAILED" };
    Ok(stdout_text
        .lines()
        .filter(|line| *line == format!("test {test}{suffix}"))
        .count()
        == 1)
}

fn mutation_identity(mutant: &Mutant, arguments: &[String]) -> String {
    let mut bytes = b"hell-release-mutant-v1\0".to_vec();
    for value in [
        &mutant.id,
        &mutant.site,
        &mutant.obligation,
        &mutant.claim_group,
    ] {
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
    }
    for argument in arguments {
        bytes.extend_from_slice(argument.as_bytes());
        bytes.push(0);
    }
    sha256_bytes(&bytes).hex()
}

fn strings(values: &BTreeMap<String, String>, key: &str) -> Result<Vec<String>, String> {
    crate::strict_toml::string_array(
        values
            .get(key)
            .ok_or_else(|| format!("mutation catalog lacks {key}"))?,
    )
}

fn booleans(values: &BTreeMap<String, String>, key: &str) -> Result<Vec<bool>, String> {
    crate::strict_toml::boolean_array(
        values
            .get(key)
            .ok_or_else(|| format!("mutation catalog lacks {key}"))?,
    )
}

fn git_head(root: &Path) -> Result<String, String> {
    let result = CommandSpec::new("git", Duration::from_secs(30))
        .git_safe_directory(root)
        .arguments(["rev-parse", "HEAD"])
        .current_directory(root)
        .run()
        .map_err(|error| format!("cannot resolve mutation candidate: {error}"))?;
    if !result.status.success() {
        return Err("cannot resolve mutation candidate".to_owned());
    }
    String::from_utf8(result.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| "mutation candidate is not UTF-8".to_owned())
}

fn parse_output(arguments: &[OsString]) -> Result<PathBuf, String> {
    if arguments.get(1).and_then(|value| value.to_str()) != Some("run")
        || arguments.get(2).and_then(|value| value.to_str()) != Some("--output")
        || arguments.len() != 4
    {
        return Err("mutation requires exact `run --output PATH`".to_owned());
    }
    Ok(PathBuf::from(&arguments[3]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_test_output_is_not_detection() {
        assert!(!exact_result(b"test result: ok. 0 passed; 0 failed\n", "named", true).unwrap());
    }

    #[test]
    fn candidate_cannot_weaken_release_required_selection() {
        let trusted = include_bytes!("../../../compat/mutants.toml");
        let weakened = String::from_utf8(trusted.to_vec())
            .unwrap()
            .replacen("true", "false", 1);
        assert_ne!(weakened.as_bytes(), trusted);
        let values = crate::strict_toml::assignments(&weakened).unwrap();
        assert_ne!(
            required_mutant_ids_from_values(&values).unwrap(),
            trusted_required_mutant_ids().unwrap()
        );
    }

    #[test]
    fn mutation_selection_requires_one_exact_typed_argv_shape() {
        let selected = [
            "test-binary",
            "--skip",
            "__hell_mutant",
            "--skip",
            "exact-id",
        ]
        .map(OsString::from);
        assert_eq!(selected_mutant(&selected).as_deref(), Some("exact-id"));
        assert_eq!(selected_mutant(&[OsString::from("test-binary")]), None);
    }

    #[test]
    #[should_panic(expected = "mutation argv is malformed")]
    fn malformed_mutation_selection_fails_closed() {
        let _ = selected_mutant(&["test-binary", "__hell_mutant", "exact-id"].map(OsString::from));
    }
}
