use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::command::{CommandSpec, ResolvedCargoExecutable, resolve_cargo_executable};
#[cfg(unix)]
use crate::command::{ResolvedStandardExecutable, resolve_standard_path_executable};
use crate::json::{self, JsonValue};

const REQUIRED_TARGETS: [&str; 31] = [
    "strict_json",
    "release_plan",
    "conformance_plan",
    "trusted_inputs",
    "platform_report",
    "evidence_manifest",
    "evidence_repository",
    "partition_reconstruction",
    "release_acceptance",
    "subjects_manifest",
    "release_gate",
    "publication_envelope",
    "governance_api_response",
    "governance_profile",
    "native_environment",
    "gzip_framing",
    "gnu_tar_subset",
    "release_bundle_inventory",
    "workflow_yaml_subset",
    "workflow_expression",
    "workflow_run_invocation",
    "independent_strict_json",
    "independent_release_plan",
    "independent_conformance_plan",
    "independent_evidence",
    "independent_ledger",
    "independent_exemption",
    "independent_gzip",
    "independent_gnu_tar",
    "independent_subjects",
    "independent_publication_envelope",
];

const RETAINED_TARGETS: [&str; 5] = [
    "requirement_toml",
    "normalizer_toml",
    "divergence_toml",
    "normalizer_replay",
    "semantic_trace",
];

const PRESERVED_REGRESSION_CORPORA: [&str; 9] = [
    "acquisition_receipt",
    "claim_toml",
    "custody_receipt",
    "dsse_envelope",
    "evidence_graph_merge",
    "observation_bundle_manifest",
    "provenance_record",
    "review_graph",
    "worklist_escaping",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    StrictJson,
    ReleasePlan,
    ConformancePlan,
    TrustedInputs,
    PlatformReport,
    EvidenceManifest,
    EvidenceRepository,
    PartitionReconstruction,
    ReleaseAcceptance,
    SubjectsManifest,
    ReleaseGate,
    PublicationEnvelope,
    GovernanceApiResponse,
    GovernanceProfile,
    NativeEnvironment,
    GzipFraming,
    GnuTarSubset,
    ReleaseBundleInventory,
}

impl Target {
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "strict_json" => Some(Self::StrictJson),
            "release_plan" => Some(Self::ReleasePlan),
            "conformance_plan" => Some(Self::ConformancePlan),
            "trusted_inputs" => Some(Self::TrustedInputs),
            "platform_report" => Some(Self::PlatformReport),
            "evidence_manifest" => Some(Self::EvidenceManifest),
            "evidence_repository" => Some(Self::EvidenceRepository),
            "partition_reconstruction" => Some(Self::PartitionReconstruction),
            "release_acceptance" => Some(Self::ReleaseAcceptance),
            "subjects_manifest" => Some(Self::SubjectsManifest),
            "release_gate" => Some(Self::ReleaseGate),
            "publication_envelope" => Some(Self::PublicationEnvelope),
            "governance_api_response" => Some(Self::GovernanceApiResponse),
            "governance_profile" => Some(Self::GovernanceProfile),
            "native_environment" => Some(Self::NativeEnvironment),
            "gzip_framing" => Some(Self::GzipFraming),
            "gnu_tar_subset" => Some(Self::GnuTarSubset),
            "release_bundle_inventory" => Some(Self::ReleaseBundleInventory),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FuzzFailure {
    pub code: &'static str,
    pub message: String,
}

impl FuzzFailure {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: "fuzz.input.invalid",
            message: message.into(),
        }
    }
}

/// Exercises the selected production parser surface with bounded bytes.
///
/// # Errors
///
/// Returns a typed failure when the bytes exceed the input limit or the
/// selected parser rejects them.
pub fn exercise(target: Target, bytes: &[u8]) -> Result<(), FuzzFailure> {
    const MAX_INPUT: usize = 64 * 1024 * 1024;
    if bytes.len() > MAX_INPUT {
        return Err(FuzzFailure {
            code: "fuzz.input.limit",
            message: "fuzz input exceeds the production surface bound".to_owned(),
        });
    }
    let result = match target {
        Target::GzipFraming => crate::release::fuzz_verify_gzip(bytes),
        Target::GnuTarSubset => crate::release::fuzz_verify_tar(bytes, 0),
        Target::SubjectsManifest | Target::ReleaseBundleInventory => {
            crate::release::fuzz_parse_subjects(bytes)
        }
        Target::StrictJson => canonical_value(bytes).map(|_| ()),
        Target::ReleasePlan => canonical_value(bytes)
            .and_then(|value| crate::release::schema::ReleasePlan::parse(&value).map(|_| ())),
        Target::ConformancePlan => canonical_value(bytes)
            .and_then(|value| crate::conformance::ConformancePlan::parse(&value).map(|_| ())),
        Target::TrustedInputs => canonical_value(bytes)
            .and_then(|value| crate::conformance::parse_trusted_inputs(&value).map(|_| ())),
        Target::PlatformReport => canonical_value(bytes)
            .and_then(|value| crate::release::assemble::fuzz_parse_platform_report(&value)),
        Target::EvidenceManifest => canonical_value(bytes)
            .and_then(|value| crate::conformance::EvidenceManifest::parse(&value).map(|_| ())),
        Target::EvidenceRepository => canonical_value(bytes)
            .and_then(|value| crate::conformance::fuzz_validate_evidence_repository(&value)),
        Target::PartitionReconstruction => canonical_value(bytes)
            .and_then(|value| crate::conformance::fuzz_reconstruct_partition(&value)),
        Target::ReleaseAcceptance => canonical_value(bytes)
            .and_then(|value| crate::conformance::ConformanceAcceptance::parse(&value).map(|_| ())),
        Target::ReleaseGate => {
            canonical_value(bytes).and_then(|value| crate::release::fuzz_parse_release_gate(&value))
        }
        Target::PublicationEnvelope => canonical_value(bytes)
            .and_then(|value| crate::release::fuzz_parse_publication_envelope(&value)),
        Target::GovernanceApiResponse => canonical_value(bytes)
            .and_then(|value| crate::release::governance::fuzz_parse_api_response(&value)),
        Target::GovernanceProfile => canonical_value(bytes)
            .and_then(|value| crate::release::governance::fuzz_parse_profile(&value)),
        Target::NativeEnvironment => canonical_value(bytes)
            .and_then(|value| crate::release::native_environment::fuzz_parse_receipt(&value)),
    };
    result.map_err(FuzzFailure::invalid)
}

fn canonical_value(bytes: &[u8]) -> Result<JsonValue, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "JSON fuzz input is not UTF-8".to_owned())?;
    let value = json::parse_json_classified(text).map_err(|error| error.message)?;
    if json::canonical_json_bytes(&value)? != bytes {
        return Err("JSON fuzz input is not canonical with one trailing LF".to_owned());
    }
    Ok(value)
}

#[derive(Clone)]
struct ManifestTarget {
    id: String,
    implementation: String,
    class: String,
    fuzz_directory: PathBuf,
    cargo_target: String,
    source: PathBuf,
    maximum_input_bytes: u64,
    maximum_depth: u64,
    maximum_records: u64,
    timeout_seconds: u64,
    corpus: PathBuf,
    artifact_directory: PathBuf,
    engine_arguments: Vec<String>,
    invariant: String,
}

struct Manifest {
    toolchain: String,
    cargo_fuzz_version: String,
    runs_per_target: u64,
    timeout_seconds: u64,
    targets: Vec<ManifestTarget>,
}

struct TargetResult {
    id: String,
    duration_millis: u64,
    source_corpus_sha256: String,
    stdout_sha256: String,
    stderr_sha256: String,
    staged_corpus_sha256: String,
}

struct FuzzToolReceipt {
    cargo: ResolvedCargoExecutable,
    cargo_sha256: String,
    #[cfg(unix)]
    cargo_fuzz: ResolvedStandardExecutable,
    cargo_fuzz_sha256: String,
}

#[derive(Clone, Eq, PartialEq)]
struct CorpusSnapshot {
    files: BTreeMap<String, (u64, String)>,
    sha256: String,
}

struct FuzzDiagnostic {
    code: &'static str,
    message: String,
}

impl FuzzDiagnostic {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[must_use]
pub fn recognizes(arguments: &[OsString]) -> bool {
    arguments.first().is_some_and(|argument| argument == "fuzz")
}

/// Runs the exact fuzz inventory check or bounded smoke campaign.
///
/// # Errors
///
/// Returns an error when command arguments, the manifest, the physical fuzz
/// inventory, a campaign, or report persistence fails.
pub fn run_cli(arguments: &[OsString]) -> Result<String, String> {
    let (command, manifest, repository_root, output) = parse_cli_options(arguments)?;
    if output.exists() {
        return Err("fuzz check output already exists".to_owned());
    }
    let result = check_manifest(&manifest, &repository_root)
        .and_then(|inventory| fuzz_report(&command, &inventory, &repository_root));
    persist_fuzz_result(&command, &output, result)
}

fn parse_cli_options(
    arguments: &[OsString],
) -> Result<(String, PathBuf, PathBuf, PathBuf), String> {
    let command = arguments
        .get(1)
        .and_then(|value| value.to_str())
        .ok_or_else(fuzz_usage)?
        .to_owned();
    let mut manifest = None;
    let mut repository_root = None;
    let mut output = None;
    let mut index = 2;
    while index < arguments.len() {
        let flag = arguments[index]
            .to_str()
            .ok_or_else(|| "fuzz option must be UTF-8".to_owned())?;
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match flag {
            "--manifest" if manifest.is_none() => manifest = Some(PathBuf::from(value)),
            "--repository-root" if repository_root.is_none() => {
                repository_root = Some(PathBuf::from(value));
            }
            "--output" if output.is_none() => output = Some(PathBuf::from(value)),
            "--manifest" | "--repository-root" | "--output" => {
                return Err(format!("{flag} was provided more than once"));
            }
            _ => return Err(format!("unknown fuzz option {flag:?}")),
        }
        index += 2;
    }
    let manifest = manifest.ok_or_else(|| "fuzz command requires --manifest".to_owned())?;
    let repository_root =
        repository_root.ok_or_else(|| "fuzz command requires --repository-root".to_owned())?;
    let output = output.ok_or_else(|| "fuzz command requires --output".to_owned())?;
    Ok((command, manifest, repository_root, output))
}

fn fuzz_report(
    command: &str,
    inventory: &Manifest,
    repository_root: &Path,
) -> Result<JsonValue, FuzzDiagnostic> {
    if command == "smoke" {
        execute_cargo_fuzz_campaigns(inventory, repository_root).map(|(tools, results)| {
            object([
                ("requiredTargetCount", number(31)),
                ("retainedTargetCount", number(5)),
                ("schemaVersion", number(1)),
                ("state", string("passed")),
                ("targetCount", number(36)),
                (
                    "targetResults",
                    JsonValue::Array(results.iter().map(target_result_json).collect()),
                ),
                (
                    "toolReceipt",
                    object([
                        ("cargoExecutableSha256", string(&tools.cargo_sha256)),
                        (
                            "cargoFuzzExecutableSha256",
                            string(&tools.cargo_fuzz_sha256),
                        ),
                        ("cargoFuzzVersion", string("0.13.2")),
                        ("toolchain", string("nightly-2026-07-31")),
                    ]),
                ),
            ])
        })
    } else if command == "check" {
        Ok(object([
            ("requiredTargetCount", number(31)),
            ("retainedTargetCount", number(5)),
            ("schemaVersion", number(1)),
            ("state", string("checked")),
            ("targetCount", number(36)),
        ]))
    } else {
        Err(FuzzDiagnostic::new("fuzz.command.invalid", fuzz_usage()))
    }
}

fn persist_fuzz_result(
    command: &str,
    output: &Path,
    result: Result<JsonValue, FuzzDiagnostic>,
) -> Result<String, String> {
    match result {
        Ok(report) => {
            persist_json(output, &report)?;
            Ok(if command == "smoke" {
                "completed all 36 bounded cargo-fuzz campaigns"
            } else {
                "verified exact fuzz target, source, binary, and corpus parity"
            }
            .to_owned())
        }
        Err(diagnostic) => {
            let report = persist_json(
                output,
                &object([
                    ("diagnosticCode", string(diagnostic.code)),
                    ("diagnosticMessage", string(&diagnostic.message)),
                    ("schemaVersion", number(1)),
                    ("state", string("blocked")),
                ]),
            );
            match report {
                Ok(()) => Err(format!("{}: {}", diagnostic.code, diagnostic.message)),
                Err(report) => Err(format!(
                    "{}: {}; additionally, cannot persist fuzz rejection: {report}",
                    diagnostic.code, diagnostic.message
                )),
            }
        }
    }
}

fn fuzz_usage() -> String {
    "usage: hell-ci fuzz check|smoke --manifest PATH --repository-root PATH --output PATH"
        .to_owned()
}

fn check_manifest(path: &Path, repository_root: &Path) -> Result<Manifest, FuzzDiagnostic> {
    let repository_root = fs::canonicalize(repository_root).map_err(|error| {
        FuzzDiagnostic::new(
            "fuzz.repository.invalid",
            format!("cannot canonicalize fuzz repository root: {error}"),
        )
    })?;
    let bytes = read_regular(path, 4 * 1024 * 1024)?;
    if !bytes.ends_with(b"\n") {
        return Err(FuzzDiagnostic::new(
            "fuzz.manifest.invalid",
            "fuzz manifest lacks its trailing LF",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| FuzzDiagnostic::new("fuzz.manifest.invalid", "fuzz manifest is not UTF-8"))?;
    let manifest = parse_manifest(text)?;
    verify_registry(&manifest)?;
    verify_physical_inventory(&manifest, &repository_root)?;
    Ok(manifest)
}

fn parse_manifest(text: &str) -> Result<Manifest, FuzzDiagnostic> {
    let mut root = String::new();
    let mut target = None::<String>;
    let mut targets = Vec::new();
    for line in text.lines() {
        if line.trim() == "[[target]]" {
            if let Some(table) = target.replace(String::new()) {
                targets.push(parse_target(&table)?);
            }
        } else if line.trim().starts_with('[') {
            return Err(FuzzDiagnostic::new(
                "fuzz.manifest.invalid",
                "fuzz manifest contains an unknown table",
            ));
        } else if let Some(table) = target.as_mut() {
            table.push_str(line);
            table.push('\n');
        } else {
            root.push_str(line);
            root.push('\n');
        }
    }
    if let Some(table) = target {
        targets.push(parse_target(&table)?);
    }
    let mut fields = crate::strict_toml::assignments(&root)
        .map_err(|message| FuzzDiagnostic::new("fuzz.manifest.invalid", message))?;
    require_literal(&mut fields, "schema-version", "1")?;
    require_string(&mut fields, "orchestrator", "hell-ci-fuzz-smoke-v1")?;
    let toolchain = take_string(&mut fields, "toolchain")?;
    let cargo_fuzz = take_string(&mut fields, "cargo-fuzz-version")?;
    let runs = take_positive(&mut fields, "runs-per-target")?;
    let timeout = take_positive(&mut fields, "timeout-seconds")?;
    if toolchain != "nightly-2026-07-31"
        || cargo_fuzz != "0.13.2"
        || runs != 64
        || timeout != 10
        || !fields.is_empty()
    {
        return Err(FuzzDiagnostic::new(
            "fuzz.manifest.invalid",
            "fuzz manifest root authority differs",
        ));
    }
    Ok(Manifest {
        toolchain,
        cargo_fuzz_version: cargo_fuzz,
        runs_per_target: runs,
        timeout_seconds: timeout,
        targets,
    })
}

fn parse_target(table: &str) -> Result<ManifestTarget, FuzzDiagnostic> {
    let mut fields = crate::strict_toml::assignments(table)
        .map_err(|message| FuzzDiagnostic::new("fuzz.manifest.invalid", message))?;
    let target = ManifestTarget {
        id: take_string(&mut fields, "id")?,
        implementation: take_string(&mut fields, "implementation")?,
        class: take_string(&mut fields, "class")?,
        fuzz_directory: PathBuf::from(take_string(&mut fields, "fuzz-directory")?),
        cargo_target: take_string(&mut fields, "cargo-target")?,
        source: PathBuf::from(take_string(&mut fields, "source")?),
        maximum_input_bytes: take_positive(&mut fields, "maximum-input-bytes")?,
        maximum_depth: take_positive(&mut fields, "maximum-depth")?,
        maximum_records: take_positive(&mut fields, "maximum-records")?,
        timeout_seconds: take_positive(&mut fields, "timeout-seconds")?,
        corpus: PathBuf::from(take_string(&mut fields, "corpus")?),
        artifact_directory: PathBuf::from(take_string(&mut fields, "artifact-directory")?),
        engine_arguments: take_string_array(&mut fields, "engine-arguments")?,
        invariant: take_string(&mut fields, "invariant")?,
    };
    if !fields.is_empty() {
        return Err(FuzzDiagnostic::new(
            "fuzz.manifest.invalid",
            format!("fuzz target {:?} has unknown fields", target.id),
        ));
    }
    for path in [
        &target.fuzz_directory,
        &target.source,
        &target.corpus,
        &target.artifact_directory,
    ] {
        require_safe_relative(path)?;
    }
    if target.id != target.cargo_target
        || target.source
            != target
                .fuzz_directory
                .join("fuzz_targets")
                .join(format!("{}.rs", target.cargo_target))
        || target.corpus != target.fuzz_directory.join("corpus").join(&target.id)
        || target.artifact_directory != Path::new("ci-out/fuzz-artifacts").join(&target.id)
        || target.timeout_seconds != 10
        || target.maximum_input_bytes == 0
        || target.maximum_depth == 0
        || target.maximum_records == 0
        || target.invariant.is_empty()
    {
        return Err(FuzzDiagnostic::new(
            "fuzz.manifest.invalid",
            format!(
                "fuzz target {:?} has inconsistent typed bindings",
                target.id
            ),
        ));
    }
    validate_engine_arguments(&target)?;
    Ok(target)
}

fn validate_engine_arguments(target: &ManifestTarget) -> Result<(), FuzzDiagnostic> {
    let [runs, timeout, maximum, artifacts] = target.engine_arguments.as_slice() else {
        return Err(FuzzDiagnostic::new(
            "fuzz.manifest.invalid",
            format!("fuzz target {:?} has an invalid engine argv", target.id),
        ));
    };
    let runs = prefixed_positive(runs, "-runs=")?;
    let timeout = prefixed_positive(timeout, "-timeout=")?;
    let maximum = prefixed_positive(maximum, "-max_len=")?;
    let artifact_path = artifacts
        .strip_prefix("-artifact_prefix=")
        .and_then(|value| value.strip_suffix('/'))
        .ok_or_else(|| {
            FuzzDiagnostic::new(
                "fuzz.manifest.invalid",
                format!("fuzz target {:?} has an invalid artifact prefix", target.id),
            )
        })?;
    if runs != 64
        || timeout != target.timeout_seconds
        || maximum != target.maximum_input_bytes
        || Path::new(artifact_path) != target.artifact_directory
    {
        return Err(FuzzDiagnostic::new(
            "fuzz.manifest.invalid",
            format!(
                "fuzz target {:?} engine argv differs from typed limits",
                target.id
            ),
        ));
    }
    Ok(())
}

fn prefixed_positive(value: &str, prefix: &str) -> Result<u64, FuzzDiagnostic> {
    let raw = value.strip_prefix(prefix).ok_or_else(|| {
        FuzzDiagnostic::new(
            "fuzz.manifest.invalid",
            "fuzz engine argument has the wrong prefix",
        )
    })?;
    let parsed = raw.parse::<u64>().map_err(|_| {
        FuzzDiagnostic::new(
            "fuzz.manifest.invalid",
            "fuzz engine argument is not an integer",
        )
    })?;
    if parsed == 0 || raw != parsed.to_string() {
        return Err(FuzzDiagnostic::new(
            "fuzz.manifest.invalid",
            "fuzz engine argument is not canonical and positive",
        ));
    }
    Ok(parsed)
}

fn verify_registry(manifest: &Manifest) -> Result<(), FuzzDiagnostic> {
    let observed = manifest
        .targets
        .iter()
        .map(|target| target.id.as_str())
        .collect::<Vec<_>>();
    let expected = REQUIRED_TARGETS
        .into_iter()
        .chain(RETAINED_TARGETS)
        .collect::<Vec<_>>();
    if observed != expected {
        return Err(FuzzDiagnostic::new(
            "fuzz.manifest.inventory",
            "fuzz manifest differs from the exact ordered 31 required plus 5 retained targets",
        ));
    }
    for target in &manifest.targets {
        let retained = RETAINED_TARGETS.contains(&target.id.as_str());
        let expected = if retained {
            ("primary", "retained-semantic-regression")
        } else if target.id.starts_with("workflow_") {
            ("workflow-auditor", "workflow-auditor")
        } else if target.id.starts_with("independent_") {
            ("independent", "independent-verifier")
        } else {
            ("primary", "release-authority")
        };
        if (target.implementation.as_str(), target.class.as_str()) != expected {
            return Err(FuzzDiagnostic::new(
                "fuzz.manifest.classification",
                format!(
                    "fuzz target {:?} has the wrong implementation class",
                    target.id
                ),
            ));
        }
    }
    Ok(())
}

fn verify_physical_inventory(
    manifest: &Manifest,
    repository_root: &Path,
) -> Result<(), FuzzDiagnostic> {
    let mut by_directory = BTreeMap::<PathBuf, Vec<&ManifestTarget>>::new();
    for target in &manifest.targets {
        require_regular(&repository_root.join(&target.source), "fuzz.source.missing")?;
        require_nonempty_corpus(
            &repository_root.join(&target.corpus),
            target.maximum_input_bytes,
            target.maximum_records,
        )?;
        by_directory
            .entry(target.fuzz_directory.clone())
            .or_default()
            .push(target);
    }
    for (directory, targets) in by_directory {
        let physical = repository_root.join(&directory);
        require_directory(&physical, "fuzz.directory.missing")?;
        let cargo_bins = parse_cargo_bins(&physical.join("Cargo.toml"))?;
        let expected_bins = targets
            .iter()
            .map(|target| {
                (
                    target.cargo_target.clone(),
                    relative_to(&directory, &target.source),
                )
            })
            .collect::<BTreeMap<_, _>>();
        if cargo_bins != expected_bins {
            return Err(FuzzDiagnostic::new(
                "fuzz.cargo-bin.inventory",
                format!(
                    "fuzz Cargo target inventory differs under {}",
                    directory.display()
                ),
            ));
        }
        let source_root = physical.join("fuzz_targets");
        let observed_sources = directory_names_with_suffix(&source_root, ".rs")?;
        let expected_sources = targets
            .iter()
            .map(|target| format!("{}.rs", target.cargo_target))
            .collect::<BTreeSet<_>>();
        if observed_sources != expected_sources {
            return Err(FuzzDiagnostic::new(
                "fuzz.source.inventory",
                format!(
                    "fuzz source inventory differs under {}",
                    directory.display()
                ),
            ));
        }
        let corpus_root = physical.join("corpus");
        let observed_corpora = directory_names(&corpus_root, "fuzz.corpus.invalid")?;
        let mut expected_corpora = targets
            .iter()
            .map(|target| target.id.clone())
            .collect::<BTreeSet<_>>();
        if directory == Path::new("crates/hell-ci/fuzz") {
            expected_corpora.extend(PRESERVED_REGRESSION_CORPORA.into_iter().map(str::to_owned));
        }
        if observed_corpora != expected_corpora {
            return Err(FuzzDiagnostic::new(
                "fuzz.corpus.inventory",
                format!(
                    "fuzz corpus inventory differs under {}",
                    directory.display()
                ),
            ));
        }
    }
    Ok(())
}

fn execute_cargo_fuzz_campaigns(
    manifest: &Manifest,
    repository_root: &Path,
) -> Result<(FuzzToolReceipt, Vec<TargetResult>), FuzzDiagnostic> {
    if manifest.toolchain != "nightly-2026-07-31"
        || manifest.cargo_fuzz_version != "0.13.2"
        || manifest.runs_per_target != 64
        || manifest.timeout_seconds != 10
    {
        return Err(FuzzDiagnostic::new(
            "fuzz.manifest.invalid",
            "fuzz execution authority differs from the pinned campaign",
        ));
    }
    let tools = resolve_fuzz_tools()?;
    verify_cargo_fuzz_version(repository_root, &tools)?;
    let source_snapshots = manifest
        .targets
        .iter()
        .map(|target| {
            corpus_snapshot(&repository_root.join(&target.corpus), target)
                .map(|snapshot| (target.id.clone(), snapshot))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let staged_corpora = stage_corpora(manifest, repository_root, &source_snapshots)?;
    let artifact_root = repository_root.join("ci-out").join("fuzz-artifacts");
    if artifact_root.exists() {
        return Err(FuzzDiagnostic::new(
            "fuzz.artifact.invalid",
            "fuzz artifact root already exists",
        ));
    }
    fs::create_dir(&artifact_root).map_err(|error| {
        FuzzDiagnostic::new(
            "fuzz.artifact.invalid",
            format!("cannot create fuzz artifact root: {error}"),
        )
    })?;
    let results = execute_campaigns(
        manifest,
        repository_root,
        &tools,
        &source_snapshots,
        &staged_corpora,
    )?;
    verify_fuzz_tools_unchanged(&tools)?;
    Ok((tools, results))
}

fn execute_campaigns(
    manifest: &Manifest,
    repository_root: &Path,
    tools: &FuzzToolReceipt,
    source_snapshots: &BTreeMap<String, CorpusSnapshot>,
    staged_corpora: &BTreeMap<String, PathBuf>,
) -> Result<Vec<TargetResult>, FuzzDiagnostic> {
    let mut results = Vec::with_capacity(manifest.targets.len());
    for target in &manifest.targets {
        let (command_timeout, staged_corpus, arguments) =
            prepare_campaign(manifest, repository_root, target, staged_corpora)?;
        #[cfg(unix)]
        let command =
            CommandSpec::trusted_standard(Duration::from_secs(command_timeout), &tools.cargo_fuzz)
                .map_err(|message| FuzzDiagnostic::new("fuzz.tool.identity", message))?
                .arguments(arguments)
                .current_directory(repository_root);
        #[cfg(not(unix))]
        let command =
            CommandSpec::trusted_cargo(Duration::from_secs(command_timeout), &tools.cargo)
                .arguments(
                    [OsString::from("+nightly-2026-07-31")]
                        .into_iter()
                        .chain(arguments),
                )
                .current_directory(repository_root);
        let execution = command.run().map_err(|error| {
            FuzzDiagnostic::new(
                "fuzz.target.spawn",
                format!(
                    "fuzz target {:?} could not execute at phase {}: {}",
                    target.id,
                    format_args!("{:?}", error.phase()),
                    error.message()
                ),
            )
        });
        let source_verification = verify_source_corpus_unchanged(
            target,
            repository_root,
            source_snapshots.get(&target.id).ok_or_else(|| {
                FuzzDiagnostic::new(
                    "fuzz.corpus.staging",
                    "source fuzz corpus binding is missing",
                )
            })?,
        );
        let result = match (execution, source_verification) {
            (Ok(result), Ok(())) => result,
            (Err(primary), Ok(())) => return Err(primary),
            (Ok(_), Err(source)) => return Err(source),
            (Err(primary), Err(source)) => {
                return Err(FuzzDiagnostic::new(
                    primary.code,
                    format!(
                        "{}; additionally, source corpus verification failed: {}",
                        primary.message, source.message
                    ),
                ));
            }
        };
        if result.timed_out || !result.status.success() {
            return Err(FuzzDiagnostic::new(
                if result.timed_out {
                    "fuzz.target.timeout"
                } else {
                    "fuzz.target.failed"
                },
                format!(
                    "fuzz target {:?} failed: status={:?}, timedOut={}, stdoutSha256={}, stderrSha256={}, stderr={:?}",
                    target.id,
                    result.status,
                    result.timed_out,
                    result.stdout_sha256.hex(),
                    result.stderr_sha256.hex(),
                    String::from_utf8_lossy(&result.stderr),
                ),
            ));
        }
        results.push(TargetResult {
            id: target.id.clone(),
            duration_millis: u64::try_from(result.duration.as_millis()).unwrap_or(u64::MAX),
            source_corpus_sha256: source_snapshots[&target.id].sha256.clone(),
            stdout_sha256: result.stdout_sha256.hex(),
            stderr_sha256: result.stderr_sha256.hex(),
            staged_corpus_sha256: corpus_snapshot(&staged_corpus, target)?.sha256,
        });
    }
    Ok(results)
}

fn prepare_campaign(
    manifest: &Manifest,
    repository_root: &Path,
    target: &ManifestTarget,
    staged_corpora: &BTreeMap<String, PathBuf>,
) -> Result<(u64, PathBuf, Vec<OsString>), FuzzDiagnostic> {
    let artifact_directory = repository_root.join(&target.artifact_directory);
    fs::create_dir(&artifact_directory).map_err(|error| {
        FuzzDiagnostic::new(
            "fuzz.artifact.invalid",
            format!("cannot create fuzz artifact directory: {error}"),
        )
    })?;
    require_directory(&artifact_directory, "fuzz.artifact.invalid")?;
    let command_timeout =
        target
            .timeout_seconds
            .checked_mul(manifest.runs_per_target.checked_add(1).ok_or_else(|| {
                FuzzDiagnostic::new("fuzz.limit.invalid", "fuzz run count overflow")
            })?)
            .ok_or_else(|| {
                FuzzDiagnostic::new("fuzz.limit.invalid", "fuzz command timeout overflow")
            })?;
    let staged_corpus = staged_corpora.get(&target.id).cloned().ok_or_else(|| {
        FuzzDiagnostic::new(
            "fuzz.corpus.staging",
            "staged fuzz corpus binding is missing",
        )
    })?;
    let arguments = [
        OsString::from("fuzz"),
        OsString::from("run"),
        OsString::from("--fuzz-dir"),
        target.fuzz_directory.clone().into_os_string(),
        OsString::from(&target.cargo_target),
        staged_corpus.clone().into_os_string(),
        OsString::from("--"),
    ]
    .into_iter()
    .chain(target.engine_arguments.iter().map(OsString::from))
    .collect();
    Ok((command_timeout, staged_corpus, arguments))
}

fn verify_cargo_fuzz_version(
    repository_root: &Path,
    tools: &FuzzToolReceipt,
) -> Result<(), FuzzDiagnostic> {
    #[cfg(unix)]
    let command = CommandSpec::trusted_standard(Duration::from_secs(30), &tools.cargo_fuzz)
        .map_err(|message| FuzzDiagnostic::new("fuzz.tool.identity", message))?
        .argument("--version");
    #[cfg(not(unix))]
    let command = CommandSpec::trusted_cargo(Duration::from_secs(30), &tools.cargo).arguments([
        OsString::from("+nightly-2026-07-31"),
        OsString::from("fuzz"),
        OsString::from("--version"),
    ]);
    let result = command
        .current_directory(repository_root)
        .run()
        .map_err(|error| {
            FuzzDiagnostic::new(
                "fuzz.tool.spawn",
                format!("cannot execute pinned cargo-fuzz: {}", error.message()),
            )
        })?;
    if result.timed_out
        || !result.status.success()
        || result.stdout != b"cargo-fuzz 0.13.2\n"
        || result.stdout_truncated
        || result.stderr_truncated
    {
        return Err(FuzzDiagnostic::new(
            "fuzz.tool.identity",
            format!(
                "cargo-fuzz identity differs: status={:?}, timedOut={}, stdoutSha256={}, stderrSha256={}",
                result.status,
                result.timed_out,
                result.stdout_sha256.hex(),
                result.stderr_sha256.hex(),
            ),
        ));
    }
    Ok(())
}

fn resolve_fuzz_tools() -> Result<FuzzToolReceipt, FuzzDiagnostic> {
    let cargo = resolve_cargo_executable()
        .map_err(|message| FuzzDiagnostic::new("fuzz.tool.resolve", message))?;
    let cargo_sha256 = hell_testkit::sha256_file(cargo.canonical_identity())
        .map_err(|error| {
            FuzzDiagnostic::new(
                "fuzz.tool.identity",
                format!("cannot hash resolved Cargo executable: {error}"),
            )
        })?
        .hex();
    #[cfg(unix)]
    {
        let cargo_fuzz = resolve_standard_path_executable(std::ffi::OsStr::new("cargo-fuzz"))
            .map_err(|message| FuzzDiagnostic::new("fuzz.tool.resolve", message))?;
        let cargo_fuzz_sha256 = hell_testkit::sha256_file(cargo_fuzz.canonical_identity())
            .map_err(|error| {
                FuzzDiagnostic::new(
                    "fuzz.tool.identity",
                    format!("cannot hash resolved cargo-fuzz executable: {error}"),
                )
            })?
            .hex();
        Ok(FuzzToolReceipt {
            cargo,
            cargo_sha256,
            cargo_fuzz,
            cargo_fuzz_sha256,
        })
    }
    #[cfg(not(unix))]
    {
        Ok(FuzzToolReceipt {
            cargo,
            cargo_sha256,
            cargo_fuzz_sha256: "unavailable-on-this-platform".to_owned(),
        })
    }
}

fn verify_fuzz_tools_unchanged(tools: &FuzzToolReceipt) -> Result<(), FuzzDiagnostic> {
    let cargo = hell_testkit::sha256_file(tools.cargo.canonical_identity())
        .map_err(|error| {
            FuzzDiagnostic::new(
                "fuzz.tool.identity",
                format!("cannot rehash resolved Cargo executable: {error}"),
            )
        })?
        .hex();
    if cargo != tools.cargo_sha256 {
        return Err(FuzzDiagnostic::new(
            "fuzz.tool.identity",
            "resolved Cargo executable changed during fuzzing",
        ));
    }
    #[cfg(unix)]
    {
        tools
            .cargo_fuzz
            .revalidate()
            .map_err(|message| FuzzDiagnostic::new("fuzz.tool.identity", message))?;
        let cargo_fuzz = hell_testkit::sha256_file(tools.cargo_fuzz.canonical_identity())
            .map_err(|error| {
                FuzzDiagnostic::new(
                    "fuzz.tool.identity",
                    format!("cannot rehash resolved cargo-fuzz executable: {error}"),
                )
            })?
            .hex();
        if cargo_fuzz != tools.cargo_fuzz_sha256 {
            return Err(FuzzDiagnostic::new(
                "fuzz.tool.identity",
                "resolved cargo-fuzz executable changed during fuzzing",
            ));
        }
    }
    Ok(())
}

fn target_result_json(result: &TargetResult) -> JsonValue {
    object([
        ("durationMillis", number(result.duration_millis)),
        ("id", string(&result.id)),
        ("sourceCorpusSha256", string(&result.source_corpus_sha256)),
        ("state", string("passed")),
        ("stderrSha256", string(&result.stderr_sha256)),
        ("stagedCorpusSha256", string(&result.staged_corpus_sha256)),
        ("stdoutSha256", string(&result.stdout_sha256)),
    ])
}

fn stage_corpora(
    manifest: &Manifest,
    repository_root: &Path,
    source_snapshots: &BTreeMap<String, CorpusSnapshot>,
) -> Result<BTreeMap<String, PathBuf>, FuzzDiagnostic> {
    let staging_root = repository_root.join("ci-out").join("fuzz-corpora");
    if staging_root.exists() {
        return Err(FuzzDiagnostic::new(
            "fuzz.corpus.staging",
            "fuzz corpus staging root already exists",
        ));
    }
    fs::create_dir_all(&staging_root).map_err(|error| {
        FuzzDiagnostic::new(
            "fuzz.corpus.staging",
            format!("cannot create fuzz corpus staging root: {error}"),
        )
    })?;
    let mut staged = BTreeMap::new();
    for target in &manifest.targets {
        let source = repository_root.join(&target.corpus);
        let destination = staging_root.join(&target.id);
        fs::create_dir(&destination).map_err(|error| {
            FuzzDiagnostic::new(
                "fuzz.corpus.staging",
                format!("cannot create staged fuzz corpus: {error}"),
            )
        })?;
        let snapshot = source_snapshots.get(&target.id).ok_or_else(|| {
            FuzzDiagnostic::new(
                "fuzz.corpus.staging",
                "source fuzz corpus snapshot is missing",
            )
        })?;
        for name in snapshot.files.keys() {
            let source_file = source.join(name);
            let destination_file = destination.join(name);
            fs::copy(&source_file, &destination_file).map_err(|error| {
                FuzzDiagnostic::new(
                    "fuzz.corpus.staging",
                    format!("cannot copy fuzz corpus entry: {error}"),
                )
            })?;
        }
        if corpus_snapshot(&destination, target)? != *snapshot {
            return Err(FuzzDiagnostic::new(
                "fuzz.corpus.staging",
                format!("staged fuzz corpus {:?} differs from its source", target.id),
            ));
        }
        staged.insert(target.id.clone(), destination);
    }
    Ok(staged)
}

fn verify_source_corpus_unchanged(
    target: &ManifestTarget,
    repository_root: &Path,
    expected: &CorpusSnapshot,
) -> Result<(), FuzzDiagnostic> {
    if &corpus_snapshot(&repository_root.join(&target.corpus), target)? != expected {
        return Err(FuzzDiagnostic::new(
            "fuzz.corpus.source-mutated",
            format!(
                "source fuzz corpus {:?} changed during its campaign",
                target.id
            ),
        ));
    }
    Ok(())
}

fn corpus_snapshot(path: &Path, target: &ManifestTarget) -> Result<CorpusSnapshot, FuzzDiagnostic> {
    require_nonempty_corpus(path, target.maximum_input_bytes, target.maximum_records)?;
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(path).map_err(|error| {
        FuzzDiagnostic::new(
            "fuzz.corpus.invalid",
            format!("cannot read corpus: {error}"),
        )
    })? {
        let entry = entry.map_err(|error| {
            FuzzDiagnostic::new(
                "fuzz.corpus.invalid",
                format!("cannot inspect corpus entry: {error}"),
            )
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            FuzzDiagnostic::new("fuzz.corpus.invalid", "fuzz corpus name is not UTF-8")
        })?;
        let bytes = read_regular(
            &entry.path(),
            usize::try_from(target.maximum_input_bytes).unwrap_or(usize::MAX),
        )?;
        files.insert(
            name,
            (
                u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                hell_testkit::sha256_bytes(&bytes).hex(),
            ),
        );
    }
    let value = JsonValue::Object(
        files
            .iter()
            .map(|(name, (size, digest))| {
                (
                    name.clone(),
                    object([("sha256", string(digest)), ("size", number(*size))]),
                )
            })
            .collect(),
    );
    let sha256 = hell_testkit::sha256_bytes(
        &json::canonical_json_bytes(&value)
            .map_err(|message| FuzzDiagnostic::new("fuzz.corpus.invalid", message))?,
    )
    .hex();
    Ok(CorpusSnapshot { files, sha256 })
}

fn parse_cargo_bins(path: &Path) -> Result<BTreeMap<String, PathBuf>, FuzzDiagnostic> {
    let bytes = read_regular(path, 1024 * 1024)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        FuzzDiagnostic::new("fuzz.cargo-bin.invalid", "fuzz Cargo.toml is not UTF-8")
    })?;
    let mut bins = BTreeMap::new();
    let mut table = None::<String>;
    let flush = |table: Option<String>, bins: &mut BTreeMap<String, PathBuf>| {
        let Some(table) = table else {
            return Ok(());
        };
        let mut fields = crate::strict_toml::assignments(&table)
            .map_err(|message| FuzzDiagnostic::new("fuzz.cargo-bin.invalid", message))?;
        let name = take_string(&mut fields, "name")?;
        let path = PathBuf::from(take_string(&mut fields, "path")?);
        for field in ["test", "doc", "bench"] {
            require_literal(&mut fields, field, "false")?;
        }
        if !fields.is_empty() || bins.insert(name, path).is_some() {
            return Err(FuzzDiagnostic::new(
                "fuzz.cargo-bin.invalid",
                "fuzz Cargo.toml has an invalid or duplicate bin table",
            ));
        }
        Ok(())
    };
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "[[bin]]" {
            flush(table.take(), &mut bins)?;
            table = Some(String::new());
        } else if trimmed.starts_with('[') {
            flush(table.take(), &mut bins)?;
        } else if let Some(table) = table.as_mut() {
            table.push_str(line);
            table.push('\n');
        }
    }
    flush(table, &mut bins)?;
    Ok(bins)
}

fn require_nonempty_corpus(
    path: &Path,
    maximum_input_bytes: u64,
    maximum_records: u64,
) -> Result<(), FuzzDiagnostic> {
    require_directory(path, "fuzz.corpus.missing")?;
    let mut count = 0_u64;
    for entry in fs::read_dir(path).map_err(|error| {
        FuzzDiagnostic::new(
            "fuzz.corpus.invalid",
            format!("cannot read corpus: {error}"),
        )
    })? {
        let entry = entry.map_err(|error| {
            FuzzDiagnostic::new(
                "fuzz.corpus.invalid",
                format!("cannot inspect corpus: {error}"),
            )
        })?;
        let kind = entry.file_type().map_err(|error| {
            FuzzDiagnostic::new(
                "fuzz.corpus.invalid",
                format!("cannot inspect corpus entry type: {error}"),
            )
        })?;
        if !kind.is_file() || kind.is_symlink() {
            return Err(FuzzDiagnostic::new(
                "fuzz.corpus.invalid",
                "fuzz corpus contains a non-regular entry",
            ));
        }
        let bytes = entry.metadata().map_err(|error| {
            FuzzDiagnostic::new(
                "fuzz.corpus.invalid",
                format!("cannot inspect fuzz corpus entry size: {error}"),
            )
        })?;
        if bytes.len() > maximum_input_bytes {
            return Err(FuzzDiagnostic::new(
                "fuzz.corpus.oversize",
                "fuzz corpus entry exceeds its declared maximum input bytes",
            ));
        }
        count = count.checked_add(1).ok_or_else(|| {
            FuzzDiagnostic::new("fuzz.corpus.invalid", "fuzz corpus entry count overflow")
        })?;
    }
    if count == 0 {
        return Err(FuzzDiagnostic::new(
            "fuzz.corpus.missing",
            "fuzz corpus is empty",
        ));
    }
    if count > maximum_records {
        return Err(FuzzDiagnostic::new(
            "fuzz.corpus.oversize",
            "fuzz corpus entry count exceeds its declared record bound",
        ));
    }
    Ok(())
}

fn directory_names(path: &Path, code: &'static str) -> Result<BTreeSet<String>, FuzzDiagnostic> {
    require_directory(path, code)?;
    fs::read_dir(path)
        .map_err(|error| {
            FuzzDiagnostic::new(
                code,
                format!("cannot enumerate {}: {error}", path.display()),
            )
        })?
        .map(|entry| {
            let entry = entry.map_err(|error| {
                FuzzDiagnostic::new(code, format!("cannot inspect {}: {error}", path.display()))
            })?;
            let kind = entry.file_type().map_err(|error| {
                FuzzDiagnostic::new(code, format!("cannot inspect corpus directory: {error}"))
            })?;
            if !kind.is_dir() || kind.is_symlink() {
                return Err(FuzzDiagnostic::new(
                    code,
                    "fuzz corpus root contains a non-directory or symlink",
                ));
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| FuzzDiagnostic::new(code, "fuzz corpus directory name is not UTF-8"))
        })
        .collect()
}

fn directory_names_with_suffix(
    path: &Path,
    suffix: &str,
) -> Result<BTreeSet<String>, FuzzDiagnostic> {
    require_directory(path, "fuzz.source.missing")?;
    fs::read_dir(path)
        .map_err(|error| {
            FuzzDiagnostic::new(
                "fuzz.source.invalid",
                format!("cannot enumerate fuzz sources: {error}"),
            )
        })?
        .map(|entry| {
            let entry = entry.map_err(|error| {
                FuzzDiagnostic::new(
                    "fuzz.source.invalid",
                    format!("cannot inspect fuzz source: {error}"),
                )
            })?;
            let kind = entry.file_type().map_err(|error| {
                FuzzDiagnostic::new(
                    "fuzz.source.invalid",
                    format!("cannot inspect fuzz source type: {error}"),
                )
            })?;
            let name = entry.file_name().into_string().map_err(|_| {
                FuzzDiagnostic::new("fuzz.source.invalid", "fuzz source name is not UTF-8")
            })?;
            if !kind.is_file() || kind.is_symlink() || !name.ends_with(suffix) {
                return Err(FuzzDiagnostic::new(
                    "fuzz.source.invalid",
                    "fuzz source directory contains an unsupported entry",
                ));
            }
            Ok(name)
        })
        .collect()
}

fn relative_to(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

fn require_safe_relative(path: &Path) -> Result<(), FuzzDiagnostic> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(FuzzDiagnostic::new(
            "fuzz.manifest.path",
            format!("fuzz manifest path is unsafe: {}", path.display()),
        ));
    }
    Ok(())
}

fn require_regular(path: &Path, code: &'static str) -> Result<(), FuzzDiagnostic> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        FuzzDiagnostic::new(code, format!("cannot inspect {}: {error}", path.display()))
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(FuzzDiagnostic::new(
            code,
            format!("{} is not a regular file", path.display()),
        ));
    }
    Ok(())
}

fn require_directory(path: &Path, code: &'static str) -> Result<(), FuzzDiagnostic> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        FuzzDiagnostic::new(code, format!("cannot inspect {}: {error}", path.display()))
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(FuzzDiagnostic::new(
            code,
            format!("{} is not a real directory", path.display()),
        ));
    }
    Ok(())
}

fn read_regular(path: &Path, maximum: usize) -> Result<Vec<u8>, FuzzDiagnostic> {
    require_regular(path, "fuzz.input.missing")?;
    let metadata = fs::metadata(path).map_err(|error| {
        FuzzDiagnostic::new(
            "fuzz.input.invalid",
            format!("cannot inspect {}: {error}", path.display()),
        )
    })?;
    if metadata.len() > u64::try_from(maximum).unwrap_or(u64::MAX) {
        return Err(FuzzDiagnostic::new(
            "fuzz.input.limit",
            format!("{} exceeds its fuzz input bound", path.display()),
        ));
    }
    fs::read(path).map_err(|error| {
        FuzzDiagnostic::new(
            "fuzz.input.invalid",
            format!("cannot read {}: {error}", path.display()),
        )
    })
}

fn take_string(
    fields: &mut BTreeMap<String, String>,
    name: &str,
) -> Result<String, FuzzDiagnostic> {
    let value = crate::strict_toml::take(fields, name)
        .and_then(|value| crate::strict_toml::string(&value))
        .map_err(|message| FuzzDiagnostic::new("fuzz.manifest.invalid", message))?;
    if value.is_empty() {
        return Err(FuzzDiagnostic::new(
            "fuzz.manifest.invalid",
            format!("fuzz manifest field {name} is empty"),
        ));
    }
    Ok(value)
}

fn take_string_array(
    fields: &mut BTreeMap<String, String>,
    name: &str,
) -> Result<Vec<String>, FuzzDiagnostic> {
    let raw = crate::strict_toml::take(fields, name)
        .map_err(|message| FuzzDiagnostic::new("fuzz.manifest.invalid", message))?;
    let values = crate::strict_toml::string_array(&raw)
        .map_err(|message| FuzzDiagnostic::new("fuzz.manifest.invalid", message))?;
    if values.is_empty() || values.iter().any(String::is_empty) {
        return Err(FuzzDiagnostic::new(
            "fuzz.manifest.invalid",
            format!("fuzz manifest field {name} is empty"),
        ));
    }
    Ok(values)
}

fn take_positive(fields: &mut BTreeMap<String, String>, name: &str) -> Result<u64, FuzzDiagnostic> {
    let raw = crate::strict_toml::take(fields, name)
        .map_err(|message| FuzzDiagnostic::new("fuzz.manifest.invalid", message))?;
    let value = raw.parse::<u64>().map_err(|_| {
        FuzzDiagnostic::new(
            "fuzz.manifest.invalid",
            format!("fuzz manifest field {name} is not an unsigned integer"),
        )
    })?;
    if value == 0 || raw != value.to_string() {
        return Err(FuzzDiagnostic::new(
            "fuzz.manifest.invalid",
            format!("fuzz manifest field {name} is not canonical and positive"),
        ));
    }
    Ok(value)
}

fn require_literal(
    fields: &mut BTreeMap<String, String>,
    name: &str,
    expected: &str,
) -> Result<(), FuzzDiagnostic> {
    let observed = crate::strict_toml::take(fields, name)
        .map_err(|message| FuzzDiagnostic::new("fuzz.manifest.invalid", message))?;
    if observed != expected {
        return Err(FuzzDiagnostic::new(
            "fuzz.manifest.invalid",
            format!("fuzz manifest field {name} differs"),
        ));
    }
    Ok(())
}

fn require_string(
    fields: &mut BTreeMap<String, String>,
    name: &str,
    expected: &str,
) -> Result<(), FuzzDiagnostic> {
    if take_string(fields, name)? != expected {
        return Err(FuzzDiagnostic::new(
            "fuzz.manifest.invalid",
            format!("fuzz manifest field {name} differs"),
        ));
    }
    Ok(())
}

fn persist_json(path: &Path, value: &JsonValue) -> Result<(), String> {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let bytes = json::canonical_json_bytes(value)?;
    let parent = path
        .parent()
        .ok_or_else(|| "fuzz report has no parent".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create fuzz report parent: {error}"))?;
    let name = path
        .file_name()
        .ok_or_else(|| "fuzz report has no filename".to_owned())?;
    let mut temporary_name = name.to_os_string();
    temporary_name.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let temporary = path.with_file_name(temporary_name);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| format!("cannot create fuzz report staging: {error}"))?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _cleanup = fs::remove_file(&temporary);
        return Err(format!("cannot write fuzz report staging: {error}"));
    }
    drop(file);
    if let Err(error) = fs::hard_link(&temporary, path) {
        let _cleanup = fs::remove_file(&temporary);
        return Err(format!("cannot install fuzz report: {error}"));
    }
    fs::remove_file(&temporary)
        .map_err(|error| format!("cannot remove fuzz report staging: {error}"))
}

fn object<const N: usize>(entries: [(&str, JsonValue); N]) -> JsonValue {
    JsonValue::Object(
        entries
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

const fn number(value: u64) -> JsonValue {
    JsonValue::Number(value)
}

fn string(value: &str) -> JsonValue {
    JsonValue::String(value.to_owned())
}
