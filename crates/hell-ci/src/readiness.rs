use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::command::CommandSpec;
use crate::json::{JsonValue, canonical_json_bytes, json_member, require_exact_json_keys};
use crate::process_environment::{ProcessEnvironment, StandardVariable};
use crate::release::manifest::{read_json, read_regular, write_atomic, write_json};
use crate::release::schema::{
    PLATFORMS, ReleasePlan, ReleasePlatform, Resolution, number, object, require_digest,
    require_sha, string, text,
};

const READINESS_VERSION: &str = "0.0.0-readiness";
const READINESS_TAG: &str = "technical-readiness";

#[derive(Default)]
struct Options {
    output: Option<PathBuf>,
    repository_root: Option<PathBuf>,
    oracle_source: Option<PathBuf>,
    plan: Option<PathBuf>,
    conformance_plan: Option<PathBuf>,
    input: Option<PathBuf>,
    state_root: Option<PathBuf>,
    platform: Option<ReleasePlatform>,
    job: Option<String>,
    state: Option<String>,
    artifact_id: Option<u64>,
    artifact_digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReadinessPlan {
    candidate_sha: String,
    workflow_sha: String,
    source_date_epoch: u64,
    evaluation_instant: String,
    source_inventory_sha256: String,
    build_inputs_sha256: String,
    policy_sha256: String,
    trusted_conformance_inputs_sha256: String,
    conformance_plan_sha256: String,
    conformance_standard: String,
    execution_plan_sha256: String,
    self_sha256: String,
}

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments
        .first()
        .is_some_and(|argument| argument == "readiness")
}

pub(crate) fn run(arguments: &[OsString]) -> Result<String, String> {
    let command = arguments
        .get(1)
        .and_then(|value| value.to_str())
        .ok_or_else(usage)?;
    let options = parse_options(&arguments[2..])?;
    match command {
        "plan" => {
            let output = required(options.output, "--output")?;
            create_plan(
                required(options.repository_root, "--repository-root")?,
                &output,
            )
        }
        "platform" => {
            let plan = required(options.plan, "--plan")?;
            platform(
                required(options.platform, "--platform")?,
                &plan,
                required(options.conformance_plan, "--conformance-plan")?,
                required(options.repository_root, "--repository-root")?,
                required(options.oracle_source, "--oracle-source")?,
                required(options.output, "--output")?,
            )
        }
        "verify" => {
            let plan = required(options.plan, "--plan")?;
            let output = required(options.output, "--output")?;
            verify(
                &plan,
                required(options.conformance_plan, "--conformance-plan")?,
                required(options.input, "--input")?,
                &output,
            )
        }
        "record-job-state" => {
            let job = required(options.job, "--job")?;
            let state = required(options.state, "--state")?;
            let output = required(options.output, "--output")?;
            record_job_state(
                &job,
                &state,
                options.artifact_id,
                options.artifact_digest.as_deref(),
                &output,
            )
        }
        "summarize" => {
            let state_root = required(options.state_root, "--state-root")?;
            let input = required(options.input, "--input")?;
            let output = required(options.output, "--output")?;
            summarize(&state_root, &input, &output)
        }
        _ => Err(usage()),
    }
}

fn create_plan(root: PathBuf, output: &Path) -> Result<String, String> {
    if output.exists() {
        return Err("readiness plan output already exists".to_owned());
    }
    let root = fs::canonicalize(root)
        .map_err(|error| format!("cannot canonicalize readiness candidate root: {error}"))?;
    let candidate_sha = git_output(&root, ["rev-parse", "HEAD"])?;
    require_sha(&candidate_sha, "readiness candidate SHA")?;
    require_clean_checkout(&root)?;
    let source_date_epoch = git_output(&root, ["show", "-s", "--format=%ct", "HEAD"])?
        .parse::<u64>()
        .map_err(|_| "readiness candidate timestamp is invalid".to_owned())?;
    let evaluation_instant = current_evaluation_instant()?;

    let automation_root = readiness_automation_root()?;
    require_clean_checkout(&automation_root)?;
    let workflow_sha = git_output(&automation_root, ["rev-parse", "HEAD"])?;
    require_sha(&workflow_sha, "readiness workflow SHA")?;
    if workflow_sha != candidate_sha {
        return Err("readiness automation SHA differs from candidate SHA".to_owned());
    }

    let source_inventory = crate::release::plan::source_inventory(&root)?;
    let source_inventory_bytes = canonical_json_bytes(&source_inventory)?;
    let source_inventory_sha256 = hell_testkit::sha256_bytes(&source_inventory_bytes).hex();
    let trusted_inputs =
        crate::conformance::build_trusted_inputs(&automation_root, &root, &workflow_sha)?;
    let exemptions = crate::conformance::parse_release_exemptions(&read_regular(
        &automation_root.join(".github/release/conformance-exemptions.toml"),
    )?)?;
    let conformance_plan = crate::conformance::build_release_conformance_plan(
        &candidate_sha,
        &workflow_sha,
        &evaluation_instant,
        &trusted_inputs.aggregate_sha256,
        &source_inventory_sha256,
        exemptions,
    )?;
    let policy_sha256 = hell_testkit::sha256_file(&root.join("release-policy.toml"))
        .map_err(|error| format!("cannot hash readiness policy: {error}"))?
        .hex();
    let mut plan = ReadinessPlan {
        candidate_sha,
        workflow_sha,
        source_date_epoch,
        evaluation_instant,
        source_inventory_sha256,
        build_inputs_sha256: String::new(),
        policy_sha256,
        trusted_conformance_inputs_sha256: trusted_inputs.aggregate_sha256,
        conformance_plan_sha256: conformance_plan.plan_sha256.clone(),
        conformance_standard: crate::conformance::RELEASE_STANDARD.to_owned(),
        execution_plan_sha256: String::new(),
        self_sha256: String::new(),
    };
    plan.build_inputs_sha256 = plan.expected_build_inputs_sha256()?;
    plan.execution_plan_sha256 = execution_plan(&plan)?.plan_sha256;
    plan.self_sha256 =
        hell_testkit::sha256_bytes(&canonical_json_bytes(&plan.json_without_digest())?).hex();
    plan.validate()?;

    fs::create_dir(output)
        .map_err(|error| format!("cannot create exact readiness plan directory: {error}"))?;
    write_json(&output.join("readiness-plan.json"), &plan.json())?;
    write_json(
        &output.join("conformance-plan.json"),
        &conformance_plan.json(),
    )?;
    write_json(
        &output.join("trusted-conformance-inputs.json"),
        &trusted_inputs.manifest,
    )?;
    write_atomic(
        &output.join("source-inventory.json"),
        &source_inventory_bytes,
    )?;
    require_exact_plan_inventory(output)?;
    validate_conformance_binding(&plan, &output.join("conformance-plan.json"))?;
    append_outputs(&plan)?;
    Ok(format!(
        "planned technical readiness for {}",
        plan.candidate_sha
    ))
}

fn platform(
    platform: ReleasePlatform,
    plan_path: &Path,
    conformance_plan_path: PathBuf,
    root: PathBuf,
    oracle_source: PathBuf,
    output: PathBuf,
) -> Result<String, String> {
    let plan = ReadinessPlan::parse(&read_json(plan_path)?)?;
    validate_conformance_binding(&plan, &conformance_plan_path)?;
    let execution_path = transient_execution_plan(&output, &plan);
    write_json(&execution_path, &execution_plan(&plan)?.json())?;
    let result = crate::release::platform::run(
        platform,
        execution_path.clone(),
        conformance_plan_path,
        root,
        oracle_source,
        output,
    );
    remove_transient(&execution_path, result)
}

fn verify(
    plan_path: &Path,
    conformance_plan_path: PathBuf,
    input: PathBuf,
    output: &Path,
) -> Result<String, String> {
    if output.exists() {
        return Err("readiness verification output already exists".to_owned());
    }
    let plan = ReadinessPlan::parse(&read_json(plan_path)?)?;
    validate_conformance_binding(&plan, &conformance_plan_path)?;
    fs::create_dir(output)
        .map_err(|error| format!("cannot create readiness verification output: {error}"))?;
    let execution_path = output.join(".execution-plan.json");
    let report_path = output.join("conformance-report.json");
    let bundle_path = output.join(".technical-bundle");
    write_json(&execution_path, &execution_plan(&plan)?.json())?;
    let result = crate::release::assemble::run_readiness(
        execution_path.clone(),
        conformance_plan_path,
        input,
        bundle_path.clone(),
        report_path,
    );
    let result = remove_transient(&execution_path, result);
    match result {
        Ok(_) => {
            fs::remove_dir_all(&bundle_path)
                .map_err(|error| format!("cannot remove transient readiness bundle: {error}"))?;
            write_json(
                &output.join("readiness-result.json"),
                &object([
                    ("candidateSha", string(&plan.candidate_sha)),
                    (
                        "conformancePlanSha256",
                        string(&plan.conformance_plan_sha256),
                    ),
                    ("readinessPlanSha256", string(&plan.self_sha256)),
                    ("schemaVersion", number(1)),
                    ("state", string("technically-release-eligible")),
                ]),
            )?;
            Ok("independently verified technical release eligibility".to_owned())
        }
        Err(error) => Err(format!("technical release readiness blocked: {error}")),
    }
}

const READINESS_JOBS: [&str; 5] = ["plan", "linux", "macos", "windows", "verify"];

#[derive(Clone)]
struct JobState {
    state: String,
    artifact_id: Option<u64>,
    artifact_digest: Option<String>,
}

struct SummaryFailure {
    diagnostics: Vec<&'static str>,
    message: String,
    states: std::collections::BTreeMap<String, JobState>,
    source_diagnostics: std::collections::BTreeMap<String, Option<String>>,
}

impl SummaryFailure {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            diagnostics: vec![code],
            message: message.into(),
            states: std::collections::BTreeMap::new(),
            source_diagnostics: empty_source_diagnostics(),
        }
    }

    fn with_states(mut self, states: std::collections::BTreeMap<String, JobState>) -> Self {
        self.states = states;
        self
    }

    fn with_source_diagnostics(
        mut self,
        source_diagnostics: std::collections::BTreeMap<String, Option<String>>,
    ) -> Self {
        self.source_diagnostics = source_diagnostics;
        self
    }
}

fn record_job_state(
    job: &str,
    state: &str,
    artifact_id: Option<u64>,
    artifact_digest: Option<&str>,
    output: &Path,
) -> Result<String, String> {
    if !READINESS_JOBS.contains(&job) {
        return Err(format!("unsupported readiness job {job:?}"));
    }
    if !matches!(state, "success" | "failure" | "skipped") {
        return Err(format!("unsupported readiness job state {state:?}"));
    }
    match state {
        "success" => {
            let id = artifact_id
                .ok_or_else(|| "successful readiness state requires --artifact-id".to_owned())?;
            if id == 0 {
                return Err("readiness artifact ID must be nonzero".to_owned());
            }
            require_digest(
                artifact_digest.ok_or_else(|| {
                    "successful readiness state requires --artifact-digest".to_owned()
                })?,
                "readiness artifact digest",
            )?;
        }
        "failure" | "skipped" if artifact_id.is_some() || artifact_digest.is_some() => {
            return Err("non-success readiness state forbids artifact identity".to_owned());
        }
        "failure" | "skipped" => {}
        _ => unreachable!("state was validated above"),
    }
    if output.exists() {
        let metadata = fs::symlink_metadata(output)
            .map_err(|error| format!("cannot inspect readiness state root: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("readiness state root is not a real directory".to_owned());
        }
    } else {
        fs::create_dir_all(output)
            .map_err(|error| format!("cannot create readiness state root: {error}"))?;
    }
    let path = output.join(format!("{job}.json"));
    if path.exists() {
        return Err(format!("readiness state for {job:?} already exists"));
    }
    write_json(
        &path,
        &object([
            (
                "artifactDigest",
                artifact_digest.map_or(JsonValue::Null, string),
            ),
            ("artifactId", artifact_id.map_or(JsonValue::Null, number)),
            ("job", string(job)),
            ("schemaVersion", number(1)),
            ("state", string(state)),
        ]),
    )?;
    Ok(format!("recorded readiness job {job} as {state}"))
}

fn summarize(state_root: &Path, input: &Path, output: &Path) -> Result<String, String> {
    if output.exists() {
        return Err("readiness summary output already exists".to_owned());
    }
    let result = summarize_inner(state_root, input);
    let source_diagnostics = collect_source_diagnostics(input);
    match (result, source_diagnostics) {
        (Ok((states, plan)), Ok(source_diagnostics)) => {
            write_readiness_summary(&ReadinessSummaryInput {
                output,
                state_root,
                input,
                states: &states,
                final_state: "admitted",
                candidate_sha: Some(&plan.candidate_sha),
                workflow_sha: Some(&plan.workflow_sha),
                plan_sha256: Some(&plan.self_sha256),
                diagnostics: &[],
                source_diagnostics: &source_diagnostics,
            })?;
            Ok("readiness terminal summary admitted the exact candidate".to_owned())
        }
        (Ok((states, _)), Err(mut failure)) => {
            failure.states = states;
            persist_readiness_failure(output, state_root, input, failure)
        }
        (Err(mut failure), Ok(source_diagnostics)) => {
            failure.source_diagnostics = source_diagnostics;
            persist_readiness_failure(output, state_root, input, failure)
        }
        (Err(mut failure), Err(source_failure)) => {
            failure
                .diagnostics
                .extend(source_failure.diagnostics.iter().copied());
            failure.source_diagnostics = source_failure.source_diagnostics;
            failure.message = format!(
                "{}; additionally, {}",
                failure.message, source_failure.message
            );
            persist_readiness_failure(output, state_root, input, failure)
        }
    }
}

fn persist_readiness_failure(
    output: &Path,
    state_root: &Path,
    input: &Path,
    failure: SummaryFailure,
) -> Result<String, String> {
    let persist = write_readiness_summary(&ReadinessSummaryInput {
        output,
        state_root,
        input,
        states: &failure.states,
        final_state: blocked_state(&failure.states),
        candidate_sha: None,
        workflow_sha: None,
        plan_sha256: None,
        diagnostics: &failure.diagnostics,
        source_diagnostics: &failure.source_diagnostics,
    });
    match persist {
        Ok(()) => Err(failure.message),
        Err(persist) => Err(format!("{}; additionally, {persist}", failure.message)),
    }
}

fn summarize_inner(
    state_root: &Path,
    input: &Path,
) -> Result<(std::collections::BTreeMap<String, JobState>, ReadinessPlan), SummaryFailure> {
    let states = read_job_states(state_root)?;
    let all_success = READINESS_JOBS.iter().all(|job| {
        states
            .get(*job)
            .is_some_and(|state| state.state == "success")
    });
    if !all_success {
        return Err(SummaryFailure::new(
            "readiness.artifact.missing",
            format!(
                "readiness summary is non-admitted: {}",
                blocked_state(&states)
            ),
        )
        .with_states(states));
    }
    validate_input_topology(input).map_err(|failure| failure.with_states(states.clone()))?;
    let plan_path = input.join("plan").join("readiness-plan.json");
    let conformance_path = input.join("plan").join("conformance-plan.json");
    let plan = read_json(&plan_path)
        .and_then(|value| ReadinessPlan::parse(&value))
        .map_err(|error| {
            SummaryFailure::new(
                "readiness.artifact.invalid",
                format!("readiness plan artifact is invalid: {error}"),
            )
            .with_states(states.clone())
        })?;
    validate_conformance_binding(&plan, &conformance_path).map_err(|error| {
        SummaryFailure::new(
            "readiness.binding.mismatch",
            format!("readiness plan binding differs: {error}"),
        )
        .with_states(states.clone())
    })?;
    let execution = execution_plan(&plan).map_err(|error| {
        SummaryFailure::new(
            "readiness.binding.mismatch",
            format!("readiness execution plan is invalid: {error}"),
        )
        .with_states(states.clone())
    })?;
    let conformance = read_json(&conformance_path)
        .and_then(|value| crate::conformance::ConformancePlan::parse(&value))
        .map_err(|error| {
            SummaryFailure::new(
                "readiness.artifact.invalid",
                format!("readiness conformance artifact is invalid: {error}"),
            )
            .with_states(states.clone())
        })?;
    for (platform_id, platform) in [
        ("linux-x86_64", ReleasePlatform::LinuxX86_64),
        ("macos-aarch64", ReleasePlatform::MacosAarch64),
        ("windows-x86_64", ReleasePlatform::WindowsX86_64),
    ] {
        crate::release::assemble::verify_platform_report(
            &input
                .join("platforms")
                .join(platform_id)
                .join("platform-report.json"),
            &execution,
            &conformance,
            platform,
        )
        .map_err(|error| {
            SummaryFailure::new(
                "readiness.artifact.invalid",
                format!("readiness platform artifact {platform_id:?} is invalid: {error}"),
            )
            .with_states(states.clone())
        })?;
    }
    validate_readiness_verifier_result(input, &plan, &states)?;
    Ok((states, plan))
}

fn validate_readiness_verifier_result(
    input: &Path,
    plan: &ReadinessPlan,
    states: &std::collections::BTreeMap<String, JobState>,
) -> Result<(), SummaryFailure> {
    let result =
        read_json(&input.join("verifier").join("readiness-result.json")).map_err(|error| {
            SummaryFailure::new(
                "readiness.artifact.invalid",
                format!("readiness verifier artifact is invalid: {error}"),
            )
            .with_states(states.clone())
        })?;
    let fields = result.object().map_err(|error| {
        SummaryFailure::new(
            "readiness.artifact.invalid",
            format!("readiness verifier artifact is invalid: {error}"),
        )
        .with_states(states.clone())
    })?;
    require_exact_json_keys(
        fields,
        &[
            "candidateSha",
            "conformancePlanSha256",
            "readinessPlanSha256",
            "schemaVersion",
            "state",
        ],
    )
    .map_err(|error| {
        SummaryFailure::new(
            "readiness.artifact.invalid",
            format!("readiness verifier artifact has invalid fields: {error}"),
        )
        .with_states(states.clone())
    })?;
    let result_is_bound = (|| -> Result<bool, String> {
        Ok(json_member(fields, "schemaVersion")?.number()? == 1
            && json_member(fields, "state")?.string()? == "technically-release-eligible"
            && json_member(fields, "candidateSha")?.string()? == plan.candidate_sha
            && json_member(fields, "conformancePlanSha256")?.string()?
                == plan.conformance_plan_sha256
            && json_member(fields, "readinessPlanSha256")?.string()? == plan.self_sha256)
    })()
    .map_err(|error| {
        SummaryFailure::new(
            "readiness.artifact.invalid",
            format!("readiness verifier artifact fields are invalid: {error}"),
        )
        .with_states(states.clone())
    })?;
    if !result_is_bound {
        return Err(SummaryFailure::new(
            "readiness.binding.mismatch",
            "readiness verifier artifact differs from the bound plan",
        )
        .with_states(states.clone()));
    }
    Ok(())
}

fn read_job_states(
    root: &Path,
) -> Result<std::collections::BTreeMap<String, JobState>, SummaryFailure> {
    let metadata = fs::symlink_metadata(root).map_err(|error| {
        SummaryFailure::new(
            "readiness.job-state.inventory",
            format!("cannot inspect readiness state root: {error}"),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SummaryFailure::new(
            "readiness.job-state.inventory",
            "readiness state root is not a real directory",
        ));
    }
    let expected = READINESS_JOBS
        .iter()
        .map(|job| format!("{job}.json"))
        .collect::<std::collections::BTreeSet<_>>();
    let observed = fs::read_dir(root)
        .map_err(|error| {
            SummaryFailure::new(
                "readiness.job-state.inventory",
                format!("cannot enumerate readiness state root: {error}"),
            )
        })?
        .map(|entry| {
            entry
                .map_err(|error| format!("cannot inspect readiness state entry: {error}"))?
                .file_name()
                .into_string()
                .map_err(|_| "readiness state filename is not UTF-8".to_owned())
        })
        .collect::<Result<std::collections::BTreeSet<_>, String>>()
        .map_err(|error| SummaryFailure::new("readiness.job-state.inventory", error))?;
    if observed != expected {
        return Err(SummaryFailure::new(
            "readiness.job-state.inventory",
            "readiness job-state exact inventory differs",
        ));
    }
    let mut states = std::collections::BTreeMap::new();
    for job in READINESS_JOBS {
        let parsed = (|| -> Result<JobState, String> {
            let value = read_json(&root.join(format!("{job}.json")))?;
            let fields = value.object()?;
            require_exact_json_keys(
                fields,
                &[
                    "artifactDigest",
                    "artifactId",
                    "job",
                    "schemaVersion",
                    "state",
                ],
            )?;
            let state = json_member(fields, "state")?.string()?.to_owned();
            if json_member(fields, "schemaVersion")?.number()? != 1
                || json_member(fields, "job")?.string()? != job
                || !matches!(state.as_str(), "success" | "failure" | "skipped")
            {
                return Err(format!("readiness state for {job:?} is invalid"));
            }
            let (artifact_id, artifact_digest) = match (
                json_member(fields, "artifactId")?,
                json_member(fields, "artifactDigest")?,
            ) {
                (JsonValue::Number(id), JsonValue::String(digest))
                    if state == "success" && *id != 0 =>
                {
                    require_digest(digest, "readiness artifact digest")?;
                    (Some(*id), Some(digest.clone()))
                }
                (JsonValue::Null, JsonValue::Null) if state != "success" => (None, None),
                _ => return Err("readiness artifact identity contradicts job state".to_owned()),
            };
            Ok(JobState {
                state,
                artifact_id,
                artifact_digest,
            })
        })();
        match parsed {
            Ok(state) => {
                states.insert(job.to_owned(), state);
            }
            Err(error) => {
                return Err(
                    SummaryFailure::new("readiness.job-state.invalid", error).with_states(states)
                );
            }
        }
    }
    Ok(states)
}

fn empty_source_diagnostics() -> std::collections::BTreeMap<String, Option<String>> {
    [
        "plan",
        "linux-x86_64",
        "macos-aarch64",
        "windows-x86_64",
        "verifier",
    ]
    .into_iter()
    .map(|artifact| (artifact.to_owned(), None))
    .collect()
}

fn collect_source_diagnostics(
    input: &Path,
) -> Result<std::collections::BTreeMap<String, Option<String>>, SummaryFailure> {
    let mut diagnostics = empty_source_diagnostics();
    for platform in ["linux-x86_64", "macos-aarch64", "windows-x86_64"] {
        let root = input.join("platforms").join(platform);
        if !root.exists() {
            continue;
        }
        match platform_source_diagnostic(&root, platform) {
            Ok(diagnostic) => {
                diagnostics.insert(platform.to_owned(), diagnostic);
            }
            Err(error) => {
                return Err(SummaryFailure::new(
                    "readiness.artifact.invalid",
                    format!("readiness platform source report {platform:?} is invalid: {error}"),
                )
                .with_source_diagnostics(diagnostics));
            }
        }
    }
    let verifier = input.join("verifier");
    if verifier.exists() {
        match verifier_source_diagnostic(&verifier) {
            Ok(diagnostic) => {
                diagnostics.insert("verifier".to_owned(), diagnostic);
            }
            Err(error) => {
                return Err(SummaryFailure::new(
                    "readiness.artifact.invalid",
                    format!("readiness verifier source report is invalid: {error}"),
                )
                .with_source_diagnostics(diagnostics));
            }
        }
    }
    Ok(diagnostics)
}

fn platform_source_diagnostic(root: &Path, platform: &str) -> Result<Option<String>, String> {
    let passed = root.join("platform-report.json");
    let failed = root.join("platform-failure-report.json");
    if passed.exists() && failed.exists() {
        return Err("both success and failure reports are present".to_owned());
    }
    if failed.exists() {
        let value = read_json(&failed)?;
        let fields = value.object()?;
        let suite_keys = ["detail", "failedGate", "report", "schemaVersion", "state"];
        let command_keys = [
            "detail",
            "evidence",
            "failedGate",
            "gates",
            "schemaVersion",
            "state",
        ];
        if require_exact_json_keys(fields, &suite_keys).is_err()
            && require_exact_json_keys(fields, &command_keys).is_err()
        {
            return Err("failure report has unknown or missing fields".to_owned());
        }
        if json_member(fields, "schemaVersion")?.number()? != 1
            || json_member(fields, "state")?.string()? != "failed"
        {
            return Err("failure report schema or state differs".to_owned());
        }
        let gate = json_member(fields, "failedGate")?.string()?;
        require_stable_diagnostic_component(gate)?;
        return Ok(Some(format!("release.gate.{gate}")));
    }
    if passed.exists() {
        let value = read_json(&passed)?;
        let fields = value.object()?;
        if json_member(fields, "schemaVersion")?.number()? != 2
            || json_member(fields, "state")?.string()? != "passed"
            || json_member(fields, "platform")?.string()? != platform
        {
            return Err("success report schema, state, or platform differs".to_owned());
        }
    }
    Ok(None)
}

fn verifier_source_diagnostic(root: &Path) -> Result<Option<String>, String> {
    let result = root.join("readiness-result.json");
    let conformance = root.join("conformance-report.json");
    if result.exists() {
        let value = read_json(&result)?;
        let fields = value.object()?;
        require_exact_json_keys(
            fields,
            &[
                "candidateSha",
                "conformancePlanSha256",
                "readinessPlanSha256",
                "schemaVersion",
                "state",
            ],
        )?;
        if json_member(fields, "schemaVersion")?.number()? != 1
            || json_member(fields, "state")?.string()? != "technically-release-eligible"
        {
            return Err("readiness result schema or state differs".to_owned());
        }
    }
    if !conformance.exists() {
        return Ok(None);
    }
    conformance_source_diagnostic(&read_json(&conformance)?)
}

fn conformance_source_diagnostic(report: &JsonValue) -> Result<Option<String>, String> {
    let fields = report.object()?;
    require_exact_json_keys(
        fields,
        &[
            "admitted",
            "candidateSha",
            "cells",
            "conformancePlanSha256",
            "evidenceArchiveSha256",
            "partition",
            "reportSha256",
            "schemaVersion",
            "standard",
            "trustedInputsSha256",
            "unclassifiedMismatches",
        ],
    )?;
    if json_member(fields, "schemaVersion")?.number()? != 2 {
        return Err("conformance report schema differs".to_owned());
    }
    for cell in json_member(fields, "cells")?.array()? {
        let cell = cell.object()?;
        require_exact_json_keys(cell, &["disposition", "exemptions", "key"])?;
        let disposition = json_member(cell, "disposition")?.object()?;
        if json_member(disposition, "kind")?.string()? != "blocked" {
            continue;
        }
        let blocker = json_member(disposition, "blocker")?.object()?;
        let kind = json_member(blocker, "kind")?.string()?;
        let diagnostic = match kind {
            "missing-evidence" => "release.evidence.missing".to_owned(),
            "mismatch" => "release.evidence.mismatch".to_owned(),
            "invalid-evidence" => {
                let code = json_member(blocker, "code")?.string()?;
                require_stable_diagnostic_component(code)?;
                code.to_owned()
            }
            _ => return Err("conformance report has an unknown blocker kind".to_owned()),
        };
        if json_member(fields, "admitted")?.boolean()? {
            return Err("admitted conformance report contains a blocker".to_owned());
        }
        return Ok(Some(diagnostic));
    }
    if !json_member(fields, "unclassifiedMismatches")?
        .array()?
        .is_empty()
    {
        if json_member(fields, "admitted")?.boolean()? {
            return Err("admitted conformance report contains an unclassified mismatch".to_owned());
        }
        return Ok(Some("release.evidence.unclassified-mismatch".to_owned()));
    }
    if json_member(fields, "admitted")?.boolean()? {
        Ok(None)
    } else {
        Ok(Some("release.conformance.rejected".to_owned()))
    }
}

fn require_stable_diagnostic_component(value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err("diagnostic component is not a stable identifier".to_owned());
    }
    Ok(())
}

struct ReadinessSummaryInput<'a> {
    output: &'a Path,
    state_root: &'a Path,
    input: &'a Path,
    states: &'a std::collections::BTreeMap<String, JobState>,
    final_state: &'a str,
    candidate_sha: Option<&'a str>,
    workflow_sha: Option<&'a str>,
    plan_sha256: Option<&'a str>,
    diagnostics: &'a [&'a str],
    source_diagnostics: &'a std::collections::BTreeMap<String, Option<String>>,
}

fn write_readiness_summary(summary: &ReadinessSummaryInput<'_>) -> Result<(), String> {
    fs::create_dir(summary.output)
        .map_err(|error| format!("cannot create readiness summary output: {error}"))?;
    let job_states = JsonValue::Object(
        summary
            .states
            .iter()
            .map(|(job, state)| (job.clone(), string(&state.state)))
            .collect(),
    );
    let artifact_ids = JsonValue::Object(
        READINESS_JOBS
            .iter()
            .map(|job| {
                let value = summary.states.get(*job).map_or(JsonValue::Null, |state| {
                    object([
                        (
                            "artifactDigest",
                            state
                                .artifact_digest
                                .as_deref()
                                .map_or(JsonValue::Null, string),
                        ),
                        (
                            "artifactId",
                            state.artifact_id.map_or(JsonValue::Null, number),
                        ),
                    ])
                });
                (artifact_name(job).to_owned(), value)
            })
            .collect(),
    );
    let absent_artifacts = READINESS_JOBS
        .iter()
        .filter(|job| !artifact_path(summary.input, job).exists())
        .map(|job| string(artifact_name(job)))
        .collect::<Vec<_>>();
    let reproduction = reproduction_command(summary.state_root, summary.input, summary.output);
    let source_diagnostics = JsonValue::Object(
        summary
            .source_diagnostics
            .iter()
            .map(|(artifact, diagnostic)| {
                (
                    artifact.clone(),
                    diagnostic.as_deref().map_or(JsonValue::Null, string),
                )
            })
            .collect(),
    );
    write_json(
        &summary.output.join("readiness-summary.json"),
        &object([
            ("absentArtifacts", JsonValue::Array(absent_artifacts)),
            ("artifactIds", artifact_ids),
            (
                "candidateSha",
                summary.candidate_sha.map_or(JsonValue::Null, string),
            ),
            (
                "diagnostics",
                JsonValue::Array(
                    summary
                        .diagnostics
                        .iter()
                        .map(|message| string(message))
                        .collect(),
                ),
            ),
            ("jobStates", job_states),
            (
                "readinessPlanSha256",
                summary.plan_sha256.map_or(JsonValue::Null, string),
            ),
            ("schemaVersion", number(1)),
            ("reproductionCommand", reproduction),
            ("sourceDiagnostics", source_diagnostics),
            ("state", string(summary.final_state)),
            (
                "workflowSha",
                summary.workflow_sha.map_or(JsonValue::Null, string),
            ),
        ]),
    )?;
    Ok(())
}

fn blocked_state(states: &std::collections::BTreeMap<String, JobState>) -> &'static str {
    if states
        .get("verify")
        .is_some_and(|state| state.state == "failure")
    {
        "verifier-failed"
    } else if ["plan", "linux", "macos", "windows"].iter().any(|job| {
        states
            .get(*job)
            .is_some_and(|state| state.state == "failure")
    }) {
        "producer-failed"
    } else if states.len() == READINESS_JOBS.len()
        && states.values().any(|state| state.state != "success")
    {
        "incomplete"
    } else {
        "blocked"
    }
}

fn artifact_name(job: &str) -> &str {
    match job {
        "plan" => "plan",
        "linux" => "linux-x86_64",
        "macos" => "macos-aarch64",
        "windows" => "windows-x86_64",
        "verify" => "verifier",
        _ => panic!("job was validated against the static readiness inventory"),
    }
}

fn artifact_path(input: &Path, job: &str) -> PathBuf {
    match job {
        "plan" => input.join("plan"),
        "linux" | "macos" | "windows" => input.join("platforms").join(artifact_name(job)),
        "verify" => input.join("verifier"),
        _ => panic!("job was validated against the static readiness inventory"),
    }
}

fn reproduction_command(state_root: &Path, input: &Path, output: &Path) -> JsonValue {
    let Some(state_root) = state_root.to_str() else {
        return JsonValue::Null;
    };
    let Some(input) = input.to_str() else {
        return JsonValue::Null;
    };
    let reproduction_output = output.with_file_name("readiness-summary-reproduction");
    let Some(reproduction_output) = reproduction_output.to_str() else {
        return JsonValue::Null;
    };
    JsonValue::Array(
        [
            "hell-ci",
            "readiness",
            "summarize",
            "--state-root",
            state_root,
            "--input",
            input,
            "--output",
            reproduction_output,
        ]
        .into_iter()
        .map(string)
        .collect(),
    )
}

fn validate_input_topology(input: &Path) -> Result<(), SummaryFailure> {
    let metadata = fs::symlink_metadata(input).map_err(|error| {
        SummaryFailure::new(
            "readiness.artifact.missing",
            format!("cannot inspect readiness artifact root: {error}"),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SummaryFailure::new(
            "readiness.artifact.invalid",
            "readiness artifact root is not a real directory",
        ));
    }
    let expected = ["plan", "platforms", "verifier"]
        .into_iter()
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>();
    let observed = directory_names(input).map_err(|error| {
        SummaryFailure::new(
            "readiness.artifact.invalid",
            format!("cannot enumerate readiness artifact root: {error}"),
        )
    })?;
    if observed != expected {
        let missing = expected.difference(&observed).next().is_some();
        return Err(SummaryFailure::new(
            if missing {
                "readiness.artifact.missing"
            } else {
                "readiness.artifact.invalid"
            },
            "readiness artifact root exact inventory differs",
        ));
    }
    let platforms = input.join("platforms");
    let expected_platforms = ["linux-x86_64", "macos-aarch64", "windows-x86_64"]
        .into_iter()
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>();
    let observed_platforms = directory_names(&platforms).map_err(|error| {
        SummaryFailure::new(
            "readiness.artifact.invalid",
            format!("cannot enumerate readiness platform artifacts: {error}"),
        )
    })?;
    if observed_platforms != expected_platforms {
        let missing = expected_platforms
            .difference(&observed_platforms)
            .next()
            .is_some();
        return Err(SummaryFailure::new(
            if missing {
                "readiness.artifact.missing"
            } else {
                "readiness.artifact.invalid"
            },
            "readiness platform artifact exact inventory differs",
        ));
    }
    for job in READINESS_JOBS {
        let path = artifact_path(input, job);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            SummaryFailure::new(
                "readiness.artifact.missing",
                format!(
                    "cannot inspect readiness artifact {:?}: {error}",
                    artifact_name(job)
                ),
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(SummaryFailure::new(
                "readiness.artifact.invalid",
                format!(
                    "readiness artifact {:?} is not a real directory",
                    artifact_name(job)
                ),
            ));
        }
    }
    Ok(())
}

fn directory_names(root: &Path) -> Result<std::collections::BTreeSet<String>, String> {
    fs::read_dir(root)
        .map_err(|error| error.to_string())?
        .map(|entry| {
            let entry = entry.map_err(|error| error.to_string())?;
            let kind = entry.file_type().map_err(|error| error.to_string())?;
            if kind.is_symlink() || !kind.is_dir() {
                return Err("readiness artifact topology contains a non-directory".to_owned());
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| "readiness artifact directory name is not UTF-8".to_owned())
        })
        .collect()
}

fn validate_conformance_binding(plan: &ReadinessPlan, path: &Path) -> Result<(), String> {
    let conformance = crate::conformance::ConformancePlan::parse(&read_json(path)?)?;
    if conformance.plan_sha256 != plan.conformance_plan_sha256
        || conformance.candidate_sha != plan.candidate_sha
        || conformance.workflow_sha != plan.workflow_sha
        || conformance.release_evaluation_instant != plan.evaluation_instant
        || conformance.trusted_inputs_sha256 != plan.trusted_conformance_inputs_sha256
        || conformance.source_inventory_sha256 != plan.source_inventory_sha256
        || conformance.standard != plan.conformance_standard
    {
        return Err("conformance plan differs from readiness plan".to_owned());
    }
    let artifact_root = path
        .parent()
        .ok_or_else(|| "conformance plan has no artifact root".to_owned())?;
    let inventory = read_json(&artifact_root.join("source-inventory.json"))?;
    if hell_testkit::sha256_bytes(&canonical_json_bytes(&inventory)?).hex()
        != plan.source_inventory_sha256
    {
        return Err("readiness source inventory digest differs".to_owned());
    }
    if inventory_digest(&inventory, "release-policy.toml")? != plan.policy_sha256 {
        return Err("readiness policy digest differs from source inventory".to_owned());
    }
    let trusted = crate::conformance::parse_trusted_inputs(&read_json(
        &artifact_root.join("trusted-conformance-inputs.json"),
    )?)?;
    if trusted.aggregate_sha256 != plan.trusted_conformance_inputs_sha256
        || json_member(trusted.manifest.object()?, "workflowSha")?.string()? != plan.workflow_sha
    {
        return Err("trusted input artifact differs from readiness plan".to_owned());
    }
    Ok(())
}

fn execution_plan(plan: &ReadinessPlan) -> Result<ReleasePlan, String> {
    let marker_sha256 = hell_testkit::sha256_bytes(b"technical-readiness\n").hex();
    let repository_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let governance = crate::release::governance::declared_bindings(
        &repository_root.join("ci/governance-policy.toml"),
    )?;
    let external_inputs_sha256 = crate::release::native_environment::external_inputs_sha256(
        &repository_root.join("ci/external-inputs.toml"),
    )?;
    let mut execution = ReleasePlan {
        resolution: Resolution {
            repository: "local/technical-readiness".to_owned(),
            repository_id: 1,
            default_branch: "not-applicable".to_owned(),
            candidate_branch: "not-applicable".to_owned(),
            candidate_sha: plan.candidate_sha.clone(),
            actor: "ci".to_owned(),
            actor_id: 1,
            run_id: 1,
            run_attempt: 1,
            workflow_ref: "technical-readiness".to_owned(),
            workflow_sha: plan.workflow_sha.clone(),
        },
        version: READINESS_VERSION.to_owned(),
        tag: READINESS_TAG.to_owned(),
        prerelease: true,
        source_date_epoch: plan.source_date_epoch,
        release_evaluation_instant: plan.evaluation_instant.clone(),
        source_inventory_sha256: plan.source_inventory_sha256.clone(),
        build_inputs_sha256: plan.build_inputs_sha256.clone(),
        policy_sha256: plan.policy_sha256.clone(),
        governance_declaration_sha256: governance.declaration_sha256,
        governance_profile_sha256: governance.profile_sha256,
        residual_assumption_set_sha256: governance.residual_set_digest,
        external_inputs_sha256,
        trusted_conformance_inputs_sha256: plan.trusted_conformance_inputs_sha256.clone(),
        conformance_plan_sha256: plan.conformance_plan_sha256.clone(),
        conformance_standard: plan.conformance_standard.clone(),
        changelog_sha256: marker_sha256,
        commit_author: "not-applicable".to_owned(),
        commit_committer: "not-applicable".to_owned(),
        plan_sha256: String::new(),
    };
    execution.plan_sha256 =
        hell_testkit::sha256_bytes(&canonical_json_bytes(&execution.json_without_digest())?).hex();
    Ok(execution)
}

impl ReadinessPlan {
    fn expected_build_inputs_sha256(&self) -> Result<String, String> {
        let inputs = object([
            ("candidateSha", string(&self.candidate_sha)),
            ("conformanceStandard", string(&self.conformance_standard)),
            (
                "expectedPlatforms",
                JsonValue::Array(
                    PLATFORMS
                        .into_iter()
                        .map(|value| string(value.id()))
                        .collect(),
                ),
            ),
            ("policySha256", string(&self.policy_sha256)),
            ("schemaVersion", number(1)),
            (
                "sourceInventorySha256",
                string(&self.source_inventory_sha256),
            ),
            (
                "trustedConformanceInputsSha256",
                string(&self.trusted_conformance_inputs_sha256),
            ),
            ("workflowSha", string(&self.workflow_sha)),
        ]);
        Ok(hell_testkit::sha256_bytes(&canonical_json_bytes(&inputs)?).hex())
    }

    fn json_without_digest(&self) -> JsonValue {
        object([
            ("buildInputsSha256", string(&self.build_inputs_sha256)),
            ("candidateSha", string(&self.candidate_sha)),
            (
                "conformancePlanSha256",
                string(&self.conformance_plan_sha256),
            ),
            ("conformanceStandard", string(&self.conformance_standard)),
            ("evaluationInstant", string(&self.evaluation_instant)),
            ("executionPlanSha256", string(&self.execution_plan_sha256)),
            (
                "expectedPlatforms",
                JsonValue::Array(
                    PLATFORMS
                        .into_iter()
                        .map(|value| string(value.id()))
                        .collect(),
                ),
            ),
            ("policySha256", string(&self.policy_sha256)),
            ("schemaVersion", number(1)),
            ("sourceDateEpoch", number(self.source_date_epoch)),
            (
                "sourceInventorySha256",
                string(&self.source_inventory_sha256),
            ),
            (
                "trustedConformanceInputsSha256",
                string(&self.trusted_conformance_inputs_sha256),
            ),
            ("workflowSha", string(&self.workflow_sha)),
        ])
    }

    fn json(&self) -> JsonValue {
        let mut fields = self.json_without_digest().object().expect("object").clone();
        fields.insert("readinessPlanSha256".to_owned(), string(&self.self_sha256));
        JsonValue::Object(fields)
    }

    fn parse(value: &JsonValue) -> Result<Self, String> {
        let fields = value.object()?;
        require_exact_json_keys(
            fields,
            &[
                "buildInputsSha256",
                "candidateSha",
                "conformancePlanSha256",
                "conformanceStandard",
                "evaluationInstant",
                "executionPlanSha256",
                "expectedPlatforms",
                "policySha256",
                "readinessPlanSha256",
                "schemaVersion",
                "sourceDateEpoch",
                "sourceInventorySha256",
                "trustedConformanceInputsSha256",
                "workflowSha",
            ],
        )?;
        if json_member(fields, "schemaVersion")?.number()? != 1 {
            return Err("unsupported readiness plan schema".to_owned());
        }
        let platforms = json_member(fields, "expectedPlatforms")?.array()?;
        if platforms.len() != PLATFORMS.len()
            || !platforms
                .iter()
                .zip(PLATFORMS)
                .all(|(value, platform)| value.string() == Ok(platform.id()))
        {
            return Err("readiness plan platform set differs".to_owned());
        }
        let plan = Self {
            candidate_sha: text(fields, "candidateSha")?,
            workflow_sha: text(fields, "workflowSha")?,
            source_date_epoch: json_member(fields, "sourceDateEpoch")?.number()?,
            evaluation_instant: text(fields, "evaluationInstant")?,
            source_inventory_sha256: text(fields, "sourceInventorySha256")?,
            build_inputs_sha256: text(fields, "buildInputsSha256")?,
            policy_sha256: text(fields, "policySha256")?,
            trusted_conformance_inputs_sha256: text(fields, "trustedConformanceInputsSha256")?,
            conformance_plan_sha256: text(fields, "conformancePlanSha256")?,
            conformance_standard: text(fields, "conformanceStandard")?,
            execution_plan_sha256: text(fields, "executionPlanSha256")?,
            self_sha256: text(fields, "readinessPlanSha256")?,
        };
        plan.validate()?;
        Ok(plan)
    }

    fn validate(&self) -> Result<(), String> {
        require_sha(&self.candidate_sha, "readiness candidate SHA")?;
        require_sha(&self.workflow_sha, "readiness workflow SHA")?;
        if self.workflow_sha != self.candidate_sha {
            return Err("readiness automation SHA differs from candidate SHA".to_owned());
        }
        crate::conformance::validate_utc_instant(&self.evaluation_instant)?;
        for (value, label) in [
            (&self.source_inventory_sha256, "source inventory digest"),
            (&self.build_inputs_sha256, "build inputs digest"),
            (&self.policy_sha256, "policy digest"),
            (
                &self.trusted_conformance_inputs_sha256,
                "trusted inputs digest",
            ),
            (&self.conformance_plan_sha256, "conformance plan digest"),
            (&self.execution_plan_sha256, "execution plan digest"),
            (&self.self_sha256, "readiness plan digest"),
        ] {
            require_digest(value, label)?;
        }
        if self.conformance_standard != crate::conformance::RELEASE_STANDARD {
            return Err("readiness conformance standard differs".to_owned());
        }
        if self.expected_build_inputs_sha256()? != self.build_inputs_sha256 {
            return Err("readiness build input digest mismatch".to_owned());
        }
        if execution_plan(self)?.plan_sha256 != self.execution_plan_sha256 {
            return Err("readiness execution plan digest mismatch".to_owned());
        }
        let observed =
            hell_testkit::sha256_bytes(&canonical_json_bytes(&self.json_without_digest())?).hex();
        if observed != self.self_sha256 {
            return Err("readiness plan self-digest mismatch".to_owned());
        }
        Ok(())
    }
}

fn require_exact_plan_inventory(root: &Path) -> Result<(), String> {
    let observed = fs::read_dir(root)
        .map_err(|error| format!("cannot enumerate readiness plan: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("cannot inspect readiness plan: {error}"))?
                .file_name()
                .into_string()
                .map_err(|_| "readiness plan member is not UTF-8".to_owned())
        })
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    let expected = [
        "conformance-plan.json",
        "readiness-plan.json",
        "source-inventory.json",
        "trusted-conformance-inputs.json",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if observed != expected {
        return Err("readiness plan exact inventory differs".to_owned());
    }
    ReadinessPlan::parse(&read_json(&root.join("readiness-plan.json"))?)?;
    crate::conformance::ConformancePlan::parse(&read_json(&root.join("conformance-plan.json"))?)?;
    crate::conformance::parse_trusted_inputs(&read_json(
        &root.join("trusted-conformance-inputs.json"),
    )?)?;
    read_json(&root.join("source-inventory.json"))?;
    Ok(())
}

fn inventory_digest<'a>(inventory: &'a JsonValue, path: &str) -> Result<&'a str, String> {
    let files = json_member(inventory.object()?, "files")?.array()?;
    let entry = files
        .iter()
        .find(|entry| {
            entry
                .object()
                .ok()
                .and_then(|fields| json_member(fields, "path").ok())
                .and_then(|value| value.string().ok())
                == Some(path)
        })
        .ok_or_else(|| format!("source inventory lacks readiness input {path:?}"))?;
    json_member(entry.object()?, "sha256")?.string()
}

fn git_output<const N: usize>(root: &Path, arguments: [&str; N]) -> Result<String, String> {
    let result = CommandSpec::new("git", Duration::from_secs(30))
        .arguments(arguments)
        .current_directory(root)
        .run()
        .map_err(|error| format!("cannot inspect readiness candidate: {error}"))?;
    if result.timed_out || !result.status.success() {
        return Err("readiness candidate identity command failed".to_owned());
    }
    let value = std::str::from_utf8(&result.stdout)
        .map_err(|_| "readiness candidate identity is not UTF-8".to_owned())?
        .trim()
        .to_owned();
    if value.is_empty() {
        return Err("readiness candidate identity is empty".to_owned());
    }
    Ok(value)
}

fn append_outputs(plan: &ReadinessPlan) -> Result<(), String> {
    let environment = ProcessEnvironment::from_process();
    let Some(path) = environment.value(StandardVariable::GithubOutput) else {
        return Ok(());
    };
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect GITHUB_OUTPUT: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("GITHUB_OUTPUT is not a regular file".to_owned());
    }
    let mut output = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|error| format!("cannot open GITHUB_OUTPUT: {error}"))?;
    writeln!(
        output,
        "readiness_plan_digest={}\nconformance_plan_digest={}\ntrusted_conformance_inputs_digest={}",
        plan.self_sha256,
        plan.conformance_plan_sha256,
        plan.trusted_conformance_inputs_sha256,
    )
    .map_err(|error| format!("cannot append readiness outputs: {error}"))
}

fn readiness_automation_root() -> Result<PathBuf, String> {
    let environment = ProcessEnvironment::from_process();
    let root = environment
        .value(StandardVariable::GithubWorkspace)
        .map_or_else(
            || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."),
            |workspace| PathBuf::from(workspace).join("automation"),
        );
    fs::canonicalize(root)
        .map_err(|error| format!("cannot canonicalize candidate readiness automation: {error}"))
}

fn require_clean_checkout(root: &Path) -> Result<(), String> {
    let result = CommandSpec::new("git", Duration::from_secs(30))
        .arguments(["status", "--porcelain=v1", "--untracked-files=all"])
        .current_directory(root)
        .run()
        .map_err(|error| format!("cannot inspect readiness checkout state: {error}"))?;
    if result.timed_out || !result.status.success() {
        return Err("readiness checkout state command failed".to_owned());
    }
    if !result.stdout.is_empty() {
        return Err("readiness candidate checkout differs from its exact commit".to_owned());
    }
    Ok(())
}

fn current_evaluation_instant() -> Result<String, String> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes the Unix epoch".to_owned())?
        .as_secs();
    evaluation_instant_from_epoch(seconds)
}

fn evaluation_instant_from_epoch(seconds: u64) -> Result<String, String> {
    let days = seconds / 86_400;
    let day_seconds = seconds % 86_400;
    let days = i64::try_from(days).map_err(|_| "evaluation instant exceeds calendar bounds")?;
    let shifted = days
        .checked_add(719_468)
        .ok_or_else(|| "evaluation date overflow".to_owned())?;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    if !(0..=9_999).contains(&year) {
        return Err("evaluation instant exceeds supported UTC year".to_owned());
    }
    let hour = day_seconds / 3_600;
    let minute = day_seconds % 3_600 / 60;
    let second = day_seconds % 60;
    let instant = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z");
    crate::conformance::validate_utc_instant(&instant)?;
    Ok(instant)
}

fn transient_execution_plan(output: &Path, plan: &ReadinessPlan) -> PathBuf {
    output.with_file_name(format!(
        ".readiness-execution-{}.json",
        plan.execution_plan_sha256
    ))
}

fn remove_transient(path: &Path, result: Result<String, String>) -> Result<String, String> {
    fs::remove_file(path)
        .map_err(|error| format!("cannot remove transient readiness execution plan: {error}"))?;
    result
}

fn required<T>(value: Option<T>, name: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("readiness command requires {name}"))
}

fn parse_options(arguments: &[OsString]) -> Result<Options, String> {
    let mut options = Options::default();
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index]
            .to_str()
            .ok_or_else(|| "readiness option name must be UTF-8".to_owned())?;
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("{flag} requires a value"))?;
        index += 2;
        match flag {
            "--output" => set_path(&mut options.output, value, flag)?,
            "--repository-root" => set_path(&mut options.repository_root, value, flag)?,
            "--oracle-source" => set_path(&mut options.oracle_source, value, flag)?,
            "--plan" => set_path(&mut options.plan, value, flag)?,
            "--conformance-plan" => set_path(&mut options.conformance_plan, value, flag)?,
            "--input" => set_path(&mut options.input, value, flag)?,
            "--state-root" => set_path(&mut options.state_root, value, flag)?,
            "--platform" => {
                if options.platform.is_some() {
                    return Err(format!("{flag} was provided more than once"));
                }
                options.platform = Some(ReleasePlatform::parse(utf8(value, flag)?)?);
            }
            "--job" => set_text(&mut options.job, value, flag)?,
            "--state" => set_text(&mut options.state, value, flag)?,
            "--artifact-id" => set_number(&mut options.artifact_id, value, flag)?,
            "--artifact-digest" => set_text(&mut options.artifact_digest, value, flag)?,
            _ => return Err(format!("unknown readiness option {flag:?}")),
        }
    }
    Ok(options)
}

fn set_path(target: &mut Option<PathBuf>, value: &OsStr, flag: &str) -> Result<(), String> {
    if target.is_some() {
        return Err(format!("{flag} was provided more than once"));
    }
    *target = Some(PathBuf::from(value));
    Ok(())
}

fn set_text(target: &mut Option<String>, value: &OsStr, flag: &str) -> Result<(), String> {
    if target.is_some() {
        return Err(format!("{flag} was provided more than once"));
    }
    *target = Some(utf8(value, flag)?.to_owned());
    Ok(())
}

fn set_number(target: &mut Option<u64>, value: &OsStr, flag: &str) -> Result<(), String> {
    if target.is_some() {
        return Err(format!("{flag} was provided more than once"));
    }
    let value = utf8(value, flag)?;
    let parsed = value
        .parse::<u64>()
        .ok()
        .filter(|parsed| parsed.to_string() == value)
        .ok_or_else(|| format!("{flag} must be a canonical unsigned integer"))?;
    *target = Some(parsed);
    Ok(())
}

fn utf8<'a>(value: &'a OsStr, flag: &str) -> Result<&'a str, String> {
    value
        .to_str()
        .ok_or_else(|| format!("{flag} value must be UTF-8"))
}

fn usage() -> String {
    "usage: hell-ci readiness plan|platform|verify|record-job-state|summarize [options]".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_plan() -> ReadinessPlan {
        let digest = "a".repeat(64);
        let mut plan = ReadinessPlan {
            candidate_sha: "b".repeat(40),
            workflow_sha: "b".repeat(40),
            source_date_epoch: 1,
            evaluation_instant: "2026-08-13T00:00:00Z".to_owned(),
            source_inventory_sha256: digest.clone(),
            build_inputs_sha256: String::new(),
            policy_sha256: digest.clone(),
            trusted_conformance_inputs_sha256: digest.clone(),
            conformance_plan_sha256: digest,
            conformance_standard: crate::conformance::RELEASE_STANDARD.to_owned(),
            execution_plan_sha256: String::new(),
            self_sha256: String::new(),
        };
        plan.build_inputs_sha256 = plan.expected_build_inputs_sha256().unwrap();
        plan.execution_plan_sha256 = execution_plan(&plan).unwrap().plan_sha256;
        plan.self_sha256 =
            hell_testkit::sha256_bytes(&canonical_json_bytes(&plan.json_without_digest()).unwrap())
                .hex();
        plan
    }

    #[test]
    fn readiness_plan_has_no_release_intent_metadata() {
        let value = sample_plan().json();
        let fields = value.object().unwrap();
        for forbidden in [
            "version",
            "tag",
            "changelogSha256",
            "attestation",
            "publication",
        ] {
            assert!(!fields.contains_key(forbidden));
        }
        assert!(ReadinessPlan::parse(&value).is_ok());
    }

    #[test]
    fn readiness_plan_rejects_unknown_and_misbound_fields() {
        let plan = sample_plan();
        let mut unknown = plan.json().object().unwrap().clone();
        unknown.insert("status".to_owned(), string("passed"));
        assert!(ReadinessPlan::parse(&JsonValue::Object(unknown)).is_err());

        let mut misbound = plan.json().object().unwrap().clone();
        misbound.insert("candidateSha".to_owned(), string(&"c".repeat(40)));
        assert!(ReadinessPlan::parse(&JsonValue::Object(misbound)).is_err());

        let mut substituted = sample_plan();
        substituted.workflow_sha = "c".repeat(40);
        assert_eq!(
            substituted.validate(),
            Err("readiness automation SHA differs from candidate SHA".to_owned())
        );
    }

    #[test]
    fn readiness_cli_rejects_duplicate_options() {
        let arguments = [
            OsString::from("readiness"),
            OsString::from("plan"),
            OsString::from("--output"),
            OsString::from("one"),
            OsString::from("--output"),
            OsString::from("two"),
        ];
        assert!(run(&arguments).is_err());
    }

    #[test]
    fn evaluation_instant_uses_exact_utc_time() {
        assert_eq!(
            evaluation_instant_from_epoch(0).unwrap(),
            "1970-01-01T00:00:00Z"
        );
    }

    #[test]
    fn current_unmapped_applicable_cells_remain_release_blocking() {
        let plan = crate::conformance::build_release_conformance_plan(
            &"a".repeat(40),
            &"b".repeat(40),
            "2026-08-13T00:00:00Z",
            &"c".repeat(64),
            &"d".repeat(64),
            Vec::new(),
        )
        .unwrap();
        let unresolved = plan
            .cells
            .iter()
            .filter(|cell| {
                matches!(
                    cell.scope,
                    crate::conformance::ScopeDisposition::Required { .. }
                ) && cell
                    .obligations
                    .iter()
                    .any(|obligation| obligation.id == "unmapped-release-evidence")
                    && cell.exemption.is_none()
            })
            .count();
        assert_eq!(unresolved, 6_255);

        // The portable getCurrentDirectory mapping replaces exactly one generic
        // unmapped cell per release platform. Its absent failure evidence remains
        // explicit and release-blocking rather than disappearing into this count.
        let current_directory_effects = plan
            .cells
            .iter()
            .filter(|cell| {
                cell.key.builtin == "Directory.getCurrentDirectory"
                    && cell.key.dimension == hell_builtins::CompatibilityDimension::Effects
                    && cell.key.profile == crate::conformance::ProfileId::Upstream
            })
            .collect::<Vec<_>>();
        assert_eq!(current_directory_effects.len(), 3);
        for platform in crate::conformance::ConformancePlatform::ALL {
            let cell = current_directory_effects
                .iter()
                .find(|cell| cell.key.platform == platform)
                .unwrap_or_else(|| {
                    panic!("missing getCurrentDirectory Effects cell for {platform:?}")
                });
            let failure = cell
                .obligations
                .iter()
                .find(|obligation| obligation.id == "effect-failure")
                .expect("getCurrentDirectory must remain semantically fallible");
            assert!(failure.case_ids.is_empty());
            assert!(
                !cell
                    .obligations
                    .iter()
                    .any(|obligation| obligation.id == "unmapped-release-evidence")
            );
        }
    }
}
