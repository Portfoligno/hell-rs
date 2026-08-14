use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::command::CommandSpec;
use crate::json::{JsonValue, canonical_json_bytes, json_member, require_exact_json_keys};
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
    platform: Option<ReleasePlatform>,
    required_gates: Option<String>,
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
    readiness_plan_sha256: String,
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
        "plan" => create_plan(
            required(options.repository_root, "--repository-root")?,
            required(options.output, "--output")?,
        ),
        "platform" => platform(
            required(options.platform, "--platform")?,
            required(options.required_gates, "--required-gates")?,
            required(options.plan, "--plan")?,
            required(options.conformance_plan, "--conformance-plan")?,
            required(options.repository_root, "--repository-root")?,
            required(options.oracle_source, "--oracle-source")?,
            required(options.output, "--output")?,
        ),
        "verify" => verify(
            required(options.plan, "--plan")?,
            required(options.conformance_plan, "--conformance-plan")?,
            required(options.input, "--input")?,
            required(options.output, "--output")?,
        ),
        _ => Err(usage()),
    }
}

fn create_plan(root: PathBuf, output: PathBuf) -> Result<String, String> {
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

    let trusted_root = trusted_automation_root()?;
    require_clean_checkout(&trusted_root)?;
    let workflow_sha = git_output(&trusted_root, ["rev-parse", "HEAD"])?;
    require_sha(&workflow_sha, "readiness workflow SHA")?;

    let source_inventory = crate::release::plan::source_inventory(&root)?;
    let source_inventory_bytes = canonical_json_bytes(&source_inventory)?;
    let source_inventory_sha256 = hell_testkit::sha256_bytes(&source_inventory_bytes).hex();
    let trusted_inputs =
        crate::conformance::build_trusted_inputs(&trusted_root, &root, &workflow_sha)?;
    let exemptions = crate::conformance::parse_release_exemptions(&read_regular(
        &trusted_root.join(".github/release/conformance-exemptions.toml"),
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
        readiness_plan_sha256: String::new(),
    };
    plan.build_inputs_sha256 = plan.expected_build_inputs_sha256()?;
    plan.execution_plan_sha256 = execution_plan(&plan)?.plan_sha256;
    plan.readiness_plan_sha256 =
        hell_testkit::sha256_bytes(&canonical_json_bytes(&plan.json_without_digest())?).hex();
    plan.validate()?;

    fs::create_dir(&output)
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
    require_exact_plan_inventory(&output)?;
    validate_conformance_binding(&plan, &output.join("conformance-plan.json"))?;
    append_outputs(&plan)?;
    Ok(format!(
        "planned technical readiness for {}",
        plan.candidate_sha
    ))
}

fn platform(
    platform: ReleasePlatform,
    required_gates: String,
    plan_path: PathBuf,
    conformance_plan_path: PathBuf,
    root: PathBuf,
    oracle_source: PathBuf,
    output: PathBuf,
) -> Result<String, String> {
    let plan = ReadinessPlan::parse(&read_json(&plan_path)?)?;
    validate_conformance_binding(&plan, &conformance_plan_path)?;
    let execution_path = transient_execution_plan(&output, &plan);
    write_json(&execution_path, &execution_plan(&plan)?.json())?;
    let result = crate::release::platform::run(
        platform,
        required_gates,
        execution_path.clone(),
        conformance_plan_path,
        root,
        oracle_source,
        output,
    );
    remove_transient(&execution_path, result)
}

fn verify(
    plan_path: PathBuf,
    conformance_plan_path: PathBuf,
    input: PathBuf,
    output: PathBuf,
) -> Result<String, String> {
    if output.exists() {
        return Err("readiness verification output already exists".to_owned());
    }
    let plan = ReadinessPlan::parse(&read_json(&plan_path)?)?;
    validate_conformance_binding(&plan, &conformance_plan_path)?;
    fs::create_dir(&output)
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
                    ("readinessPlanSha256", string(&plan.readiness_plan_sha256)),
                    ("schemaVersion", number(1)),
                    ("state", string("technically-release-eligible")),
                ]),
            )?;
            Ok("independently verified technical release eligibility".to_owned())
        }
        Err(error) => Err(format!("technical release readiness blocked: {error}")),
    }
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
        fields.insert(
            "readinessPlanSha256".to_owned(),
            string(&self.readiness_plan_sha256),
        );
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
            readiness_plan_sha256: text(fields, "readinessPlanSha256")?,
        };
        plan.validate()?;
        Ok(plan)
    }

    fn validate(&self) -> Result<(), String> {
        require_sha(&self.candidate_sha, "readiness candidate SHA")?;
        require_sha(&self.workflow_sha, "readiness workflow SHA")?;
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
            (&self.readiness_plan_sha256, "readiness plan digest"),
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
        if observed != self.readiness_plan_sha256 {
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
    let Some(path) = std::env::var_os("GITHUB_OUTPUT") else {
        return Ok(());
    };
    let metadata = fs::symlink_metadata(&path)
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
        "trusted_sha={}\nreadiness_plan_digest={}\nconformance_plan_digest={}\ntrusted_conformance_inputs_digest={}",
        plan.workflow_sha,
        plan.readiness_plan_sha256,
        plan.conformance_plan_sha256,
        plan.trusted_conformance_inputs_sha256,
    )
    .map_err(|error| format!("cannot append readiness outputs: {error}"))
}

fn trusted_automation_root() -> Result<PathBuf, String> {
    let root = std::env::var_os("GITHUB_WORKSPACE")
        .map(PathBuf::from)
        .map(|workspace| workspace.join("automation"))
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
    fs::canonicalize(root)
        .map_err(|error| format!("cannot canonicalize trusted readiness automation: {error}"))
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
            "--platform" => {
                if options.platform.is_some() {
                    return Err(format!("{flag} was provided more than once"));
                }
                options.platform = Some(ReleasePlatform::parse(utf8(value, flag)?)?);
            }
            "--required-gates" => {
                if options.required_gates.is_some() {
                    return Err(format!("{flag} was provided more than once"));
                }
                options.required_gates = Some(utf8(value, flag)?.to_owned());
            }
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

fn utf8<'a>(value: &'a OsStr, flag: &str) -> Result<&'a str, String> {
    value
        .to_str()
        .ok_or_else(|| format!("{flag} value must be UTF-8"))
}

fn usage() -> String {
    "usage: hell-ci readiness plan|platform|verify [options]".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_plan() -> ReadinessPlan {
        let digest = "a".repeat(64);
        let mut plan = ReadinessPlan {
            candidate_sha: "b".repeat(40),
            workflow_sha: "c".repeat(40),
            source_date_epoch: 1,
            evaluation_instant: "2026-08-13T00:00:00Z".to_owned(),
            source_inventory_sha256: digest.clone(),
            build_inputs_sha256: String::new(),
            policy_sha256: digest.clone(),
            trusted_conformance_inputs_sha256: digest.clone(),
            conformance_plan_sha256: digest,
            conformance_standard: crate::conformance::RELEASE_STANDARD.to_owned(),
            execution_plan_sha256: String::new(),
            readiness_plan_sha256: String::new(),
        };
        plan.build_inputs_sha256 = plan.expected_build_inputs_sha256().unwrap();
        plan.execution_plan_sha256 = execution_plan(&plan).unwrap().plan_sha256;
        plan.readiness_plan_sha256 =
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
