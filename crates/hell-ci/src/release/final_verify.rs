use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::command::CommandSpec;
use crate::json::{JsonValue, canonical_json_bytes, json_member};

use super::decision::{self, VerifierDecision};
use super::manifest::{read_json, read_regular, write_atomic_new, write_json, write_json_new};
use super::schema::{ReleasePlan, number, object, string};

const EXECUTION_BUDGET: Duration = Duration::from_mins(30);
const COMPLETION_GRACE: Duration = Duration::from_mins(1);
const CLEANUP_GRACE: Duration = Duration::from_mins(1);
const MAX_RETAINED_DIAGNOSTIC_BYTES: usize = 4096;
const MAX_RETAINED_REPORT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy)]
struct Deadlines {
    execution: Instant,
    completion: Instant,
    cleanup: Instant,
}

impl Deadlines {
    fn establish() -> Result<Self, String> {
        let started = Instant::now();
        let execution = started
            .checked_add(EXECUTION_BUDGET)
            .ok_or_else(|| "final verification execution deadline overflow".to_owned())?;
        let completion = execution
            .checked_add(COMPLETION_GRACE)
            .ok_or_else(|| "final verification completion deadline overflow".to_owned())?;
        let cleanup = completion
            .checked_add(CLEANUP_GRACE)
            .ok_or_else(|| "final verification cleanup deadline overflow".to_owned())?;
        Ok(Self {
            execution,
            completion,
            cleanup,
        })
    }

    fn require_cleanup(self, phase: &str) -> Result<(), String> {
        if Instant::now() >= self.cleanup {
            return Err(format!(
                "final verification cleanup deadline expired before {phase}"
            ));
        }
        Ok(())
    }

    fn require_execution(self, phase: &str) -> Result<(), String> {
        if Instant::now() >= self.execution {
            return Err(format!(
                "final verification execution deadline expired before {phase}"
            ));
        }
        Ok(())
    }

    fn require_completion(self, phase: &str) -> Result<(), String> {
        if Instant::now() >= self.completion {
            return Err(format!(
                "final verification completion deadline expired before {phase}"
            ));
        }
        Ok(())
    }
}

pub(crate) struct Options {
    pub plan: PathBuf,
    pub conformance_plan: PathBuf,
    pub bundle: PathBuf,
    pub independent_verifier: PathBuf,
    pub protocol_projection: PathBuf,
    pub expected_artifact_digest: String,
    pub governance_post_assembly: PathBuf,
    pub governance_pre_attestation: PathBuf,
    pub output: PathBuf,
    pub report: PathBuf,
}

struct FinalVerificationTransaction(Options);

impl FinalVerificationTransaction {
    fn new(options: Options) -> Self {
        Self(options)
    }

    fn options(&self) -> &Options {
        &self.0
    }
}

pub(crate) fn run(options: Options) -> Result<String, String> {
    let transaction = FinalVerificationTransaction::new(options);
    let options = transaction.options();
    if options.output.exists() {
        return Err("final verification output already exists".to_owned());
    }
    if options.report.exists() {
        return Err("final verification report already exists".to_owned());
    }
    let diagnostics = diagnostic_root(&options.report)?;
    if diagnostics.exists() {
        return Err("final verification diagnostic output already exists".to_owned());
    }
    let deadlines = Deadlines::establish()?;
    let staging = staging_path(&options.output)?;
    let report_staging = staging_path(&options.report)?;
    if staging.exists() {
        return Err("final verification staging path already exists".to_owned());
    }
    if report_staging.exists() {
        return Err("final verification report staging path already exists".to_owned());
    }
    fs::create_dir_all(&staging)
        .map_err(|error| format!("cannot create final verification staging: {error}"))?;
    let result = run_staged(options, &staging, deadlines);
    match result {
        Ok(message) => {
            if let Err(primary) = deadlines.require_completion("durable success report") {
                return fail_run(
                    &options.report,
                    &staging,
                    &diagnostics,
                    &report_staging,
                    primary,
                    deadlines,
                );
            }
            if let Err(primary) = write_json_new(
                &report_staging,
                &object([
                    ("admitted", JsonValue::Bool(true)),
                    ("diagnosticCode", JsonValue::Null),
                    ("schemaVersion", number(1)),
                    ("state", string("dually-verified")),
                ]),
            ) {
                return fail_run(
                    &options.report,
                    &staging,
                    &diagnostics,
                    &report_staging,
                    primary,
                    deadlines,
                );
            }
            if let Err(primary) = deadlines.require_cleanup("verified output promotion") {
                return fail_run(
                    &options.report,
                    &staging,
                    &diagnostics,
                    &report_staging,
                    primary,
                    deadlines,
                );
            }
            if let Err(failure) =
                promote_success(&staging, &options.output, &report_staging, &options.report)
            {
                return fail_run(
                    &options.report,
                    &failure.authority_root,
                    &diagnostics,
                    &report_staging,
                    failure.message,
                    deadlines,
                );
            }
            Ok(message)
        }
        Err(primary) => fail_run(
            &options.report,
            &staging,
            &diagnostics,
            &report_staging,
            primary,
            deadlines,
        ),
    }
}

fn fail_run(
    report: &Path,
    authority_root: &Path,
    diagnostics: &Path,
    report_staging: &Path,
    primary: String,
    deadlines: Deadlines,
) -> Result<String, String> {
    let retained = retain_diagnostics(authority_root, diagnostics, &primary, deadlines);
    let staged_report_cleanup = if report_staging.exists() {
        fs::remove_file(report_staging)
            .map_err(|error| format!("cannot remove staged verification report: {error}"))
    } else {
        Ok(())
    };
    let report_result = write_json_new(
        report,
        &object([
            ("admitted", JsonValue::Bool(false)),
            (
                "diagnosticCode",
                string("release.final-verification-failed"),
            ),
            ("diagnosticMessage", string(&bounded_text(&primary))),
            ("diagnosticsPath", string(&diagnostics.to_string_lossy())),
            ("schemaVersion", number(1)),
            ("state", string("blocked")),
        ]),
    );
    let cleanup_deadline = deadlines.require_cleanup("failed authority cleanup");
    let cleanup = if authority_root.exists() {
        fs::remove_dir_all(authority_root)
            .map_err(|error| format!("cannot remove failed verification authority: {error}"))
    } else {
        Ok(())
    };
    let mut error = primary;
    for secondary in [
        retained,
        staged_report_cleanup,
        report_result.map(|_| ()),
        cleanup_deadline,
        cleanup,
    ] {
        if let Err(secondary) = secondary {
            error.push_str("; additionally, ");
            error.push_str(&secondary);
        }
    }
    Err(error)
}

struct PromotionFailure {
    authority_root: PathBuf,
    message: String,
}

fn promote_success(
    staging: &Path,
    output: &Path,
    report_staging: &Path,
    report: &Path,
) -> Result<(), PromotionFailure> {
    fs::rename(staging, output).map_err(|error| PromotionFailure {
        authority_root: staging.to_path_buf(),
        message: format!("cannot promote verified release set: {error}"),
    })?;
    fs::rename(report_staging, report).map_err(|error| PromotionFailure {
        authority_root: output.to_path_buf(),
        message: format!("cannot promote final verification report: {error}"),
    })?;
    Ok(())
}

fn run_staged(options: &Options, staging: &Path, deadlines: Deadlines) -> Result<String, String> {
    deadlines.require_execution("primary deep verification")?;
    let (governance_receipts, governance_resolve) = verify_governance_receipt_chain(options)?;
    let primary_report = staging.join("primary-verification-report.json");
    let primary_decision_path = staging.join("primary-verifier-decision.json");
    let protocol_sha256 =
        super::decision::protocol_sha256_from_projection(&options.protocol_projection)?;
    super::verify::technical_bundle_with_decision(
        options.plan.clone(),
        options.conformance_plan.clone(),
        options.bundle.clone(),
        primary_report,
        primary_decision_path.clone(),
        protocol_sha256,
        governance_receipts,
    )?;
    deadlines.require_execution("independent deep verification")?;

    let executable = fs::canonicalize(&options.independent_verifier)
        .map_err(|error| format!("cannot canonicalize independent verifier: {error}"))?;
    let arguments = independent_verifier_arguments(options, staging, &governance_resolve);
    let mut command = CommandSpec::trusted_absolute(executable.clone(), Duration::from_mins(30))?
        .arguments(arguments);
    command.clear_environment = true;
    let (progress, _receiver) = hell_testkit::SupervisedProgressObserver::bounded(1);
    let result = command
        .run_until(deadlines.execution, deadlines.completion, progress)
        .map_err(|error| format!("independent verifier could not run: {}", error.message()))?;
    write_child_report(staging, "independent-deep", &result)?;
    if !result.status.success() || result.timed_out {
        return Err(format!(
            "independent verifier rejected the release with status {}: {}",
            result.status,
            bounded_text(&String::from_utf8_lossy(&result.stderr)),
        ));
    }
    deadlines.require_completion("verifier agreement")?;
    let independent_decision_path = staging
        .join("independent")
        .join("independent-verifier-decision.json");
    let agreement = staging.join("verifier-agreement.json");
    decision::agree(
        primary_decision_path.clone(),
        independent_decision_path.clone(),
        agreement,
    )?;
    let primary = decision::read(&primary_decision_path)?;
    let independent = decision::read(&independent_decision_path)?;
    install_bundle(&options.bundle, staging)?;
    write_atomic_new(
        &staging.join("release-plan.json"),
        &read_regular(&options.plan)?,
    )?;
    for (source, name) in [
        (&governance_resolve, "governance-resolve.json"),
        (
            &options.governance_post_assembly,
            "governance-post-assembly.json",
        ),
        (
            &options.governance_pre_attestation,
            "governance-pre-attestation.json",
        ),
    ] {
        write_atomic_new(&staging.join(name), &read_regular(source)?)?;
    }
    fs::copy(
        &independent_decision_path,
        staging.join("independent-verifier-decision.json"),
    )
    .map_err(|error| format!("cannot retain independent verifier decision: {error}"))?;
    fs::copy(
        staging
            .join("independent")
            .join("independent-verifier-report.json"),
        staging.join("independent-verifier-report.json"),
    )
    .map_err(|error| format!("cannot retain independent verifier report: {error}"))?;
    fs::remove_dir_all(staging.join("independent"))
        .map_err(|error| format!("cannot remove empty verifier staging directory: {error}"))?;
    deadlines.require_completion("publication envelope construction")?;
    write_publication_envelope(options, staging, &primary, &independent)?;
    if !crate::mutation::active("skip-shallow-envelope-verification") {
        verify_publication_envelope(options, staging, &executable, deadlines)?;
    }
    Ok("deep release verification completed with matching independent decisions".to_owned())
}

fn independent_verifier_arguments(
    options: &Options,
    staging: &Path,
    governance_resolve: &Path,
) -> Vec<OsString> {
    vec![
        OsString::from("verify"),
        OsString::from("--plan"),
        options.plan.as_os_str().to_owned(),
        OsString::from("--conformance-plan"),
        options.conformance_plan.as_os_str().to_owned(),
        OsString::from("--bundle"),
        options.bundle.as_os_str().to_owned(),
        OsString::from("--output"),
        staging.join("independent").into_os_string(),
        OsString::from("--protocol-projection"),
        options.protocol_projection.as_os_str().to_owned(),
        OsString::from("--governance-resolve"),
        governance_resolve.as_os_str().to_owned(),
        OsString::from("--governance-post-assembly"),
        options.governance_post_assembly.as_os_str().to_owned(),
        OsString::from("--governance-pre-attestation"),
        options.governance_pre_attestation.as_os_str().to_owned(),
    ]
}

fn verify_governance_receipt_chain(
    options: &Options,
) -> Result<(super::verify::GovernanceReceiptDigests, PathBuf), String> {
    let plan = ReleasePlan::parse(&read_json(&options.plan)?)?;
    let resolve = options
        .plan
        .parent()
        .ok_or_else(|| "release plan has no artifact root".to_owned())?
        .join("governance-resolve.json");
    let resolve_sha256 = super::governance::verify_snapshot(
        &resolve,
        &plan,
        super::governance::Phase::Resolve,
        None,
        None,
    )?;
    let post_assembly_sha256 = super::governance::verify_snapshot(
        &options.governance_post_assembly,
        &plan,
        super::governance::Phase::PostAssembly,
        Some(&resolve_sha256),
        Some(&resolve_sha256),
    )?;
    let pre_attestation_sha256 = super::governance::verify_snapshot(
        &options.governance_pre_attestation,
        &plan,
        super::governance::Phase::PreAttestation,
        Some(&resolve_sha256),
        Some(&post_assembly_sha256),
    )?;
    Ok((
        super::verify::GovernanceReceiptDigests {
            resolve: resolve_sha256,
            post_assembly: post_assembly_sha256,
            pre_attestation: pre_attestation_sha256,
        },
        resolve,
    ))
}

fn verify_publication_envelope(
    options: &Options,
    staging: &Path,
    executable: &Path,
    deadlines: Deadlines,
) -> Result<(), String> {
    let arguments = [
        OsString::from("verify-envelope"),
        OsString::from("--envelope"),
        staging.join("publication-envelope.json").into_os_string(),
        OsString::from("--subject-root"),
        staging.as_os_str().to_owned(),
        OsString::from("--expected-artifact-digest"),
        OsString::from(&options.expected_artifact_digest),
        OsString::from("--output"),
        staging
            .join("publication-envelope-verification.json")
            .into_os_string(),
    ];
    let mut command =
        CommandSpec::trusted_absolute(executable.to_path_buf(), Duration::from_mins(1))?
            .arguments(arguments);
    command.clear_environment = true;
    let (progress, _receiver) = hell_testkit::SupervisedProgressObserver::bounded(1);
    let result = command
        .run_until(deadlines.execution, deadlines.completion, progress)
        .map_err(|error| {
            format!(
                "independent envelope verifier could not run: {}",
                error.message()
            )
        })?;
    write_child_report(staging, "independent-envelope", &result)?;
    if !result.status.success() || result.timed_out {
        return Err(format!(
            "independent envelope verifier rejected staged publication metadata with status {}: {}",
            result.status,
            bounded_text(&String::from_utf8_lossy(&result.stderr)),
        ));
    }
    Ok(())
}

fn write_child_report(
    staging: &Path,
    id: &str,
    result: &crate::command::CommandResult,
) -> Result<(), String> {
    let stderr = bounded_text(&String::from_utf8_lossy(&result.stderr));
    write_json(
        &staging.join(format!("{id}-child.json")),
        &object([
            ("id", string(id)),
            ("schemaVersion", number(1)),
            ("status", string(&result.status.to_string())),
            ("stderr", string(&stderr)),
            ("stderrBytes", number(result.stderr_bytes)),
            ("stderrSha256", string(&result.stderr_sha256.hex())),
            ("stderrTruncated", JsonValue::Bool(result.stderr_truncated)),
            ("timedOut", JsonValue::Bool(result.timed_out)),
        ]),
    )
    .map(|_| ())
}

fn diagnostic_root(report: &Path) -> Result<PathBuf, String> {
    let parent = report
        .parent()
        .ok_or_else(|| "final verification report has no parent".to_owned())?;
    Ok(parent.join("final-verification-diagnostics"))
}

fn retain_diagnostics(
    staging: &Path,
    output: &Path,
    primary: &str,
    deadlines: Deadlines,
) -> Result<(), String> {
    fs::create_dir_all(output)
        .map_err(|error| format!("cannot create final verification diagnostics: {error}"))?;
    let mut secondary = Vec::new();
    if let Err(error) = deadlines.require_cleanup("diagnostic retention") {
        secondary.push(error);
    }
    if let Err(error) = write_json_new(
        &output.join("failure-summary.json"),
        &object([
            (
                "diagnosticCode",
                string("release.final-verification-failed"),
            ),
            ("diagnosticMessage", string(&bounded_text(primary))),
            ("schemaVersion", number(1)),
            ("state", string("blocked")),
        ]),
    ) {
        secondary.push(error);
    }
    for (sources, destination) in [
        (
            &["primary-verification-report.json"][..],
            "primary-verification-report.json",
        ),
        (
            &["primary-verifier-decision.json"][..],
            "primary-verifier-decision.json",
        ),
        (&["verifier-agreement.json"][..], "verifier-agreement.json"),
        (
            &["publication-envelope.json"][..],
            "publication-envelope.json",
        ),
        (
            &["publication-envelope-verification.json"][..],
            "publication-envelope-verification.json",
        ),
        (
            &["independent-deep-child.json"][..],
            "independent-deep-child.json",
        ),
        (
            &["independent-envelope-child.json"][..],
            "independent-envelope-child.json",
        ),
        (
            &[
                "independent-verifier-report.json",
                "independent/independent-verifier-report.json",
            ][..],
            "independent-verifier-report.json",
        ),
        (
            &[
                "independent-verifier-decision.json",
                "independent/independent-verifier-decision.json",
            ][..],
            "independent-verifier-decision.json",
        ),
    ] {
        let source = sources
            .iter()
            .map(|source| staging.join(source))
            .find(|source| source.exists());
        let Some(source) = source else {
            continue;
        };
        if let Err(error) = deadlines.require_cleanup("diagnostic file retention") {
            secondary.push(error);
            break;
        }
        let retained = read_bounded_diagnostic(&source)
            .and_then(|bytes| write_atomic_new(&output.join(destination), &bytes));
        if let Err(error) = retained {
            secondary.push(error);
        }
    }
    if secondary.is_empty() {
        Ok(())
    } else {
        Err(secondary.join("; additionally, "))
    }
}

fn read_bounded_diagnostic(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect retained diagnostic: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("retained diagnostic is not a regular file".to_owned());
    }
    if metadata.len() > MAX_RETAINED_REPORT_BYTES {
        return Err("retained diagnostic exceeds the bounded report limit".to_owned());
    }
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read retained diagnostic: {error}"))?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err("retained diagnostic changed while being read".to_owned());
    }
    Ok(bytes)
}

pub(crate) fn verify_transaction_for_integration(arguments: &[OsString]) -> Result<(), String> {
    if arguments.len() != 2 {
        return Err(
            "final verification transaction check requires CASE and one output root".to_owned(),
        );
    }
    let case = arguments[0]
        .to_str()
        .ok_or_else(|| "final verification transaction case must be UTF-8".to_owned())?;
    let root = PathBuf::from(&arguments[1]);
    prepare_transaction_fixture_root(&root)?;
    match case {
        "promotion" => verify_success_promotion(&root),
        "rollback" => verify_failed_report_promotion(&root),
        "retention-late-failure" => verify_late_retention_failure(&root),
        "expired-cleanup" => verify_expired_cleanup(&root),
        _ => Err("unknown final verification transaction case".to_owned()),
    }
}

fn prepare_transaction_fixture_root(root: &Path) -> Result<(), String> {
    fs::create_dir_all(root)
        .map_err(|error| format!("cannot create transaction fixture root: {error}"))?;
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect transaction fixture root: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("transaction fixture root is not a real directory".to_owned());
    }
    let mut entries = fs::read_dir(root)
        .map_err(|error| format!("cannot enumerate transaction fixture root: {error}"))?;
    if entries.next().is_some() {
        return Err("transaction fixture root is not empty".to_owned());
    }
    Ok(())
}

fn verify_success_promotion(root: &Path) -> Result<(), String> {
    let staging = root.join("authority-staging");
    let output = root.join("authority");
    let report_staging = root.join("report-staging.json");
    let report = root.join("report.json");
    fs::create_dir(&staging)
        .map_err(|error| format!("cannot create authority staging fixture: {error}"))?;
    write_json_new(
        &staging.join("authority.json"),
        &transaction_fixture_json("verified-authority"),
    )?;
    write_json_new(
        &report_staging,
        &object([
            ("admitted", JsonValue::Bool(true)),
            ("diagnosticCode", JsonValue::Null),
            ("schemaVersion", number(1)),
            ("state", string("dually-verified")),
        ]),
    )?;
    promote_success(&staging, &output, &report_staging, &report).map_err(|failure| failure.message)
}

fn verify_failed_report_promotion(root: &Path) -> Result<(), String> {
    let staging = root.join("authority-staging");
    let output = root.join("authority");
    let report_staging = root.join("missing-report-staging.json");
    let report = root.join("report.json");
    let diagnostics = root.join("diagnostics");
    fs::create_dir(&staging)
        .map_err(|error| format!("cannot create authority staging fixture: {error}"))?;
    write_json_new(
        &staging.join("primary-verification-report.json"),
        &transaction_fixture_json("primary-verified"),
    )?;
    let failure = match promote_success(&staging, &output, &report_staging, &report) {
        Ok(()) => return Err("missing report staging unexpectedly promoted".to_owned()),
        Err(failure) => failure,
    };
    fail_run(
        &report,
        &failure.authority_root,
        &diagnostics,
        &report_staging,
        failure.message,
        Deadlines::establish()?,
    )
    .map(|_| ())
}

fn verify_late_retention_failure(root: &Path) -> Result<(), String> {
    let staging = root.join("authority-staging");
    let diagnostics = root.join("diagnostics");
    fs::create_dir(&staging)
        .map_err(|error| format!("cannot create authority staging fixture: {error}"))?;
    write_json_new(
        &staging.join("primary-verification-report.json"),
        &transaction_fixture_json("primary-verified"),
    )?;
    fs::create_dir(staging.join("primary-verifier-decision.json"))
        .map_err(|error| format!("cannot create late retention failure fixture: {error}"))?;
    retain_diagnostics(
        &staging,
        &diagnostics,
        "integration primary failure",
        Deadlines::establish()?,
    )
}

fn verify_expired_cleanup(root: &Path) -> Result<(), String> {
    let staging = root.join("authority-staging");
    let report_staging = root.join("report-staging.json");
    let report = root.join("report.json");
    let diagnostics = root.join("diagnostics");
    fs::create_dir(&staging)
        .map_err(|error| format!("cannot create authority staging fixture: {error}"))?;
    write_json_new(
        &staging.join("primary-verification-report.json"),
        &transaction_fixture_json("primary-verified"),
    )?;
    let expired = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .ok_or_else(|| "cannot establish expired cleanup fixture deadline".to_owned())?;
    fail_run(
        &report,
        &staging,
        &diagnostics,
        &report_staging,
        "integration primary failure".to_owned(),
        Deadlines {
            execution: expired,
            completion: expired,
            cleanup: expired,
        },
    )
    .map(|_| ())
}

fn transaction_fixture_json(state: &str) -> JsonValue {
    object([("schemaVersion", number(1)), ("state", string(state))])
}

fn bounded_text(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        if output
            .len()
            .checked_add(character.len_utf8())
            .is_none_or(|length| length > MAX_RETAINED_DIAGNOSTIC_BYTES)
        {
            break;
        }
        output.push(character);
    }
    output
}

fn staging_path(output: &Path) -> Result<PathBuf, String> {
    let parent = output
        .parent()
        .ok_or_else(|| "final verification output has no parent".to_owned())?;
    let name = output
        .file_name()
        .ok_or_else(|| "final verification output has no filename".to_owned())?;
    let mut staging_name = OsString::from(".final-verify-");
    staging_name.push(name);
    staging_name.push(format!("-{}", std::process::id()));
    Ok(parent.join(staging_name))
}

fn install_bundle(source: &Path, destination: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("cannot inspect assembled bundle: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("assembled bundle is not a real directory".to_owned());
    }
    for entry in fs::read_dir(source)
        .map_err(|error| format!("cannot enumerate assembled bundle: {error}"))?
    {
        let entry = entry.map_err(|error| format!("cannot inspect assembled bundle: {error}"))?;
        let metadata = entry
            .file_type()
            .map_err(|error| format!("cannot inspect assembled bundle entry: {error}"))?;
        if !metadata.is_file() || metadata.is_symlink() {
            return Err("assembled bundle contains a non-regular top-level entry".to_owned());
        }
        let bytes = read_regular(&entry.path())?;
        write_atomic_new(&destination.join(entry.file_name()), &bytes)?;
    }
    Ok(())
}

fn write_publication_envelope(
    options: &Options,
    output: &Path,
    primary: &VerifierDecision,
    independent: &VerifierDecision,
) -> Result<(), String> {
    let plan = ReleasePlan::parse(&read_json(&options.plan)?)?;
    let materials = publication_envelope_materials(options, output, primary, independent)?;
    let envelope = publication_envelope(options, &plan, primary, &materials)?;
    fuzz_parse_publication_envelope(&envelope)?;
    write_json(&output.join("publication-envelope.json"), &envelope)?;
    Ok(())
}

struct PublicationEnvelopeMaterials {
    independent_decision: String,
    primary_decision: String,
    subject_manifest: String,
    verifier_agreement: String,
    release_gate: String,
}

fn publication_envelope_materials(
    options: &Options,
    output: &Path,
    primary: &VerifierDecision,
    independent: &VerifierDecision,
) -> Result<PublicationEnvelopeMaterials, String> {
    let primary_bytes = canonical_json_bytes(&primary.json())?;
    let independent_bytes = canonical_json_bytes(&independent.json())?;
    let bundle_manifest = read_regular(&options.bundle.join("SUBJECTS.sha256"))?;
    let agreement = read_regular(&output.join("verifier-agreement.json"))?;
    let gate = read_json(&options.bundle.join("release-gate.json"))?;
    Ok(PublicationEnvelopeMaterials {
        independent_decision: hell_testkit::sha256_bytes(&independent_bytes).hex(),
        primary_decision: hell_testkit::sha256_bytes(&primary_bytes).hex(),
        subject_manifest: hell_testkit::sha256_bytes(&bundle_manifest).hex(),
        verifier_agreement: hell_testkit::sha256_bytes(&agreement).hex(),
        release_gate: json_member(gate.object()?, "releaseGateSha256")?
            .string()?
            .to_owned(),
    })
}

fn publication_envelope(
    options: &Options,
    plan: &ReleasePlan,
    primary: &VerifierDecision,
    materials: &PublicationEnvelopeMaterials,
) -> Result<JsonValue, String> {
    Ok(object([
        ("admitted", JsonValue::Bool(true)),
        (
            "assembledArtifactDigest",
            string(&options.expected_artifact_digest),
        ),
        ("candidateSha", string(&plan.resolution.candidate_sha)),
        ("cellLedgerSha256", string(&primary.cell_ledger_sha256)),
        (
            "conformancePlanSha256",
            string(&plan.conformance_plan_sha256),
        ),
        (
            "evaluationInstant",
            string(&plan.release_evaluation_instant),
        ),
        ("externalInputsSha256", string(&plan.external_inputs_sha256)),
        (
            "governanceDeclarationSha256",
            string(&plan.governance_declaration_sha256),
        ),
        (
            "governanceProfileSha256",
            string(&plan.governance_profile_sha256),
        ),
        (
            "governancePostAssemblySha256",
            string(&primary.governance_post_assembly_sha256),
        ),
        (
            "governancePreAttestationSha256",
            string(&primary.governance_pre_attestation_sha256),
        ),
        (
            "governanceResolveSha256",
            string(&primary.governance_resolve_sha256),
        ),
        (
            "independentVerifierDecisionSha256",
            string(&materials.independent_decision),
        ),
        (
            "primaryVerifierDecisionSha256",
            string(&materials.primary_decision),
        ),
        (
            "nativeEnvironmentSetSha256",
            string(&primary.native_environment_set_sha256),
        ),
        (
            "obligationRulesSha256",
            string(&primary.obligation_rules_sha256),
        ),
        ("protocolSha256", string(&primary.protocol_sha256)),
        ("protocolVersion", string(&primary.protocol_version)),
        ("releaseGateSha256", string(&materials.release_gate)),
        ("releasePlanSha256", string(&plan.plan_sha256)),
        ("repositoryId", number(plan.resolution.repository_id)),
        (
            "repositoryName",
            string(repository_name(&plan.resolution.repository)?),
        ),
        (
            "repositoryOwner",
            string(repository_owner(&plan.resolution.repository)?),
        ),
        ("schemaVersion", number(1)),
        ("sourceDateEpoch", number(plan.source_date_epoch)),
        (
            "sourceInventorySha256",
            string(&plan.source_inventory_sha256),
        ),
        (
            "residualAssumptionSetSha256",
            string(&plan.residual_assumption_set_sha256),
        ),
        ("subjectManifestSha256", string(&materials.subject_manifest)),
        ("tag", string(&plan.tag)),
        (
            "trustedInputsSha256",
            string(&plan.trusted_conformance_inputs_sha256),
        ),
        (
            "verifierAgreementSha256",
            string(&materials.verifier_agreement),
        ),
        ("version", string(&plan.version)),
        ("workflowSha", string(&plan.resolution.workflow_sha)),
    ]))
}

pub(crate) fn fuzz_parse_publication_envelope(envelope: &JsonValue) -> Result<(), String> {
    let fields = envelope.object()?;
    crate::json::require_exact_json_keys(
        fields,
        &[
            "admitted",
            "assembledArtifactDigest",
            "candidateSha",
            "cellLedgerSha256",
            "conformancePlanSha256",
            "evaluationInstant",
            "externalInputsSha256",
            "governanceDeclarationSha256",
            "governancePostAssemblySha256",
            "governancePreAttestationSha256",
            "governanceProfileSha256",
            "governanceResolveSha256",
            "independentVerifierDecisionSha256",
            "nativeEnvironmentSetSha256",
            "obligationRulesSha256",
            "primaryVerifierDecisionSha256",
            "protocolSha256",
            "protocolVersion",
            "releaseGateSha256",
            "releasePlanSha256",
            "repositoryId",
            "repositoryName",
            "repositoryOwner",
            "residualAssumptionSetSha256",
            "schemaVersion",
            "sourceDateEpoch",
            "sourceInventorySha256",
            "subjectManifestSha256",
            "tag",
            "trustedInputsSha256",
            "verifierAgreementSha256",
            "version",
            "workflowSha",
        ],
    )?;
    if json_member(fields, "schemaVersion")?.number()? != 1
        || !json_member(fields, "admitted")?.boolean()?
        || json_member(fields, "repositoryId")?.number()? == 0
    {
        return Err("publication envelope state or repository identity is invalid".to_owned());
    }
    super::schema::require_sha(
        json_member(fields, "candidateSha")?.string()?,
        "candidate SHA",
    )?;
    super::schema::require_sha(
        json_member(fields, "workflowSha")?.string()?,
        "workflow SHA",
    )?;
    for name in [
        "assembledArtifactDigest",
        "cellLedgerSha256",
        "conformancePlanSha256",
        "externalInputsSha256",
        "governanceDeclarationSha256",
        "governancePostAssemblySha256",
        "governancePreAttestationSha256",
        "governanceProfileSha256",
        "governanceResolveSha256",
        "independentVerifierDecisionSha256",
        "nativeEnvironmentSetSha256",
        "obligationRulesSha256",
        "primaryVerifierDecisionSha256",
        "protocolSha256",
        "releaseGateSha256",
        "releasePlanSha256",
        "residualAssumptionSetSha256",
        "sourceInventorySha256",
        "subjectManifestSha256",
        "trustedInputsSha256",
        "verifierAgreementSha256",
    ] {
        super::schema::require_digest(json_member(fields, name)?.string()?, name)?;
    }
    for name in [
        "evaluationInstant",
        "protocolVersion",
        "repositoryName",
        "repositoryOwner",
        "tag",
        "version",
    ] {
        if json_member(fields, name)?.string()?.is_empty() {
            return Err(format!("publication envelope field {name} is empty"));
        }
    }
    json_member(fields, "sourceDateEpoch")?.number()?;
    Ok(())
}

fn repository_owner(repository: &str) -> Result<&str, String> {
    repository
        .split_once('/')
        .map(|(owner, _)| owner)
        .filter(|owner| !owner.is_empty())
        .ok_or_else(|| "release repository identity is malformed".to_owned())
}

fn repository_name(repository: &str) -> Result<&str, String> {
    repository
        .split_once('/')
        .map(|(_, name)| name)
        .filter(|name| !name.is_empty() && !name.contains('/'))
        .ok_or_else(|| "release repository identity is malformed".to_owned())
}
