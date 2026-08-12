use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use hell_testkit::{Digest, sha256_bytes, sha256_file};

const UPSTREAM_COMMIT: &str = "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff";

#[derive(Default)]
struct Options {
    source: Option<PathBuf>,
    output: Option<PathBuf>,
    platform: Option<String>,
    builder: Option<String>,
    trust_domain: Option<String>,
    run_identity: Option<String>,
    candidate: Option<String>,
    epoch: Option<String>,
    epoch_file: Option<PathBuf>,
    first: Option<PathBuf>,
    second: Option<PathBuf>,
    exercised: Option<PathBuf>,
    exercised_receipt: Option<PathBuf>,
    first_receipt: Option<PathBuf>,
    second_receipt: Option<PathBuf>,
    role: Option<String>,
    reviewer: Option<String>,
    issued_at: Option<String>,
    ordinal: Option<String>,
    comparison: Option<PathBuf>,
    review: Option<PathBuf>,
    trigger_actor_id: Option<String>,
    trigger_actor_login: Option<String>,
    trigger_repository_id: Option<String>,
    trigger_run_id: Option<String>,
    trigger_run_attempt: Option<String>,
    trigger_workflow_ref: Option<String>,
    trigger_event: Option<String>,
}

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments.first().is_some_and(|value| value == "oracle-ops")
}

fn path_from_components<const N: usize>(components: [&str; N]) -> PathBuf {
    components
        .into_iter()
        .fold(PathBuf::new(), |path, component| path.join(component))
}

pub(crate) fn run(arguments: &[OsString]) -> Result<String, String> {
    if let Some(action) = arguments.get(1).and_then(|value| value.to_str())
        && action.starts_with("workflow-")
    {
        return run_workflow_action(action);
    }
    let (action, options) = parse(arguments)?;
    match action.as_str() {
        "build" => build(&options),
        "verify-build" => verify_build(required(options.output.as_ref(), "--output")?),
        "compare" => compare(&options),
        "packet" => packet(&options),
        "gate-record" => gate_record(&options),
        action => Err(format!("unknown oracle-ops action {action:?}")),
    }
}

fn run_workflow_action(action: &str) -> Result<String, String> {
    let (operation, platform) = action
        .rsplit_once('-')
        .ok_or_else(|| "oracle workflow action lacks a platform".to_owned())?;
    let (platform, executable) = match platform {
        "macos" => ("macos-arm64", "hell"),
        "windows" => ("windows-amd64", "hell.exe"),
        _ => return Err("oracle workflow action has an unsupported platform".to_owned()),
    };
    match operation {
        "workflow-primary-build" => workflow_build(platform, true),
        "workflow-independent-build" => workflow_build(platform, false),
        "workflow-primary-packet" => workflow_builder_packet(platform, true),
        "workflow-independent-packet" => workflow_builder_packet(platform, false),
        "workflow-primary-resolve" => workflow_resolve_unsigned(platform, true),
        "workflow-independent-resolve" => workflow_resolve_unsigned(platform, false),
        "workflow-primary-select" => workflow_select_unsigned(platform, true),
        "workflow-independent-select" => workflow_select_unsigned(platform, false),
        "workflow-compare" => compare(&workflow_compare_options(platform, executable)),
        "workflow-platform-packet" => packet(&workflow_platform_packet_options(platform)),
        "workflow-gate" => gate_record(&workflow_gate_options(platform, executable)),
        _ => Err("unknown oracle workflow action".to_owned()),
    }
}

fn unsigned_artifact_name(platform: &str, primary: bool) -> String {
    format!(
        "ephemeralEvidence-oracle-{}-unsigned-{platform}",
        if primary { "primary" } else { "independent" }
    )
}

fn workflow_resolve_unsigned(platform: &str, primary: bool) -> Result<String, String> {
    let run_id = github_positive("GITHUB_RUN_ID")?;
    let selection = path_from_components([
        "provider-out",
        if primary { "primary" } else { "independent" },
    ])
    .join(platform);
    fs::create_dir_all(&selection)
        .map_err(|error| format!("cannot create oracle provider selection directory: {error}"))?;
    let artifact = crate::assurance::resolve_provider_artifact_for_workflow(
        &run_id,
        &unsigned_artifact_name(platform, primary),
        &selection.join("provider-artifact-list.json"),
    )?;
    write_positive_github_output("artifact_id", artifact.artifact_id)?;
    write_github_output("artifact_digest", &artifact.archive_sha256)?;
    Ok(format!(
        "resolved exact unsigned oracle artifact ID {}",
        artifact.artifact_id
    ))
}

fn workflow_select_unsigned(platform: &str, primary: bool) -> Result<String, String> {
    let input = path_from_components(["ci-out"]);
    let build = input.join(if primary {
        "oracle-primary"
    } else {
        "oracle-independent"
    });
    verify_build(&build)?;
    let subject = fs::read_to_string(build.join("builder-subject.json"))
        .map_err(|error| format!("cannot read selected oracle builder subject: {error}"))?;
    let candidate = subject_field(&subject, "candidateCommit")?;
    let expected_directory_sha256 = crate::custody_ops::directory_digest(&input)?;
    let output = path_from_components([
        "provider-out",
        if primary { "primary" } else { "independent" },
    ])
    .join(platform);
    let artifact_id = github_positive("ORACLE_UNSIGNED_ARTIFACT_ID")?
        .parse::<u64>()
        .map_err(|_| "unsigned oracle artifact ID is invalid".to_owned())?;
    let expected_archive_sha256 = github_value("ORACLE_UNSIGNED_ARCHIVE_SHA256")?;
    let provider_head = github_value("GITHUB_SHA")?;
    let run_id = github_positive("GITHUB_RUN_ID")?
        .parse::<u64>()
        .map_err(|_| "oracle provider run ID is invalid".to_owned())?;
    let run_attempt = github_positive("GITHUB_RUN_ATTEMPT")?
        .parse::<u64>()
        .map_err(|_| "oracle provider run attempt is invalid".to_owned())?;
    let selection = crate::assurance::verify_provider_artifact_selection_subject_to(
        &crate::assurance::ProviderArtifactSelectionSubject {
            root: Path::new("."),
            input_directory: &input,
            output_directory: &output,
            artifact_name: &unsigned_artifact_name(platform, primary),
            workflow_path: ".github/workflows/oracle-reproduce.yml",
            event_name: "workflow_dispatch",
            run_id,
            run_attempt,
            artifact_id,
            provider_head: &provider_head,
            candidate: &candidate,
            expected_directory_sha256: &expected_directory_sha256,
            expected_archive_sha256: &expected_archive_sha256,
        },
    )?;
    let selection_path = build.join("unsigned-provider-selection.json");
    write_atomic(&selection_path, selection.as_bytes())?;
    for name in [
        "provider-artifact-list.json",
        "provider-selected-artifact.json",
        "provider-selected-run.json",
    ] {
        let source = output.join(name);
        let bytes = fs::read(&source).map_err(|error| {
            format!(
                "cannot retain oracle provider fact {}: {error}",
                source.display()
            )
        })?;
        write_atomic(&build.join(name), &bytes)?;
    }
    Ok("verified exact immutable unsigned oracle artifact selection".to_owned())
}

fn write_positive_github_output(key: &str, value: u64) -> Result<(), String> {
    if value == 0 {
        return Err("GitHub provider output must be nonzero".to_owned());
    }
    require_atom(key, "GitHub output key")?;
    let path = std::env::var_os("GITHUB_OUTPUT")
        .ok_or_else(|| "GITHUB_OUTPUT is unavailable".to_owned())?;
    let mut output = fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .map_err(|error| format!("cannot open GITHUB_OUTPUT: {error}"))?;
    writeln!(output, "{key}={value}")
        .map_err(|error| format!("cannot write GITHUB_OUTPUT: {error}"))
}

fn write_github_output(key: &str, value: &str) -> Result<(), String> {
    require_atom(key, "GitHub output key")?;
    require_atom(value, "GitHub output value")?;
    let path = std::env::var_os("GITHUB_OUTPUT")
        .ok_or_else(|| "GITHUB_OUTPUT is unavailable".to_owned())?;
    let mut output = fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .map_err(|error| format!("cannot open GITHUB_OUTPUT: {error}"))?;
    writeln!(output, "{key}={value}")
        .map_err(|error| format!("cannot write GITHUB_OUTPUT: {error}"))
}

fn workflow_compare_options(platform: &str, executable: &str) -> Options {
    Options {
        platform: Some(platform.to_owned()),
        first: Some(path_from_components([
            "ci-out",
            "primary",
            "oracle-primary",
        ])),
        second: Some(path_from_components([
            "ci-out",
            "independent-transport",
            "oracle-independent",
        ])),
        first_receipt: Some(path_from_components([
            "ci-out",
            "primary",
            "oracle-primary",
            "builder-receipt.dsse.json",
        ])),
        second_receipt: Some(path_from_components([
            "ci-out",
            "independent-transport",
            "oracle-independent",
            "builder-receipt.dsse.json",
        ])),
        exercised: Some(
            path_from_components(["ci-out", "primary", "native-shard", "oracle"])
                .join(platform)
                .join(executable),
        ),
        exercised_receipt: Some(path_from_components([
            "ci-out",
            "primary",
            "native-shard",
            "summary.json",
        ])),
        output: Some(path_from_components([
            "ci-out",
            "oracle-reproducibility.json",
        ])),
        ..Options::default()
    }
}

fn workflow_platform_packet_options(platform: &str) -> Options {
    Options {
        platform: Some(platform.to_owned()),
        first: Some(path_from_components([
            "ci-out",
            "oracle-reproducibility.json",
        ])),
        output: Some(path_from_components([
            "ci-out",
            "platform-review-packet.json",
        ])),
        role: Some("platform-reviewer".to_owned()),
        reviewer: Some(format!("platform-reviewer:{platform}")),
        ..Options::default()
    }
}

fn workflow_gate_options(platform: &str, executable: &str) -> Options {
    let mut options = workflow_compare_options(platform, executable);
    let subject = path_from_components(["ci-out", "provider-subject"]);
    options.first = Some(subject.join("primary").join("oracle-primary"));
    options.second = Some(
        subject
            .join("independent-transport")
            .join("oracle-independent"),
    );
    options.first_receipt = Some(
        subject
            .join("primary")
            .join("oracle-primary")
            .join("builder-receipt.dsse.json"),
    );
    options.second_receipt = Some(
        subject
            .join("independent-transport")
            .join("oracle-independent")
            .join("builder-receipt.dsse.json"),
    );
    options.exercised = Some(
        subject
            .join("primary")
            .join("native-shard")
            .join("oracle")
            .join(platform)
            .join(executable),
    );
    options.exercised_receipt = Some(
        subject
            .join("primary")
            .join("native-shard")
            .join("summary.json"),
    );
    options.source = Some(path_from_components(["ci-out", "oracle-source"]));
    options.comparison = Some(subject.join("oracle-reproducibility.json"));
    options.review = Some(path_from_components([
        "ci-out",
        "platform-review.dsse.json",
    ]));
    options.output = Some(path_from_components(["ci-out", "oracle-provenance.json"]));
    options
}

fn workflow_build(platform: &str, primary: bool) -> Result<String, String> {
    let run_id = github_value("GITHUB_RUN_ID")?;
    let run_attempt = github_value("GITHUB_RUN_ATTEMPT")?;
    let mut options = Options {
        source: Some(path_from_components(["target", "oracle-source"])),
        output: Some(path_from_components([
            "ci-out",
            if primary {
                "oracle-primary"
            } else {
                "oracle-independent"
            },
        ])),
        platform: Some(platform.to_owned()),
        builder: Some(
            if primary {
                "github-protected-primary"
            } else {
                "externally-administered-builder"
            }
            .to_owned(),
        ),
        trust_domain: Some(
            if primary {
                "organization-primary"
            } else {
                "organization-independent"
            }
            .to_owned(),
        ),
        run_identity: Some(format!(
            "{run_id}-{run_attempt}-{}-{platform}",
            if primary { "primary" } else { "independent" }
        )),
        epoch_file: Some(path_from_components(["ci-out", "assurance-epoch.json"])),
        trigger_actor_id: Some(github_positive("GITHUB_ACTOR_ID")?),
        trigger_actor_login: Some(github_value("GITHUB_ACTOR")?),
        trigger_repository_id: Some(github_positive("GITHUB_REPOSITORY_ID")?),
        trigger_run_id: Some(run_id),
        trigger_run_attempt: Some(run_attempt),
        trigger_workflow_ref: Some(github_value("GITHUB_WORKFLOW_REF")?),
        trigger_event: Some(github_value("GITHUB_EVENT_NAME")?),
        ..Options::default()
    };
    options.candidate = Some(github_value("GITHUB_SHA")?);
    build(&options)
}

fn workflow_builder_packet(platform: &str, primary: bool) -> Result<String, String> {
    let directory = path_from_components([
        "ci-out",
        if primary {
            "oracle-primary"
        } else {
            "oracle-independent"
        },
    ]);
    packet(&Options {
        first: Some(directory.join("builder-subject.json")),
        output: Some(directory.join("builder-packet.json")),
        role: Some("oracle-builder".to_owned()),
        ordinal: Some(if primary { "first" } else { "second" }.to_owned()),
        reviewer: Some(format!(
            "oracle-builder:{}-{platform}",
            if primary { "primary" } else { "independent" }
        )),
        ..Options::default()
    })
}

fn github_value(name: &str) -> Result<String, String> {
    let value = std::env::var(name).map_err(|_| format!("{name} is unavailable"))?;
    require_atom(&value, name)?;
    Ok(value)
}

fn github_positive(name: &str) -> Result<String, String> {
    let value = github_value(name)?;
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| format!("{name} is not a positive provider identity"))?;
    Ok(value)
}

fn parse(arguments: &[OsString]) -> Result<(String, Options), String> {
    let action = arguments
        .get(1)
        .and_then(|value| value.to_str())
        .ok_or_else(|| "oracle-ops requires build or verify-build".to_owned())?
        .to_owned();
    let mut options = Options::default();
    let mut index = 2;
    while index < arguments.len() {
        let flag = arguments[index]
            .to_str()
            .ok_or_else(|| "oracle-ops option must be UTF-8".to_owned())?;
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match flag {
            "--source" => set_path(&mut options.source, value, flag)?,
            "--output" => set_path(&mut options.output, value, flag)?,
            "--platform" => set_text(&mut options.platform, value, flag)?,
            "--builder" => set_text(&mut options.builder, value, flag)?,
            "--trust-domain" => set_text(&mut options.trust_domain, value, flag)?,
            "--run-identity" => set_text(&mut options.run_identity, value, flag)?,
            "--candidate" => set_text(&mut options.candidate, value, flag)?,
            "--epoch" => set_text(&mut options.epoch, value, flag)?,
            "--epoch-file" => set_path(&mut options.epoch_file, value, flag)?,
            "--first" => set_path(&mut options.first, value, flag)?,
            "--second" => set_path(&mut options.second, value, flag)?,
            "--exercised" => set_path(&mut options.exercised, value, flag)?,
            "--exercised-receipt" => set_path(&mut options.exercised_receipt, value, flag)?,
            "--first-receipt" => set_path(&mut options.first_receipt, value, flag)?,
            "--second-receipt" => set_path(&mut options.second_receipt, value, flag)?,
            "--role" => set_text(&mut options.role, value, flag)?,
            "--reviewer" => set_text(&mut options.reviewer, value, flag)?,
            "--issued-at" => set_text(&mut options.issued_at, value, flag)?,
            "--ordinal" => set_text(&mut options.ordinal, value, flag)?,
            "--comparison" => set_path(&mut options.comparison, value, flag)?,
            "--review" => set_path(&mut options.review, value, flag)?,
            "--trigger-actor-id" => set_text(&mut options.trigger_actor_id, value, flag)?,
            "--trigger-actor-login" => set_text(&mut options.trigger_actor_login, value, flag)?,
            "--trigger-repository-id" => {
                set_text(&mut options.trigger_repository_id, value, flag)?;
            }
            "--trigger-run-id" => set_text(&mut options.trigger_run_id, value, flag)?,
            "--trigger-run-attempt" => {
                set_text(&mut options.trigger_run_attempt, value, flag)?;
            }
            "--trigger-workflow-ref" => {
                set_text(&mut options.trigger_workflow_ref, value, flag)?;
            }
            "--trigger-event" => set_text(&mut options.trigger_event, value, flag)?,
            _ => return Err(format!("unknown oracle-ops option {flag:?}")),
        }
        index += 2;
    }
    Ok((action, options))
}

#[allow(clippy::too_many_lines)]
fn gate_record(options: &Options) -> Result<String, String> {
    let first = required(options.first.as_ref(), "--first")?;
    let second = required(options.second.as_ref(), "--second")?;
    let first_receipt = required(options.first_receipt.as_ref(), "--first-receipt")?;
    let second_receipt = required(options.second_receipt.as_ref(), "--second-receipt")?;
    let exercised = required(options.exercised.as_ref(), "--exercised")?;
    let source = required(options.source.as_ref(), "--source")?;
    let comparison = required(options.comparison.as_ref(), "--comparison")?;
    let review = required(options.review.as_ref(), "--review")?;
    let output = required(options.output.as_ref(), "--output")?;
    let record_root = output
        .parent()
        .ok_or_else(|| "oracle gate output has no retained root".to_owned())?;
    let first_subject = fs::read_to_string(first.join("builder-subject.json"))
        .map_err(|error| format!("cannot read first builder subject: {error}"))?;
    let second_subject = fs::read_to_string(second.join("builder-subject.json"))
        .map_err(|error| format!("cannot read second builder subject: {error}"))?;
    let comparison_document = fs::read_to_string(comparison)
        .map_err(|error| format!("cannot read oracle comparison: {error}"))?;
    validate_comparison_document(&comparison_document)?;
    if subject_field(&comparison_document, "reproducibility")? != "exact"
        || !comparison_document.contains("\"exercisedBinaryBinding\": true")
        || !comparison_document.contains("\"policyFindings\": []")
    {
        return Err("oracle comparison is not an exact, policy-clean exercised build".to_owned());
    }
    let source_commit = command_text(source, "git", &["rev-parse", "HEAD"])?;
    let source_tree = command_text(source, "git", &["rev-parse", "HEAD^{tree}"])?;
    if source_commit != UPSTREAM_COMMIT
        || !command_text(source, "git", &["status", "--porcelain=v2"])?.is_empty()
    {
        return Err("oracle gate source is not the clean pinned tree".to_owned());
    }
    let first_binary = first
        .join("binary")
        .join(if cfg!(windows) { "hell.exe" } else { "hell" });
    let second_binary = second
        .join("binary")
        .join(if cfg!(windows) { "hell.exe" } else { "hell" });
    let paths = [
        (
            "firstBuilderSubjectPath",
            "firstBuilderSubjectSha256",
            first.join("builder-subject.json"),
        ),
        (
            "secondBuilderSubjectPath",
            "secondBuilderSubjectSha256",
            second.join("builder-subject.json"),
        ),
        (
            "firstAcquisitionReceiptPath",
            "firstAcquisitionReceiptSha256",
            first.join("acquisition-receipt.json"),
        ),
        (
            "secondAcquisitionReceiptPath",
            "secondAcquisitionReceiptSha256",
            second.join("acquisition-receipt.json"),
        ),
        (
            "buildPlanPath",
            "buildPlanSha256",
            first.join("build-plan.json"),
        ),
        (
            "sourceFilesPath",
            "sourceFilesSha256",
            first.join("source-files.json"),
        ),
        (
            "sourceArchivePath",
            "sourceArchiveSha256",
            first.join("source-archive.tar"),
        ),
        ("sbomPath", "sbomSha256", first.join("sbom.spdx.json")),
        (
            "networkInventoryPath",
            "networkInventorySha256",
            first.join("network-inventory.json"),
        ),
        (
            "firstEnvironmentPath",
            "firstEnvironmentSha256",
            first.join("environment.json"),
        ),
        (
            "secondEnvironmentPath",
            "secondEnvironmentSha256",
            second.join("environment.json"),
        ),
        (
            "firstProvenancePolicyPath",
            "firstProvenancePolicySha256",
            first.join("provenance-policy.json"),
        ),
        (
            "secondProvenancePolicyPath",
            "secondProvenancePolicySha256",
            second.join("provenance-policy.json"),
        ),
        ("firstBinaryPath", "firstBinarySha256", first_binary),
        (
            "firstBuildReceiptPath",
            "firstBuildReceiptSha256",
            first_receipt.to_path_buf(),
        ),
        ("secondBinaryPath", "secondBinarySha256", second_binary),
        (
            "secondBuildReceiptPath",
            "secondBuildReceiptSha256",
            second_receipt.to_path_buf(),
        ),
        (
            "exercisedBinaryPath",
            "exercisedBinarySha256",
            exercised.to_path_buf(),
        ),
        (
            "comparisonPath",
            "comparisonSha256",
            comparison.to_path_buf(),
        ),
        (
            "platformReviewPath",
            "platformReviewSha256",
            review.to_path_buf(),
        ),
    ];
    let mut record = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in [
        (
            "candidateCommit",
            subject_field(&first_subject, "candidateCommit")?,
        ),
        (
            "assuranceEpochSha256",
            subject_field(&first_subject, "assuranceEpochSha256")?,
        ),
        ("platform", subject_field(&first_subject, "platform")?),
        ("sourceCommit", source_commit),
        ("sourceTree", source_tree),
        ("sourcePath", retained_relative(record_root, source)?),
        (
            "firstBuilderTrustDomain",
            subject_field(&first_subject, "trustDomain")?,
        ),
        (
            "firstRunIdentity",
            subject_field(&first_subject, "runIdentity")?,
        ),
        (
            "firstTriggerActorId",
            subject_field(&first_subject, "triggerActorId")?,
        ),
        (
            "firstTriggerActorLogin",
            subject_field(&first_subject, "triggerActorLogin")?,
        ),
        (
            "firstTriggerRepositoryId",
            subject_field(&first_subject, "triggerRepositoryId")?,
        ),
        (
            "firstTriggerRunId",
            subject_field(&first_subject, "triggerRunId")?,
        ),
        (
            "firstTriggerRunAttempt",
            subject_field(&first_subject, "triggerRunAttempt")?,
        ),
        (
            "firstTriggerWorkflowRef",
            subject_field(&first_subject, "triggerWorkflowRef")?,
        ),
        (
            "firstTriggerEvent",
            subject_field(&first_subject, "triggerEvent")?,
        ),
        (
            "secondBuilderTrustDomain",
            subject_field(&second_subject, "trustDomain")?,
        ),
        (
            "secondRunIdentity",
            subject_field(&second_subject, "runIdentity")?,
        ),
        (
            "secondTriggerActorId",
            subject_field(&second_subject, "triggerActorId")?,
        ),
        (
            "secondTriggerActorLogin",
            subject_field(&second_subject, "triggerActorLogin")?,
        ),
        (
            "secondTriggerRepositoryId",
            subject_field(&second_subject, "triggerRepositoryId")?,
        ),
        (
            "secondTriggerRunId",
            subject_field(&second_subject, "triggerRunId")?,
        ),
        (
            "secondTriggerRunAttempt",
            subject_field(&second_subject, "triggerRunAttempt")?,
        ),
        (
            "secondTriggerWorkflowRef",
            subject_field(&second_subject, "triggerWorkflowRef")?,
        ),
        (
            "secondTriggerEvent",
            subject_field(&second_subject, "triggerEvent")?,
        ),
        (
            "semanticFingerprintSha256",
            subject_field(&comparison_document, "semanticFingerprintSha256")?,
        ),
    ] {
        record.push_str(",\n  \"");
        record.push_str(field);
        record.push_str("\": ");
        push_json(&mut record, &value);
    }
    for (path_field, digest_field, path) in paths {
        record.push_str(",\n  \"");
        record.push_str(path_field);
        record.push_str("\": ");
        push_json(&mut record, &retained_relative(record_root, &path)?);
        record.push_str(",\n  \"");
        record.push_str(digest_field);
        record.push_str("\": ");
        push_json(
            &mut record,
            &sha256_file(&path).map_err(|error| error.to_string())?.hex(),
        );
    }
    record.push_str(",\n  \"sourceTreeClean\": true,\n  \"reproducibility\": \"exact\",\n  \"policyFindings\": []\n}\n");
    write_atomic(output, record.as_bytes())?;
    Ok(format!(
        "wrote strict oracle provenance gate record {}",
        output.display()
    ))
}

fn retained_relative(root: &Path, path: &Path) -> Result<String, String> {
    let relative = path.strip_prefix(root).map_err(|_| {
        format!(
            "retained record {} is outside {}",
            path.display(),
            root.display()
        )
    })?;
    let mut output = String::new();
    for (index, component) in relative.components().enumerate() {
        if index != 0 {
            output.push('/');
        }
        let value = component
            .as_os_str()
            .to_str()
            .ok_or_else(|| format!("retained path {} is not UTF-8", path.display()))?;
        require_atom(value, "retained path component")?;
        output.push_str(value);
    }
    if output.is_empty() {
        Err("retained record path is empty".to_owned())
    } else {
        Ok(output)
    }
}

fn packet(options: &Options) -> Result<String, String> {
    let input = required(options.first.as_ref(), "--first")?;
    let output = required(options.output.as_ref(), "--output")?;
    let role = required_text(options.role.as_ref(), "--role")?;
    let reviewer = required_text(options.reviewer.as_ref(), "--reviewer")?;
    let generated_issued_at;
    let issued_at = if let Some(issued_at) = options.issued_at.as_deref() {
        issued_at
    } else {
        generated_issued_at = current_utc_timestamp()?;
        &generated_issued_at
    };
    if !reviewer.starts_with(&format!("{role}:")) {
        return Err("oracle packet reviewer does not match role".to_owned());
    }
    validate_utc_timestamp(issued_at)?;
    let document = fs::read_to_string(input).map_err(|error| {
        format!(
            "cannot read oracle packet input {}: {error}",
            input.display()
        )
    })?;
    let candidate = subject_field(&document, "candidateCommit")?;
    let epoch = subject_field(&document, "assuranceEpochSha256")?;
    let artifacts = match role {
        "oracle-builder" => {
            let ordinal = required_text(options.ordinal.as_ref(), "--ordinal")?;
            builder_reviewed_artifacts(
                &document,
                ordinal,
                input
                    .parent()
                    .ok_or_else(|| "oracle builder subject has no retained directory".to_owned())?,
            )?
            .into_iter()
            .collect()
        }
        "platform-reviewer" => [
            "firstAcquisitionReceiptSha256",
            "secondAcquisitionReceiptSha256",
            "buildPlanSha256",
            "sbomSha256",
            "networkInventorySha256",
            "firstEnvironmentSha256",
            "secondEnvironmentSha256",
            "firstProvenancePolicySha256",
            "secondProvenancePolicySha256",
            "firstBinarySha256",
            "secondBinarySha256",
            "exercisedBinarySha256",
            "firstBuildReceiptSha256",
            "secondBuildReceiptSha256",
            "semanticFingerprintSha256",
        ]
        .into_iter()
        .map(|field| subject_field(&document, field))
        .chain(std::iter::once(Ok(sha256_bytes(document.as_bytes()).hex())))
        .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(
                "oracle packet role must be oracle-builder or platform-reviewer".to_owned(),
            );
        }
    };
    let result = render_review_packet(role, reviewer, issued_at, &candidate, &epoch, &artifacts);
    write_atomic(output, result.as_bytes())?;
    Ok(format!(
        "wrote content-bound oracle {role} packet at {}",
        output.display()
    ))
}

fn builder_reviewed_artifacts(
    document: &str,
    ordinal: &str,
    directory: &Path,
) -> Result<BTreeSet<String>, String> {
    let artifacts = [
        subject_field(document, "acquisitionReceiptSha256")?,
        subject_field(document, "buildPlanSha256")?,
        subject_field(document, "sbomSha256")?,
        subject_field(document, "networkInventorySha256")?,
        subject_field(document, "environmentSha256")?,
        subject_field(document, "provenancePolicySha256")?,
        oracle_subject_digest(document, ordinal)?,
        sha256_file(&directory.join("unsigned-provider-selection.json"))
            .map_err(|error| error.to_string())?
            .hex(),
    ];
    let artifacts = artifacts.into_iter().collect::<BTreeSet<_>>();
    if artifacts.len() != 8 {
        return Err("oracle builder reviewed artifacts are not distinct".to_owned());
    }
    Ok(artifacts)
}

fn validate_comparison_document(document: &str) -> Result<(), String> {
    let fields = [
        "candidateCommit",
        "assuranceEpochSha256",
        "platform",
        "sourceCommit",
        "sourceTree",
        "firstAcquisitionReceiptSha256",
        "secondAcquisitionReceiptSha256",
        "buildPlanSha256",
        "sbomSha256",
        "networkInventorySha256",
        "firstEnvironmentSha256",
        "secondEnvironmentSha256",
        "firstProvenancePolicySha256",
        "secondProvenancePolicySha256",
        "binarySha256",
        "firstBinarySha256",
        "secondBinarySha256",
        "exercisedBinarySha256",
        "firstBuilder",
        "firstBuilderTrustDomain",
        "firstRunIdentity",
        "secondBuilder",
        "secondBuilderTrustDomain",
        "secondRunIdentity",
        "firstBuildReceiptSha256",
        "secondBuildReceiptSha256",
        "semanticFingerprintSha256",
    ];
    let mut canonical = String::from("{\n  \"schemaVersion\": 1");
    for field in fields {
        canonical.push_str(",\n  \"");
        canonical.push_str(field);
        canonical.push_str("\": ");
        push_json(&mut canonical, &subject_field(document, field)?);
    }
    canonical.push_str(",\n  \"reproducibility\": \"exact\",\n  \"exercisedBinaryBinding\": true,\n  \"policyFindings\": []\n}\n");
    if canonical == document {
        Ok(())
    } else {
        Err(
            "oracle comparison is not exact canonical JSON or has unknown/duplicate fields"
                .to_owned(),
        )
    }
}

fn render_review_packet(
    role: &str,
    reviewer: &str,
    issued_at: &str,
    candidate: &str,
    epoch: &str,
    artifacts: &[String],
) -> String {
    let artifact_identity = artifacts.join("\n");
    let review_id = sha256_bytes(
        [
            candidate.as_bytes(),
            epoch.as_bytes(),
            role.as_bytes(),
            artifact_identity.as_bytes(),
        ]
        .concat()
        .as_slice(),
    )
    .hex();
    let artifact_list_json = artifacts
        .iter()
        .map(|digest| {
            let mut value = String::new();
            push_json(&mut value, digest);
            value
        })
        .collect::<Vec<_>>()
        .join(",");
    let mut result = String::from("{\"schemaVersion\":1,\"reviewId\":");
    push_json(&mut result, &review_id);
    for (field, value) in [
        ("role", role),
        ("reviewer", reviewer),
        ("decision", "accept"),
        ("candidateCommit", candidate),
        ("assuranceEpochSha256", epoch),
    ] {
        result.push_str(",\"");
        result.push_str(field);
        result.push_str("\":");
        push_json(&mut result, value);
    }
    result.push_str(",\"reviewedArtifacts\":[");
    result.push_str(&artifact_list_json);
    result.push_str(
        "],\"distinctSubjects\":1,\"independenceViolations\":[],\"findings\":[],\"issuedAt\":",
    );
    push_json(&mut result, issued_at);
    result.push_str("}\n");
    result
}

fn oracle_subject_digest(document: &str, ordinal: &str) -> Result<String, String> {
    let binary_field = match ordinal {
        "first" => "firstBinarySha256",
        "second" => "secondBinarySha256",
        _ => return Err("oracle packet ordinal must be first or second".to_owned()),
    };
    let mut subject = String::from("{\"schemaVersion\":1");
    for (target, source) in [
        ("candidateCommit", "candidateCommit"),
        ("assuranceEpochSha256", "assuranceEpochSha256"),
        ("platform", "platform"),
        ("sourceCommit", "sourceCommit"),
        ("sourceTree", "sourceTree"),
        ("acquisitionReceiptSha256", "acquisitionReceiptSha256"),
        ("buildPlanSha256", "buildPlanSha256"),
        ("sbomSha256", "sbomSha256"),
        ("networkInventorySha256", "networkInventorySha256"),
        ("environmentSha256", "environmentSha256"),
        ("provenancePolicySha256", "provenancePolicySha256"),
        (binary_field, "binarySha256"),
        (&format!("{ordinal}BuilderTrustDomain"), "trustDomain"),
        (&format!("{ordinal}RunIdentity"), "runIdentity"),
        (&format!("{ordinal}TriggerActorId"), "triggerActorId"),
        (&format!("{ordinal}TriggerActorLogin"), "triggerActorLogin"),
        (
            &format!("{ordinal}TriggerRepositoryId"),
            "triggerRepositoryId",
        ),
        (&format!("{ordinal}TriggerRunId"), "triggerRunId"),
        (&format!("{ordinal}TriggerRunAttempt"), "triggerRunAttempt"),
        (
            &format!("{ordinal}TriggerWorkflowRef"),
            "triggerWorkflowRef",
        ),
        (&format!("{ordinal}TriggerEvent"), "triggerEvent"),
    ] {
        subject.push(',');
        push_json(&mut subject, target);
        subject.push(':');
        push_json(&mut subject, &subject_field(document, source)?);
    }
    subject.push_str("}\n");
    Ok(sha256_bytes(subject.as_bytes()).hex())
}

#[allow(clippy::too_many_lines)]
fn compare(options: &Options) -> Result<String, String> {
    let first = required(options.first.as_ref(), "--first")?;
    let second = required(options.second.as_ref(), "--second")?;
    let exercised = required(options.exercised.as_ref(), "--exercised")?;
    let exercised_receipt = required(options.exercised_receipt.as_ref(), "--exercised-receipt")?;
    let first_receipt = required(options.first_receipt.as_ref(), "--first-receipt")?;
    let second_receipt = required(options.second_receipt.as_ref(), "--second-receipt")?;
    let output = required(options.output.as_ref(), "--output")?;
    verify_build(first)?;
    verify_build(second)?;
    let first_subject = fs::read_to_string(first.join("builder-subject.json"))
        .map_err(|error| format!("cannot read first builder subject: {error}"))?;
    let second_subject = fs::read_to_string(second.join("builder-subject.json"))
        .map_err(|error| format!("cannot read second builder subject: {error}"))?;
    let policy = path_from_components(["compat", "reviews.allowed_signers"]);
    for (directory, receipt, subject, ordinal) in [
        (first, first_receipt, first_subject.as_str(), "first"),
        (second, second_receipt, second_subject.as_str(), "second"),
    ] {
        crate::assurance::verify_review_binding(
            receipt,
            &policy,
            "oracle-builder",
            &subject_field(subject, "candidateCommit")?,
            &subject_field(subject, "assuranceEpochSha256")?,
            &builder_reviewed_artifacts(subject, ordinal, directory)?,
        )?;
    }
    for field in [
        "candidateCommit",
        "assuranceEpochSha256",
        "platform",
        "sourceCommit",
        "sourceTree",
        "buildPlanSha256",
        "sbomSha256",
        "networkInventorySha256",
        "binarySha256",
        "triggerActorId",
        "triggerActorLogin",
        "triggerRepositoryId",
        "triggerRunId",
        "triggerRunAttempt",
        "triggerWorkflowRef",
        "triggerEvent",
    ] {
        if subject_field(&first_subject, field)? != subject_field(&second_subject, field)? {
            return Err(format!("independent oracle builds disagree on {field}"));
        }
    }
    for field in ["builder", "trustDomain", "runIdentity"] {
        if subject_field(&first_subject, field)? == subject_field(&second_subject, field)? {
            return Err(format!("independent oracle builds reuse {field}"));
        }
    }
    if subject_field(&first_subject, "acquisitionReceiptSha256")?
        == subject_field(&second_subject, "acquisitionReceiptSha256")?
    {
        return Err("oracle rebuilds reuse one acquisition receipt".to_owned());
    }
    if subject_field(&first_subject, "environmentSha256")?
        == subject_field(&second_subject, "environmentSha256")?
    {
        return Err("oracle rebuilds reuse one runner environment identity".to_owned());
    }
    if first == second || first_receipt == second_receipt {
        return Err("oracle builds and signed receipts must be separately retained".to_owned());
    }
    let platform = subject_field(&first_subject, "platform")?;
    let binary_name = if platform == "windows-amd64" {
        "hell.exe"
    } else {
        "hell"
    };
    let first_binary = first.join("binary").join(binary_name);
    let second_binary = second.join("binary").join(binary_name);
    let binary_digest = subject_field(&first_subject, "binarySha256")?;
    let shard_summary = fs::read_to_string(exercised_receipt)
        .map_err(|error| format!("cannot read exercised shard identity: {error}"))?;
    if subject_field(&shard_summary, "oracleSha256")? != binary_digest
        || subject_field(&shard_summary, "platform")? != platform
    {
        return Err("native shard did not exercise the reviewed oracle binary".to_owned());
    }
    for path in [&first_binary, &second_binary, exercised] {
        if sha256_file(path)
            .map_err(|error| format!("cannot hash {}: {error}", path.display()))?
            .hex()
            != binary_digest
        {
            return Err(format!(
                "oracle executable {} is not the reviewed binary",
                path.display()
            ));
        }
    }
    let mut semantic_fingerprint = Vec::new();
    for probe in [["--version"].as_slice(), ["--help"].as_slice()] {
        let first_fingerprint = run_checked(Path::new("."), path_text(&first_binary)?, probe)?;
        let second_fingerprint = run_checked(Path::new("."), path_text(&second_binary)?, probe)?;
        if first_fingerprint.stdout != second_fingerprint.stdout
            || first_fingerprint.stderr != second_fingerprint.stderr
        {
            return Err(
                "oracle fixed semantic fingerprint corpus differs between rebuilds".to_owned(),
            );
        }
        semantic_fingerprint.extend_from_slice(&first_fingerprint.stdout);
        semantic_fingerprint.extend_from_slice(&first_fingerprint.stderr);
    }
    let mut record = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in [
        (
            "candidateCommit",
            subject_field(&first_subject, "candidateCommit")?,
        ),
        (
            "assuranceEpochSha256",
            subject_field(&first_subject, "assuranceEpochSha256")?,
        ),
        ("platform", platform),
        (
            "sourceCommit",
            subject_field(&first_subject, "sourceCommit")?,
        ),
        ("sourceTree", subject_field(&first_subject, "sourceTree")?),
        (
            "buildPlanSha256",
            subject_field(&first_subject, "buildPlanSha256")?,
        ),
        ("sbomSha256", subject_field(&first_subject, "sbomSha256")?),
        (
            "networkInventorySha256",
            subject_field(&first_subject, "networkInventorySha256")?,
        ),
        (
            "firstAcquisitionReceiptSha256",
            subject_field(&first_subject, "acquisitionReceiptSha256")?,
        ),
        (
            "secondAcquisitionReceiptSha256",
            subject_field(&second_subject, "acquisitionReceiptSha256")?,
        ),
        (
            "firstEnvironmentSha256",
            subject_field(&first_subject, "environmentSha256")?,
        ),
        (
            "secondEnvironmentSha256",
            subject_field(&second_subject, "environmentSha256")?,
        ),
        (
            "firstProvenancePolicySha256",
            subject_field(&first_subject, "provenancePolicySha256")?,
        ),
        (
            "secondProvenancePolicySha256",
            subject_field(&second_subject, "provenancePolicySha256")?,
        ),
        ("binarySha256", binary_digest),
        (
            "firstBinarySha256",
            subject_field(&first_subject, "binarySha256")?,
        ),
        (
            "secondBinarySha256",
            subject_field(&second_subject, "binarySha256")?,
        ),
        (
            "exercisedBinarySha256",
            sha256_file(exercised)
                .map_err(|error| error.to_string())?
                .hex(),
        ),
        ("firstBuilder", subject_field(&first_subject, "builder")?),
        (
            "firstBuilderTrustDomain",
            subject_field(&first_subject, "trustDomain")?,
        ),
        (
            "firstRunIdentity",
            subject_field(&first_subject, "runIdentity")?,
        ),
        ("secondBuilder", subject_field(&second_subject, "builder")?),
        (
            "secondBuilderTrustDomain",
            subject_field(&second_subject, "trustDomain")?,
        ),
        (
            "secondRunIdentity",
            subject_field(&second_subject, "runIdentity")?,
        ),
        (
            "firstBuildReceiptSha256",
            sha256_file(first_receipt)
                .map_err(|error| error.to_string())?
                .hex(),
        ),
        (
            "secondBuildReceiptSha256",
            sha256_file(second_receipt)
                .map_err(|error| error.to_string())?
                .hex(),
        ),
        (
            "semanticFingerprintSha256",
            sha256_bytes(&semantic_fingerprint).hex(),
        ),
    ] {
        record.push_str(",\n  \"");
        record.push_str(field);
        record.push_str("\": ");
        push_json(&mut record, &value);
    }
    record.push_str(",\n  \"reproducibility\": \"exact\",\n  \"exercisedBinaryBinding\": true,\n  \"policyFindings\": []\n}\n");
    write_atomic(output, record.as_bytes())?;
    Ok(format!(
        "verified and recorded exact independent oracle rebuilds at {}",
        output.display()
    ))
}

fn subject_field(document: &str, field: &str) -> Result<String, String> {
    let prefix = format!("\"{field}\": \"");
    let line = document
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(&prefix))
        .ok_or_else(|| format!("builder subject lacks {field}"))?;
    let value = line
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix(',').or(Some(value)))
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| format!("builder subject field {field} is malformed"))?;
    require_atom(value, field)?;
    Ok(value.to_owned())
}

fn path_text(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("path {} is not UTF-8", path.display()))
}

fn current_utc_timestamp() -> Result<String, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_owned())?;
    let days = i64::try_from(now.as_secs() / 86_400)
        .map_err(|_| "system clock is outside the supported range".to_owned())?;
    let seconds = now.as_secs() % 86_400;
    let (year, month, day) = civil_from_unix_days(days);
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3_600,
        seconds % 3_600 / 60,
        seconds % 60
    ))
}

fn validate_utc_timestamp(value: &str) -> Result<(), String> {
    let without_zone = value
        .strip_suffix('Z')
        .ok_or_else(|| "oracle packet issued-at must be UTC".to_owned())?;
    let (date, time) = without_zone
        .split_once('T')
        .ok_or_else(|| "oracle packet issued-at lacks date or time".to_owned())?;
    let date = date
        .split('-')
        .map(str::parse::<i64>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "oracle packet issued-at date is invalid".to_owned())?;
    let time = time
        .split(':')
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "oracle packet issued-at time is invalid".to_owned())?;
    if date.len() != 3
        || time.len() != 3
        || !(1..=12).contains(&date[1])
        || date[2] < 1
        || date[2] > i64::from(days_in_month(date[0], date[1]))
        || time[0] > 23
        || time[1] > 59
        || time[2] > 59
    {
        Err("oracle packet issued-at is outside the UTC calendar".to_owned())
    } else {
        Ok(())
    }
}

const fn days_in_month(year: i64, month: i64) -> u32 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 31,
    }
}

fn civil_from_unix_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (
        year,
        u32::try_from(month).expect("civil month is bounded"),
        u32::try_from(day).expect("civil day is bounded"),
    )
}

#[allow(clippy::too_many_lines)]
fn build(options: &Options) -> Result<String, String> {
    let source = required(options.source.as_ref(), "--source")?;
    let output = required(options.output.as_ref(), "--output")?;
    let platform = required_text(options.platform.as_ref(), "--platform")?;
    if !matches!(platform, "macos-arm64" | "windows-amd64") {
        return Err("oracle rebuild platform must be macos-arm64 or windows-amd64".to_owned());
    }
    let builder = required_text(options.builder.as_ref(), "--builder")?;
    let trust_domain = required_text(options.trust_domain.as_ref(), "--trust-domain")?;
    let run_identity = required_text(options.run_identity.as_ref(), "--run-identity")?;
    let trigger_actor_id = required_text(options.trigger_actor_id.as_ref(), "--trigger-actor-id")?;
    let trigger_actor_login = required_text(
        options.trigger_actor_login.as_ref(),
        "--trigger-actor-login",
    )?;
    let trigger_repository_id = required_text(
        options.trigger_repository_id.as_ref(),
        "--trigger-repository-id",
    )?;
    let trigger_run_id = required_text(options.trigger_run_id.as_ref(), "--trigger-run-id")?;
    let trigger_run_attempt = required_text(
        options.trigger_run_attempt.as_ref(),
        "--trigger-run-attempt",
    )?;
    let trigger_workflow_ref = required_text(
        options.trigger_workflow_ref.as_ref(),
        "--trigger-workflow-ref",
    )?;
    let trigger_event = required_text(options.trigger_event.as_ref(), "--trigger-event")?;
    let candidate = required_text(options.candidate.as_ref(), "--candidate")?;
    let epoch_from_file = options
        .epoch_file
        .as_deref()
        .map(crate::assurance::retained_epoch_digest)
        .transpose()?;
    let epoch = match (options.epoch.as_deref(), epoch_from_file.as_ref()) {
        (Some(epoch), None) => epoch,
        (None, Some((epoch_candidate, epoch))) => {
            if epoch_candidate != candidate {
                return Err(
                    "retained assurance epoch candidate does not match oracle candidate".to_owned(),
                );
            }
            epoch
        }
        (Some(_), Some(_)) => return Err("use exactly one of --epoch and --epoch-file".to_owned()),
        (None, None) => return Err("oracle-ops requires --epoch or --epoch-file".to_owned()),
    };
    require_git_sha(candidate, "candidate")?;
    require_digest(epoch, "assurance epoch")?;
    for (label, value) in [
        ("builder", builder),
        ("trust domain", trust_domain),
        ("run identity", run_identity),
        ("trigger actor ID", trigger_actor_id),
        ("trigger actor login", trigger_actor_login),
        ("trigger repository ID", trigger_repository_id),
        ("trigger run ID", trigger_run_id),
        ("trigger run attempt", trigger_run_attempt),
        ("trigger workflow ref", trigger_workflow_ref),
        ("trigger event", trigger_event),
    ] {
        require_atom(value, label)?;
    }
    for (value, label) in [
        (trigger_actor_id, "trigger actor ID"),
        (trigger_repository_id, "trigger repository ID"),
        (trigger_run_id, "trigger run ID"),
        (trigger_run_attempt, "trigger run attempt"),
    ] {
        value
            .parse::<u64>()
            .ok()
            .filter(|value| *value != 0)
            .ok_or_else(|| format!("{label} is not positive"))?;
    }

    let source_commit = command_text(source, "git", &["rev-parse", "HEAD"])?;
    if source_commit != UPSTREAM_COMMIT {
        return Err(format!(
            "oracle source commit mismatch: expected {UPSTREAM_COMMIT}, observed {source_commit}"
        ));
    }
    let source_tree = command_text(source, "git", &["rev-parse", "HEAD^{tree}"])?;
    let status = command_text(source, "git", &["status", "--porcelain=v2"])?;
    if !status.is_empty() {
        return Err("oracle source tree is not clean before build".to_owned());
    }
    run_checked(source, "git", &["fsck", "--strict"])?;
    verify_submodules(source)?;
    reject_lfs_pointers(source)?;

    fs::create_dir_all(output)
        .map_err(|error| format!("cannot create {}: {error}", output.display()))?;
    let stack_yaml = fs::canonicalize(source.join("stack.yaml"))
        .map_err(|error| format!("cannot resolve pinned stack.yaml: {error}"))?;
    let stack_lock = source.join("stack.yaml.lock");
    let resolver = fs::read(&stack_lock)
        .map_err(|error| format!("cannot read {}: {error}", stack_lock.display()))?;
    let stack_configuration = validate_stack_configuration(&stack_yaml, &stack_lock)?;
    let resolver_sha256 = sha256_bytes(&resolver);
    let stack_yaml_sha256 = sha256_file(&stack_yaml)
        .map_err(|error| format!("cannot hash {}: {error}", stack_yaml.display()))?;
    let source_archive = run_checked(source, "git", &["archive", "--format=tar", "HEAD"])?;
    let source_archive_sha256 = sha256_bytes(&source_archive.stdout);
    let source_files = tracked_source_inventory(source, &source_tree)?;

    let stack_version = command_text(Path::new("."), "stack", &["--numeric-version"])?;
    let stack_root = path_from_components(["target", "oracle-stack-root"])
        .join(platform)
        .join(builder);
    if stack_root.exists() {
        return Err("oracle acquisition Stack root must start absent".to_owned());
    }
    fs::create_dir_all(&stack_root)
        .map_err(|error| format!("cannot create isolated Stack root: {error}"))?;
    let stack_root = fs::canonicalize(&stack_root)
        .map_err(|error| format!("cannot resolve isolated Stack root: {error}"))?;
    let acquisition = run_checked_os(
        source,
        "stack",
        &[
            OsString::from("--stack-root"),
            stack_root.as_os_str().to_owned(),
            OsString::from("--stack-yaml"),
            stack_yaml.as_os_str().to_owned(),
            OsString::from("--lock-file"),
            OsString::from("error-on-write"),
            OsString::from("--system-ghc"),
            OsString::from("--no-install-ghc"),
            OsString::from("--verbose"),
            OsString::from("build"),
            OsString::from("--only-dependencies"),
        ],
    )?;
    let dependency_validation = run_checked_os(
        source,
        "stack",
        &[
            OsString::from("--stack-root"),
            stack_root.as_os_str().to_owned(),
            OsString::from("--stack-yaml"),
            stack_yaml.as_os_str().to_owned(),
            OsString::from("--lock-file"),
            OsString::from("error-on-write"),
            OsString::from("--offline"),
            OsString::from("build"),
            OsString::from("--only-dependencies"),
        ],
    )?;
    let binary_directory = output.join("binary");
    fs::create_dir_all(&binary_directory)
        .map_err(|error| format!("cannot create {}: {error}", binary_directory.display()))?;
    let binary_directory = fs::canonicalize(&binary_directory)
        .map_err(|error| format!("cannot resolve {}: {error}", binary_directory.display()))?;
    let offline_build = run_checked_os(
        source,
        "stack",
        &[
            OsString::from("--stack-root"),
            stack_root.as_os_str().to_owned(),
            OsString::from("--stack-yaml"),
            stack_yaml.as_os_str().to_owned(),
            OsString::from("--lock-file"),
            OsString::from("error-on-write"),
            OsString::from("--offline"),
            OsString::from("build"),
            OsString::from("--copy-bins"),
            OsString::from("--local-bin-path"),
            binary_directory.as_os_str().to_owned(),
        ],
    )?;
    let compiler = run_checked_os(
        source,
        "stack",
        &[
            OsString::from("--stack-root"),
            stack_root.as_os_str().to_owned(),
            OsString::from("--stack-yaml"),
            stack_yaml.as_os_str().to_owned(),
            OsString::from("exec"),
            OsString::from("--"),
            OsString::from("ghc"),
            OsString::from("--info"),
        ],
    )?;
    let dependencies = run_checked_os(
        source,
        "stack",
        &[
            OsString::from("--stack-root"),
            stack_root.as_os_str().to_owned(),
            OsString::from("--stack-yaml"),
            stack_yaml.as_os_str().to_owned(),
            OsString::from("ls"),
            OsString::from("dependencies"),
        ],
    )?;
    let executable = binary_directory.join(if platform == "windows-amd64" {
        "hell.exe"
    } else {
        "hell"
    });
    let binary_sha256 = sha256_file(&executable)
        .map_err(|error| format!("cannot hash {}: {error}", executable.display()))?;
    let mut dependency_rows = dependencies_from_output(&dependencies.stdout)?;
    dependency_rows.retain(|(name, _)| name != "hell");
    if dependency_rows.is_empty() {
        return Err("oracle dependency plan is empty".to_owned());
    }
    let mut package_sources =
        collect_package_sources(source, output, &stack_yaml, &stack_root, &dependency_rows)?;
    let observed_urls = observed_acquisition_urls(&acquisition)?;
    let unrecorded_urls = bind_package_accesses(&mut package_sources, &observed_urls.reviewed);
    let source_acquisition_complete = package_sources
        .iter()
        .all(|package| !package.provider_urls.is_empty())
        && observed_urls.unexpected.is_empty()
        && unrecorded_urls.is_empty();

    let stack_executable = find_executable("stack")?;
    let stack_sha256 = sha256_file(&stack_executable)
        .map_err(|error| format!("cannot hash {}: {error}", stack_executable.display()))?;
    let compiler_sha256 = sha256_bytes(&compiler.stdout);
    let toolchain_sha256 = sha256_bytes(
        format!(
            "{stack_version}\n{}\n{}\n",
            stack_sha256.hex(),
            compiler_sha256.hex()
        )
        .as_bytes(),
    );
    let stack_sha256_text = stack_sha256.hex();
    let compiler_sha256_text = compiler_sha256.hex();
    let resolver_sha256_text = resolver_sha256.hex();
    let toolchain_sha256_text = toolchain_sha256.hex();
    let source_files_path = output.join("source-files.json");
    let source_archive_path = output.join("source-archive.tar");
    write_atomic(&source_files_path, source_files.as_bytes())?;
    write_atomic(&source_archive_path, &source_archive.stdout)?;
    let source_files_sha256 = sha256_file(&source_files_path)
        .map_err(|error| format!("cannot hash {}: {error}", source_files_path.display()))?;
    let environment = environment_json(
        platform,
        &stack_version,
        &stack_sha256_text,
        &compiler_sha256_text,
    )?;
    let plan = build_plan_json(
        &source_commit,
        &source_tree,
        &stack_version,
        &stack_sha256_text,
        &compiler_sha256_text,
        &resolver_sha256_text,
        &stack_yaml_sha256.hex(),
        &source_archive_sha256.hex(),
        &source_files_sha256.hex(),
        &toolchain_sha256_text,
        &stack_configuration,
        &package_sources,
        source_acquisition_complete,
        &dependency_validation,
        &offline_build,
    );
    let sbom = sbom_json(&source_tree, &package_sources, &resolver_sha256_text);
    let network = network_json(&NetworkInventoryInputs {
        lock: &resolver,
        packages: &package_sources,
        observed_urls: &observed_urls.reviewed,
        unexpected_urls: &observed_urls.unexpected,
        unrecorded_urls: &unrecorded_urls,
        acquisition: &acquisition,
        dependency_validation: &dependency_validation,
        build: &offline_build,
    });
    let plan_path = output.join("build-plan.json");
    let sbom_path = output.join("sbom.spdx.json");
    let network_path = output.join("network-inventory.json");
    let environment_path = output.join("environment.json");
    let acquisition_path = output.join("acquisition-receipt.json");
    let policy_path = output.join("provenance-policy.json");
    write_atomic(&plan_path, plan.as_bytes())?;
    write_atomic(&sbom_path, sbom.as_bytes())?;
    write_atomic(&network_path, network.as_bytes())?;
    write_atomic(&environment_path, environment.as_bytes())?;
    let acquisition_receipt = acquisition_receipt_json(&AcquisitionReceiptInputs {
        candidate,
        epoch,
        builder,
        trust_domain,
        run_identity,
        trigger_actor_id,
        trigger_actor_login,
        trigger_repository_id,
        trigger_run_id,
        trigger_run_attempt,
        trigger_workflow_ref,
        trigger_event,
        packages: &package_sources,
        urls: &observed_urls.reviewed,
        unexpected_urls: &observed_urls.unexpected,
        source_acquisition_complete,
        unrecorded_urls: &unrecorded_urls,
        acquisition: &acquisition,
    });
    write_atomic(&acquisition_path, acquisition_receipt.as_bytes())?;
    let policy = provenance_policy_json(&ProvenancePolicyInputs {
        source_commit: &source_commit,
        source_tree: &source_tree,
        plan: &plan_path,
        sbom: &sbom_path,
        network: &network_path,
        environment: &environment_path,
        source_files: &source_files_path,
        acquisition: &acquisition_path,
        binary: binary_sha256,
    })?;
    write_atomic(&policy_path, policy.as_bytes())?;
    verify_build(output)?;
    let subject = builder_subject_json(&BuilderSubject {
        candidate,
        epoch,
        platform,
        source_commit: &source_commit,
        source_tree: &source_tree,
        builder,
        trust_domain,
        run_identity,
        trigger_actor_id,
        trigger_actor_login,
        trigger_repository_id,
        trigger_run_id,
        trigger_run_attempt,
        trigger_workflow_ref,
        trigger_event,
        build_plan: sha256_file(&plan_path)
            .map_err(|error| error.to_string())?
            .hex(),
        sbom: sha256_file(&sbom_path)
            .map_err(|error| error.to_string())?
            .hex(),
        network: sha256_file(&network_path)
            .map_err(|error| error.to_string())?
            .hex(),
        acquisition: sha256_file(&acquisition_path)
            .map_err(|error| error.to_string())?
            .hex(),
        environment: sha256_file(&environment_path)
            .map_err(|error| error.to_string())?
            .hex(),
        policy: sha256_file(&policy_path)
            .map_err(|error| error.to_string())?
            .hex(),
        binary: binary_sha256.hex(),
    });
    write_atomic(&output.join("builder-subject.json"), subject.as_bytes())?;
    Ok(format!(
        "collected checksum-complete, offline oracle build for {platform} at {}",
        output.display()
    ))
}

fn verify_build(output: &Path) -> Result<String, String> {
    for relative in [
        "acquisition-receipt.json",
        "build-plan.json",
        "sbom.spdx.json",
        "network-inventory.json",
        "environment.json",
        "source-files.json",
        "provenance-policy.json",
        "builder-subject.json",
    ] {
        let path = output.join(relative);
        let bytes =
            fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if bytes.last() != Some(&b'\n') {
            return Err(format!("{} lacks a trailing newline", path.display()));
        }
    }
    let plan = fs::read_to_string(output.join("build-plan.json"))
        .map_err(|error| format!("cannot read build plan: {error}"))?;
    let archive = output.join("source-archive.tar");
    let archive_sha256 = sha256_file(&archive)
        .map_err(|error| format!("cannot hash {}: {error}", archive.display()))?
        .hex();
    if subject_field(&plan, "sourceArchiveSha256")? != archive_sha256 {
        return Err("oracle source archive differs from the typed build plan".to_owned());
    }
    for required in [
        "\"buildOffline\": true",
        "\"sourceTreeClean\": true",
        "\"packageDigestsComplete\": true",
        "\"mutableVcsDependencies\": []",
        "\"localDependencyEscapes\": []",
        "\"reviewRequired\": []",
    ] {
        if !plan.contains(required) {
            return Err(format!("oracle build plan is missing {required}"));
        }
    }
    let network = fs::read_to_string(output.join("network-inventory.json"))
        .map_err(|error| format!("cannot read network inventory: {error}"))?;
    for required in [
        "\"buildOffline\": true",
        "\"unexpectedEndpoints\": []",
        "\"unrecordedDownloads\": []",
    ] {
        if !network.contains(required) {
            return Err(format!("oracle network inventory is missing {required}"));
        }
    }
    let sbom = fs::read_to_string(output.join("sbom.spdx.json"))
        .map_err(|error| format!("cannot read oracle SBOM: {error}"))?;
    if sbom.contains("\"checksumState\": \"not-collected\"") || sbom.contains("\"checksums\": []") {
        return Err("oracle SBOM lacks dependency source checksums".to_owned());
    }
    let policy = fs::read_to_string(output.join("provenance-policy.json"))
        .map_err(|error| format!("cannot read oracle provenance policy: {error}"))?;
    for required in [
        "\"failures\": []",
        "\"reviewFindings\": []",
        "\"verdict\": \"pass\"",
    ] {
        if !policy.contains(required) {
            return Err(format!("oracle provenance policy is missing {required}"));
        }
    }
    Ok("verified typed offline oracle build receipt".to_owned())
}

fn verify_submodules(source: &Path) -> Result<(), String> {
    let output = command_text(source, "git", &["submodule", "status", "--recursive"])?;
    if output.lines().any(|line| {
        line.as_bytes()
            .first()
            .is_some_and(|prefix| matches!(prefix, b'-' | b'+' | b'U'))
    }) {
        return Err("oracle source has uninitialized or changed submodules".to_owned());
    }
    Ok(())
}

fn reject_lfs_pointers(root: &Path) -> Result<(), String> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("cannot enumerate {}: {error}", directory.display()))?
        {
            let entry = entry.map_err(|error| format!("cannot enumerate source: {error}"))?;
            let path = entry.path();
            if path.file_name().is_some_and(|name| name == ".git") {
                continue;
            }
            let kind = entry
                .file_type()
                .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
            if kind.is_symlink() {
                return Err(format!("oracle source contains symlink {}", path.display()));
            }
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                let bytes = fs::read(&path)
                    .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
                if bytes.starts_with(b"version https://git-lfs.github.com/spec/v1\n") {
                    return Err(format!("unresolved Git LFS pointer {}", path.display()));
                }
            }
        }
    }
    Ok(())
}

fn tracked_source_inventory(source: &Path, source_tree: &str) -> Result<String, String> {
    let root = fs::canonicalize(source)
        .map_err(|error| format!("cannot resolve oracle source root: {error}"))?;
    let listing = run_checked(source, "git", &["ls-files", "-z"])?;
    if !listing.stdout.ends_with(&[0]) {
        return Err("git ls-files inventory is not NUL terminated".to_owned());
    }
    let mut files = Vec::new();
    for raw_path in listing.stdout.split(|byte| *byte == 0) {
        if raw_path.is_empty() {
            continue;
        }
        let relative = std::str::from_utf8(raw_path)
            .map_err(|_| "tracked source path is not UTF-8".to_owned())?;
        let relative_path = Path::new(relative);
        if relative_path.is_absolute()
            || relative_path
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(format!(
                "tracked source path {relative:?} is not normalized"
            ));
        }
        let path = root.join(relative_path);
        let canonical = fs::canonicalize(&path)
            .map_err(|error| format!("cannot resolve tracked source {relative:?}: {error}"))?;
        if !canonical.starts_with(&root) {
            return Err(format!(
                "tracked source path {relative:?} escapes the reviewed tree"
            ));
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect tracked source {relative:?}: {error}"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(format!("tracked source {relative:?} is not a regular file"));
        }
        files.push((
            relative.to_owned(),
            sha256_file(&canonical).map_err(|error| error.to_string())?,
        ));
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    if files.is_empty() {
        return Err("reviewed source inventory is empty".to_owned());
    }
    let mut output = String::from("{\n  \"schemaVersion\": 1,\n  \"sourceTree\": ");
    push_json(&mut output, source_tree);
    write!(
        output,
        ",\n  \"fileCount\": {},\n  \"files\": [",
        files.len()
    )
    .expect("writing to String cannot fail");
    for (index, (path, digest)) in files.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("\n    {\"path\": ");
        push_json(&mut output, path);
        output.push_str(", \"sha256\": \"");
        output.push_str(&digest.hex());
        output.push_str("\"}");
    }
    output.push_str("\n  ]\n}\n");
    Ok(output)
}

fn dependencies_from_output(output: &[u8]) -> Result<Vec<(String, String)>, String> {
    let text = std::str::from_utf8(output)
        .map_err(|_| "stack dependency output is not UTF-8".to_owned())?;
    let mut dependencies = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let mut fields = line.split_ascii_whitespace();
        let name = fields
            .next()
            .ok_or_else(|| "dependency lacks name".to_owned())?;
        let version = fields
            .next()
            .ok_or_else(|| format!("dependency {name:?} lacks version"))?;
        if fields.next().is_some() {
            return Err(format!("dependency row {line:?} has unexpected fields"));
        }
        require_atom(name, "dependency name")?;
        require_atom(version, "dependency version")?;
        dependencies.push((name.to_owned(), version.to_owned()));
    }
    dependencies.sort();
    dependencies.dedup();
    Ok(dependencies)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PackageSource {
    name: String,
    version: String,
    checksum: Digest,
    retained_path: String,
    provider_urls: Vec<String>,
}

struct PackageCoordinate<'a> {
    name: &'a str,
    version: &'a str,
}

impl PackageCoordinate<'_> {
    fn stack_argument(&self) -> Result<OsString, String> {
        require_atom(self.name, "package name")?;
        require_atom(self.version, "package version")?;
        let mut argument = OsString::from(self.name);
        argument.push("-");
        argument.push(self.version);
        Ok(argument)
    }
}

fn collect_package_sources(
    source: &Path,
    output: &Path,
    stack_yaml: &Path,
    stack_root: &Path,
    dependencies: &[(String, String)],
) -> Result<Vec<PackageSource>, String> {
    let root = output.join("package-sources");
    fs::create_dir_all(&root)
        .map_err(|error| format!("cannot create {}: {error}", root.display()))?;
    let root = fs::canonicalize(&root)
        .map_err(|error| format!("cannot resolve {}: {error}", root.display()))?;
    let mut packages = Vec::with_capacity(dependencies.len());
    for (index, (name, version)) in dependencies.iter().enumerate() {
        let coordinate = PackageCoordinate { name, version };
        let destination = root.join(index.to_string());
        fs::create_dir_all(&destination)
            .map_err(|error| format!("cannot create {}: {error}", destination.display()))?;
        run_checked_os(
            source,
            "stack",
            &[
                OsString::from("--stack-root"),
                stack_root.as_os_str().to_owned(),
                OsString::from("--stack-yaml"),
                stack_yaml.as_os_str().to_owned(),
                OsString::from("--offline"),
                OsString::from("unpack"),
                coordinate.stack_argument()?,
                OsString::from("--to"),
                destination.as_os_str().to_owned(),
            ],
        )?;
        packages.push(PackageSource {
            name: name.clone(),
            version: version.clone(),
            checksum: directory_digest(&destination)?,
            retained_path: PathBuf::from("package-sources")
                .join(index.to_string())
                .to_str()
                .ok_or_else(|| "retained package source path is not UTF-8".to_owned())?
                .to_owned(),
            provider_urls: Vec::new(),
        });
    }
    Ok(packages)
}

fn bind_package_accesses(packages: &mut [PackageSource], urls: &[String]) -> Vec<String> {
    let mut assigned = vec![false; urls.len()];
    for package in packages {
        let mut coordinate = String::with_capacity(package.name.len() + package.version.len() + 1);
        coordinate.push_str(&package.name);
        coordinate.push('-');
        coordinate.push_str(&package.version);
        for (index, url) in urls.iter().enumerate() {
            if url.contains(&coordinate) {
                package.provider_urls.push(url.clone());
                assigned[index] = true;
            }
        }
    }
    urls.iter()
        .zip(assigned)
        .filter(|(url, assigned)| !*assigned && !known_non_package_access(url))
        .map(|(url, _)| url.clone())
        .collect()
}

fn known_non_package_access(url: &str) -> bool {
    [
        "https://api.github.com/",
        "https://downloads.haskell.org/",
        "https://raw.githubusercontent.com/",
    ]
    .iter()
    .any(|prefix| url.starts_with(prefix))
}

fn directory_digest(root: &Path) -> Result<Digest, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory)
            .map_err(|error| format!("cannot read {}: {error}", directory.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("cannot read directory entry: {error}"))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "package source {} contains a symlink",
                    path.display()
                ));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| "package source path escaped collection root".to_owned())?;
                let relative = relative
                    .components()
                    .map(|component| {
                        component
                            .as_os_str()
                            .to_str()
                            .ok_or_else(|| "package source path is not UTF-8".to_owned())
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .join("/");
                files.push((
                    relative,
                    sha256_file(&path).map_err(|error| error.to_string())?,
                ));
            } else {
                return Err(format!(
                    "package source {} is not a regular file",
                    path.display()
                ));
            }
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    if files.is_empty() {
        return Err("unpacked package source is empty".to_owned());
    }
    let mut manifest = String::new();
    for (path, digest) in files {
        writeln!(manifest, "{} {path}", digest.hex()).expect("writing to String cannot fail");
    }
    Ok(sha256_bytes(manifest.as_bytes()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StackConfiguration {
    resolver: String,
    declared_ghc_options: Vec<String>,
}

fn validate_stack_configuration(
    stack_yaml: &Path,
    stack_lock: &Path,
) -> Result<StackConfiguration, String> {
    let configuration = fs::read_to_string(stack_yaml)
        .map_err(|error| format!("cannot read {}: {error}", stack_yaml.display()))?;
    let lock = fs::read_to_string(stack_lock)
        .map_err(|error| format!("cannot read {}: {error}", stack_lock.display()))?;
    validate_stack_configuration_documents(&configuration, &lock)
}

fn validate_stack_configuration_documents(
    configuration: &str,
    lock: &str,
) -> Result<StackConfiguration, String> {
    if crate::assurance_control_mutant_active("local-dependency-override") {
        return Ok(StackConfiguration {
            resolver: "mutable-local-override".to_owned(),
            declared_ghc_options: Vec::new(),
        });
    }
    let active = configuration
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default().trim_end())
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    if active.iter().any(|line| {
        !line.starts_with(char::is_whitespace)
            && ["packages:", "extra-deps:", "flags:"]
                .iter()
                .any(|prefix| line.trim_start().starts_with(prefix))
    }) {
        return Err(
            "pinned oracle Stack configuration declares an unreviewed package, extra dependency, or flag override"
                .to_owned(),
        );
    }
    let resolver = active
        .iter()
        .find_map(|line| line.strip_prefix("resolver:").map(str::trim))
        .ok_or_else(|| "pinned oracle Stack configuration lacks resolver".to_owned())?;
    require_atom(resolver, "Stack resolver")?;
    let lock_packages = lock
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .filter(|line| line.starts_with("packages:"))
        .collect::<Vec<_>>();
    if lock_packages.as_slice() != ["packages: []"] {
        return Err(
            "pinned oracle lock contains package overrides requiring explicit source review"
                .to_owned(),
        );
    }
    let mut declared_ghc_options = Vec::new();
    let mut in_ghc_options = false;
    for line in active {
        if !line.starts_with(char::is_whitespace) {
            in_ghc_options = line == "ghc-options:";
            continue;
        }
        if in_ghc_options {
            let option = line.trim();
            if option.is_empty() || option.chars().any(char::is_control) {
                return Err("declared GHC option mapping is not canonical text".to_owned());
            }
            declared_ghc_options.push(option.to_owned());
        }
    }
    if declared_ghc_options.is_empty() {
        return Err("pinned oracle Stack configuration lacks reviewed GHC options".to_owned());
    }
    Ok(StackConfiguration {
        resolver: resolver.to_owned(),
        declared_ghc_options,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_plan_json(
    source_commit: &str,
    source_tree: &str,
    stack_version: &str,
    stack_sha256: &str,
    compiler_sha256: &str,
    resolver_sha256: &str,
    stack_yaml_sha256: &str,
    source_archive_sha256: &str,
    source_files_sha256: &str,
    toolchain_sha256: &str,
    stack_configuration: &StackConfiguration,
    dependencies: &[PackageSource],
    source_acquisition_complete: bool,
    dependency_validation: &Output,
    build: &Output,
) -> String {
    let mut output = String::from("{\n  \"schemaVersion\": 2,\n  \"sourceCommit\": ");
    push_json(&mut output, source_commit);
    output.push_str(",\n  \"sourceTree\": ");
    push_json(&mut output, source_tree);
    output.push_str(",\n  \"sourceTreeClean\": true,\n  \"stackVersion\": ");
    push_json(&mut output, stack_version);
    for (field, value) in [
        ("stackExecutableSha256", stack_sha256),
        ("compilerInfoSha256", compiler_sha256),
        ("resolverSha256", resolver_sha256),
        ("stackYamlSha256", stack_yaml_sha256),
        ("sourceArchiveSha256", source_archive_sha256),
        ("sourceFilesSha256", source_files_sha256),
        ("toolchainSha256", toolchain_sha256),
    ] {
        output.push_str(",\n  \"");
        output.push_str(field);
        output.push_str("\": \"");
        output.push_str(value);
        output.push('"');
    }
    output.push_str(",\n  \"declaredResolver\": ");
    push_json(&mut output, &stack_configuration.resolver);
    output.push_str(",\n  \"executableTarget\": \"hell\",\n  \"localDependencies\": [{\"path\": \".\", \"sourceTree\": ");
    push_json(&mut output, source_tree);
    output.push_str("}],\n  \"packageFlags\": [],\n  \"declaredCompilerOptions\": [");
    for (index, option) in stack_configuration.declared_ghc_options.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        push_json(&mut output, option);
    }
    output.push_str("],\n  \"packageDigestsComplete\": true,\n  \"sourceAcquisitionComplete\": ");
    output.push_str(if source_acquisition_complete {
        "true"
    } else {
        "false"
    });
    output.push_str(",\n  \"buildOffline\": true,\n  \"mutableVcsDependencies\": [],\n  \"localDependencyEscapes\": [],\n  \"reviewRequired\": [");
    if !source_acquisition_complete {
        output.push_str("\"package-source-provider-access-unbound\"");
    }
    output.push_str("],\n  \"packages\": [");
    for (index, package) in dependencies.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("\n    {\"name\": ");
        push_json(&mut output, &package.name);
        output.push_str(", \"version\": ");
        push_json(&mut output, &package.version);
        output.push_str(", \"sourceKind\": \"stack-offline-unpack\", \"sourceChecksumSha256\": \"");
        output.push_str(&package.checksum.hex());
        output.push_str("\", \"retainedPath\": ");
        push_json(&mut output, &package.retained_path);
        output.push_str(", \"providerUrls\": [");
        for (url_index, url) in package.provider_urls.iter().enumerate() {
            if url_index != 0 {
                output.push_str(", ");
            }
            push_json(&mut output, url);
        }
        output.push_str("]}");
    }
    output.push_str("\n  ],\n  \"commands\": [");
    for (index, (name, command)) in [
        ("offline-dependency-validation", dependency_validation),
        ("offline-build", build),
    ]
    .into_iter()
    .enumerate()
    {
        if index != 0 {
            output.push(',');
        }
        output.push_str("\n    {\"name\": ");
        push_json(&mut output, name);
        write!(
            output,
            ", \"status\": {}, \"stdoutSha256\": \"{}\", \"stderrSha256\": \"{}\"}}",
            command.status.code().unwrap_or(-1),
            sha256_bytes(&command.stdout).hex(),
            sha256_bytes(&command.stderr).hex()
        )
        .expect("writing to String cannot fail");
    }
    output.push_str("\n  ]\n}\n");
    output
}

fn sbom_json(source_tree: &str, dependencies: &[PackageSource], resolver: &str) -> String {
    let mut output = String::from(
        "{\n  \"spdxVersion\": \"SPDX-2.3\",\n  \"dataLicense\": \"CC0-1.0\",\n  \"SPDXID\": \"SPDXRef-DOCUMENT\",\n  \"packages\": [",
    );
    for (index, package) in dependencies.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("\n    {\"name\": ");
        push_json(&mut output, &package.name);
        output.push_str(", \"versionInfo\": ");
        push_json(&mut output, &package.version);
        output.push_str(", \"downloadLocation\": ");
        push_json(
            &mut output,
            package
                .provider_urls
                .first()
                .map_or("NOASSERTION", String::as_str),
        );
        output.push_str(", \"checksums\": [{\"algorithm\": \"SHA256\", \"checksumValue\": \"");
        output.push_str(&package.checksum.hex());
        output.push_str("\"}], \"checksumState\": \"collected-from-retained-acquired-source\", \"retainedPath\": ");
        push_json(&mut output, &package.retained_path);
        output.push_str(", \"externalRefs\": [{\"referenceType\": \"hell-rs-stack-resolution\", \"referenceLocator\": \"");
        output.push_str(resolver);
        output.push_str("\"}]} ");
    }
    output.push_str("\n  ],\n  \"sourceTreeSha256\": ");
    push_json(&mut output, source_tree);
    output.push_str("\n}\n");
    output
}

struct AcquisitionUrls {
    reviewed: Vec<String>,
    unexpected: Vec<String>,
}

fn observed_acquisition_urls(acquisition: &Output) -> Result<AcquisitionUrls, String> {
    let stdout = std::str::from_utf8(&acquisition.stdout)
        .map_err(|_| "Stack acquisition observation is not UTF-8".to_owned())?;
    let stderr = std::str::from_utf8(&acquisition.stderr)
        .map_err(|_| "Stack acquisition observation is not UTF-8".to_owned())?;
    acquisition_urls_from_text([stdout, stderr])
}

fn acquisition_urls_from_text<const N: usize>(
    observations: [&str; N],
) -> Result<AcquisitionUrls, String> {
    let mut reviewed = Vec::new();
    let mut unexpected = Vec::new();
    for text in observations {
        for token in text.split_ascii_whitespace() {
            let value = token.trim_matches(|character: char| {
                matches!(character, '"' | '\'' | '(' | ')' | '[' | ']' | ',' | ';')
            });
            if !value.starts_with("https://") {
                continue;
            }
            if value.contains('@') || value.contains('?') || value.contains('#') {
                return Err(
                    "Stack acquisition URL contains unreviewed identity or query data".to_owned(),
                );
            }
            let approved = [
                "https://api.github.com/",
                "https://downloads.haskell.org/",
                "https://github.com/",
                "https://hackage.haskell.org/",
                "https://objects.githubusercontent.com/",
                "https://raw.githubusercontent.com/",
            ]
            .iter()
            .any(|prefix| value.starts_with(prefix));
            require_atom(value, "observed acquisition URL")?;
            if approved {
                reviewed.push(value.to_owned());
            } else {
                unexpected.push(value.to_owned());
            }
        }
    }
    reviewed.sort();
    reviewed.dedup();
    unexpected.sort();
    unexpected.dedup();
    if reviewed.is_empty() && unexpected.is_empty() {
        return Err("isolated Stack acquisition observed no package or source access".to_owned());
    }
    Ok(AcquisitionUrls {
        reviewed,
        unexpected,
    })
}

struct AcquisitionReceiptInputs<'a> {
    candidate: &'a str,
    epoch: &'a str,
    builder: &'a str,
    trust_domain: &'a str,
    run_identity: &'a str,
    trigger_actor_id: &'a str,
    trigger_actor_login: &'a str,
    trigger_repository_id: &'a str,
    trigger_run_id: &'a str,
    trigger_run_attempt: &'a str,
    trigger_workflow_ref: &'a str,
    trigger_event: &'a str,
    packages: &'a [PackageSource],
    urls: &'a [String],
    unexpected_urls: &'a [String],
    source_acquisition_complete: bool,
    unrecorded_urls: &'a [String],
    acquisition: &'a Output,
}

fn acquisition_receipt_json(inputs: &AcquisitionReceiptInputs<'_>) -> String {
    let mut output = String::from("{\n  \"schemaVersion\": 1");
    let stdout_sha256 = sha256_bytes(&inputs.acquisition.stdout).hex();
    let stderr_sha256 = sha256_bytes(&inputs.acquisition.stderr).hex();
    for (field, value) in [
        ("candidateCommit", inputs.candidate),
        ("assuranceEpochSha256", inputs.epoch),
        ("builder", inputs.builder),
        ("trustDomain", inputs.trust_domain),
        ("runIdentity", inputs.run_identity),
        ("triggerActorId", inputs.trigger_actor_id),
        ("triggerActorLogin", inputs.trigger_actor_login),
        ("triggerRepositoryId", inputs.trigger_repository_id),
        ("triggerRunId", inputs.trigger_run_id),
        ("triggerRunAttempt", inputs.trigger_run_attempt),
        ("triggerWorkflowRef", inputs.trigger_workflow_ref),
        ("triggerEvent", inputs.trigger_event),
        ("acquisitionStdoutSha256", stdout_sha256.as_str()),
        ("acquisitionStderrSha256", stderr_sha256.as_str()),
    ] {
        output.push_str(",\n  \"");
        output.push_str(field);
        output.push_str("\": ");
        push_json(&mut output, value);
    }
    output.push_str(",\n  \"observedHttpsAccesses\": [");
    for (index, url) in inputs.urls.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        push_json(&mut output, url);
    }
    output.push_str("],\n  \"packageSources\": [");
    for (index, package) in inputs.packages.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("\n    {\"name\": ");
        push_json(&mut output, &package.name);
        output.push_str(", \"version\": ");
        push_json(&mut output, &package.version);
        output.push_str(", \"sha256\": \"");
        output.push_str(&package.checksum.hex());
        output.push_str("\", \"retainedPath\": ");
        push_json(&mut output, &package.retained_path);
        output.push_str(", \"providerUrls\": [");
        for (url_index, url) in package.provider_urls.iter().enumerate() {
            if url_index != 0 {
                output.push_str(", ");
            }
            push_json(&mut output, url);
        }
        output.push_str("]}");
    }
    output.push_str("\n  ],\n  \"unexpectedAccesses\": [");
    for (index, url) in inputs.unexpected_urls.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        push_json(&mut output, url);
    }
    output.push_str("],\n  \"unrecordedAccesses\": [");
    for (index, url) in inputs.unrecorded_urls.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        push_json(&mut output, url);
    }
    output.push_str("],\n  \"sourceAcquisitionComplete\": ");
    output.push_str(if inputs.source_acquisition_complete {
        "true"
    } else {
        "false"
    });
    output.push_str("\n}\n");
    output
}

struct NetworkInventoryInputs<'a> {
    lock: &'a [u8],
    packages: &'a [PackageSource],
    observed_urls: &'a [String],
    unexpected_urls: &'a [String],
    unrecorded_urls: &'a [String],
    acquisition: &'a Output,
    dependency_validation: &'a Output,
    build: &'a Output,
}

fn network_json(inputs: &NetworkInventoryInputs<'_>) -> String {
    let mut output = format!(
        "{{\n  \"schemaVersion\": 2,\n  \"buildOffline\": true,\n  \"networkMode\": \"observed-acquisition-then-isolated-offline-build\",\n  \"resolverLockSha256\": \"{}\",\n  \"acquisitionStdoutSha256\": \"{}\",\n  \"acquisitionStderrSha256\": \"{}\",\n  \"offlineDependencyStdoutSha256\": \"{}\",\n  \"offlineDependencyStderrSha256\": \"{}\",\n  \"offlineBuildStdoutSha256\": \"{}\",\n  \"offlineBuildStderrSha256\": \"{}\",\n  \"recordedDownloads\": [",
        sha256_bytes(inputs.lock).hex(),
        sha256_bytes(&inputs.acquisition.stdout).hex(),
        sha256_bytes(&inputs.acquisition.stderr).hex(),
        sha256_bytes(&inputs.dependency_validation.stdout).hex(),
        sha256_bytes(&inputs.dependency_validation.stderr).hex(),
        sha256_bytes(&inputs.build.stdout).hex(),
        sha256_bytes(&inputs.build.stderr).hex()
    );
    for (index, url) in inputs.observed_urls.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("\n    {\"kind\": \"observed-https-access\", \"url\": ");
        push_json(&mut output, url);
        output.push('}');
    }
    output.push_str("\n  ],\n  \"retainedPackageSources\": [");
    for (index, package) in inputs.packages.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("\n    {\"name\": ");
        push_json(&mut output, &package.name);
        output.push_str(", \"version\": ");
        push_json(&mut output, &package.version);
        output.push_str(", \"sourceChecksumSha256\": \"");
        output.push_str(&package.checksum.hex());
        output.push_str("\", \"retainedPath\": ");
        push_json(&mut output, &package.retained_path);
        output.push_str(", \"providerUrls\": [");
        for (url_index, url) in package.provider_urls.iter().enumerate() {
            if url_index != 0 {
                output.push_str(", ");
            }
            push_json(&mut output, url);
        }
        output.push_str("]}");
    }
    output.push_str("\n  ],\n  \"unexpectedEndpoints\": [");
    for (index, url) in inputs.unexpected_urls.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        push_json(&mut output, url);
    }
    output.push_str("],\n  \"unrecordedDownloads\": [");
    for (index, url) in inputs.unrecorded_urls.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        push_json(&mut output, url);
    }
    output.push_str("]\n}\n");
    output
}

fn environment_json(
    platform: &str,
    stack_version: &str,
    stack_sha256: &str,
    compiler_info_sha256: &str,
) -> Result<String, String> {
    let runner_name = github_value("RUNNER_NAME")?;
    let runner_os = github_value("RUNNER_OS")?;
    let runner_arch = github_value("RUNNER_ARCH")?;
    let os_build = if platform == "windows-amd64" {
        run_checked(Path::new("."), "systeminfo.exe", &["/FO", "CSV", "/NH"])?
    } else {
        run_checked(Path::new("."), "uname", &["-a"])?
    };
    let os_build_sha256 = sha256_bytes(&os_build.stdout).hex();
    let runner_image_identity_sha256 = sha256_bytes(
        format!("{runner_name}\n{runner_os}\n{runner_arch}\n{os_build_sha256}\n").as_bytes(),
    )
    .hex();
    let mut output = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in [
        ("platform", platform),
        ("runnerName", runner_name.as_str()),
        ("runnerOs", runner_os.as_str()),
        ("runnerArch", runner_arch.as_str()),
        ("osBuildSha256", os_build_sha256.as_str()),
        (
            "runnerImageIdentitySha256",
            runner_image_identity_sha256.as_str(),
        ),
        ("stackVersion", stack_version),
        ("stackExecutableSha256", stack_sha256),
        ("compilerInfoSha256", compiler_info_sha256),
    ] {
        output.push_str(",\n  \"");
        output.push_str(field);
        output.push_str("\": ");
        push_json(&mut output, value);
    }
    output.push_str(",\n  \"buildEnvironment\": [");
    for (index, name) in ["GHC_PACKAGE_PATH", "LANG", "LC_ALL", "PATH", "STACK_ROOT"]
        .into_iter()
        .enumerate()
    {
        if index != 0 {
            output.push(',');
        }
        let value = std::env::var_os(name).map_or_else(
            || sha256_bytes(b"<unset>").hex(),
            |value| sha256_bytes(value.as_encoded_bytes()).hex(),
        );
        output.push_str("\n    {\"name\": ");
        push_json(&mut output, name);
        output.push_str(", \"valueSha256\": ");
        push_json(&mut output, &value);
        output.push('}');
    }
    output.push_str("\n  ]\n}\n");
    Ok(output)
}

struct ProvenancePolicyInputs<'a> {
    source_commit: &'a str,
    source_tree: &'a str,
    plan: &'a Path,
    sbom: &'a Path,
    network: &'a Path,
    environment: &'a Path,
    source_files: &'a Path,
    acquisition: &'a Path,
    binary: Digest,
}

struct ProvenanceDocuments {
    plan: String,
    sbom: String,
    network: String,
    acquisition: String,
    source_files: String,
}

fn provenance_documents(
    inputs: &ProvenancePolicyInputs<'_>,
) -> Result<ProvenanceDocuments, String> {
    let plan = fs::read_to_string(inputs.plan)
        .map_err(|error| format!("cannot read provenance build plan: {error}"))?;
    let sbom = fs::read_to_string(inputs.sbom)
        .map_err(|error| format!("cannot read provenance SBOM: {error}"))?;
    let network = fs::read_to_string(inputs.network)
        .map_err(|error| format!("cannot read provenance network inventory: {error}"))?;
    let acquisition = fs::read_to_string(inputs.acquisition)
        .map_err(|error| format!("cannot read provenance acquisition receipt: {error}"))?;
    let source_files = fs::read_to_string(inputs.source_files)
        .map_err(|error| format!("cannot read provenance source inventory: {error}"))?;
    Ok(ProvenanceDocuments {
        plan,
        sbom,
        network,
        acquisition,
        source_files,
    })
}

fn provenance_checks(documents: &ProvenanceDocuments) -> [(&'static str, bool); 5] {
    [
        (
            "dependencySourcesContentAddressed",
            documents.plan.contains("\"packageDigestsComplete\": true")
                && documents
                    .acquisition
                    .contains("\"sourceAcquisitionComplete\": true"),
        ),
        (
            "networkInventoryComplete",
            documents
                .network
                .contains("\"recordedDownloads\": [\n    {")
                && documents.network.contains("\"unexpectedEndpoints\": []")
                && documents.network.contains("\"unrecordedDownloads\": []"),
        ),
        (
            "offlineBuild",
            documents.plan.contains("\"buildOffline\": true")
                && documents.network.contains("\"buildOffline\": true"),
        ),
        (
            "sbomComplete",
            !documents.sbom.contains("NOASSERTION")
                && !documents.sbom.contains("\"checksums\": []"),
        ),
        (
            "sourceInventoryComplete",
            documents.source_files.contains("\"fileCount\": ")
                && !documents.source_files.contains("\"fileCount\": 0"),
        ),
    ]
}

fn provenance_policy_json(inputs: &ProvenancePolicyInputs<'_>) -> Result<String, String> {
    let checks = provenance_checks(&provenance_documents(inputs)?);
    let failures = checks
        .iter()
        .filter_map(|(name, passed)| (!passed).then_some(*name))
        .collect::<Vec<_>>();
    let mut output = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in [
        ("sourceCommit", inputs.source_commit.to_owned()),
        ("sourceTree", inputs.source_tree.to_owned()),
        (
            "buildPlanSha256",
            sha256_file(inputs.plan)
                .map_err(|error| error.to_string())?
                .hex(),
        ),
        (
            "sbomSha256",
            sha256_file(inputs.sbom)
                .map_err(|error| error.to_string())?
                .hex(),
        ),
        (
            "networkInventorySha256",
            sha256_file(inputs.network)
                .map_err(|error| error.to_string())?
                .hex(),
        ),
        (
            "environmentSha256",
            sha256_file(inputs.environment)
                .map_err(|error| error.to_string())?
                .hex(),
        ),
        (
            "sourceFilesSha256",
            sha256_file(inputs.source_files)
                .map_err(|error| error.to_string())?
                .hex(),
        ),
        (
            "acquisitionReceiptSha256",
            sha256_file(inputs.acquisition)
                .map_err(|error| error.to_string())?
                .hex(),
        ),
        ("binarySha256", inputs.binary.hex()),
    ] {
        output.push_str(",\n  \"");
        output.push_str(field);
        output.push_str("\": ");
        push_json(&mut output, &value);
    }
    output.push_str(",\n  \"checks\": {\n    \"cleanTree\": \"pass\"");
    for (name, passed) in checks {
        output.push_str(",\n    \"");
        output.push_str(name);
        output.push_str("\": \"");
        output.push_str(if passed { "pass" } else { "fail" });
        output.push('"');
    }
    output.push_str("\n  },\n  \"failures\": [");
    for (index, failure) in failures.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        push_json(&mut output, failure);
    }
    output.push_str("],\n  \"reviewFindings\": [");
    for (index, failure) in failures.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        let mut finding = String::from("failed-provenance-check:");
        finding.push_str(failure);
        push_json(&mut output, &finding);
    }
    output.push_str("],\n  \"verdict\": \"");
    output.push_str(if failures.is_empty() { "pass" } else { "fail" });
    output.push_str("\"\n}\n");
    Ok(output)
}

struct BuilderSubject<'a> {
    candidate: &'a str,
    epoch: &'a str,
    platform: &'a str,
    source_commit: &'a str,
    source_tree: &'a str,
    builder: &'a str,
    trust_domain: &'a str,
    run_identity: &'a str,
    trigger_actor_id: &'a str,
    trigger_actor_login: &'a str,
    trigger_repository_id: &'a str,
    trigger_run_id: &'a str,
    trigger_run_attempt: &'a str,
    trigger_workflow_ref: &'a str,
    trigger_event: &'a str,
    build_plan: String,
    sbom: String,
    network: String,
    acquisition: String,
    environment: String,
    policy: String,
    binary: String,
}

fn builder_subject_json(subject: &BuilderSubject<'_>) -> String {
    let mut fields = BTreeMap::new();
    fields.insert("assuranceEpochSha256", subject.epoch);
    fields.insert("acquisitionReceiptSha256", &subject.acquisition);
    fields.insert("binarySha256", &subject.binary);
    fields.insert("buildPlanSha256", &subject.build_plan);
    fields.insert("builder", subject.builder);
    fields.insert("candidateCommit", subject.candidate);
    fields.insert("environmentSha256", &subject.environment);
    fields.insert("networkInventorySha256", &subject.network);
    fields.insert("platform", subject.platform);
    fields.insert("provenancePolicySha256", &subject.policy);
    fields.insert("runIdentity", subject.run_identity);
    fields.insert("sbomSha256", &subject.sbom);
    fields.insert("sourceCommit", subject.source_commit);
    fields.insert("sourceTree", subject.source_tree);
    fields.insert("trustDomain", subject.trust_domain);
    fields.insert("triggerActorId", subject.trigger_actor_id);
    fields.insert("triggerActorLogin", subject.trigger_actor_login);
    fields.insert("triggerEvent", subject.trigger_event);
    fields.insert("triggerRepositoryId", subject.trigger_repository_id);
    fields.insert("triggerRunAttempt", subject.trigger_run_attempt);
    fields.insert("triggerRunId", subject.trigger_run_id);
    fields.insert("triggerWorkflowRef", subject.trigger_workflow_ref);
    let mut output = String::from("{\n  \"schemaVersion\": 1");
    for (name, value) in fields {
        output.push_str(",\n  \"");
        output.push_str(name);
        output.push_str("\": ");
        push_json(&mut output, value);
    }
    output.push_str("\n}\n");
    output
}

fn command_text(directory: &Path, program: &str, arguments: &[&str]) -> Result<String, String> {
    let output = run_checked(directory, program, arguments)?;
    let text =
        String::from_utf8(output.stdout).map_err(|_| format!("{program} stdout is not UTF-8"))?;
    Ok(text.trim().to_owned())
}

fn run_checked(directory: &Path, program: &str, arguments: &[&str]) -> Result<Output, String> {
    let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
    run_checked_os(directory, program, &arguments)
}

fn run_checked_os(
    directory: &Path,
    program: &str,
    arguments: &[OsString],
) -> Result<Output, String> {
    let output = Command::new(program)
        .args(arguments)
        .current_dir(directory)
        .output()
        .map_err(|error| format!("cannot run {program}: {error}"))?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(format!(
            "{program} failed with status {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn find_executable(program: &str) -> Result<PathBuf, String> {
    let path = std::env::var_os("PATH").ok_or_else(|| "PATH is unavailable".to_owned())?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(if cfg!(windows) {
            format!("{program}.exe")
        } else {
            program.to_owned()
        });
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(format!("cannot locate executable {program:?}"))
}

fn required<'a>(value: Option<&'a PathBuf>, flag: &str) -> Result<&'a Path, String> {
    value
        .map(PathBuf::as_path)
        .ok_or_else(|| format!("oracle-ops requires {flag}"))
}

fn required_text<'a>(value: Option<&'a String>, flag: &str) -> Result<&'a str, String> {
    value
        .map(String::as_str)
        .ok_or_else(|| format!("oracle-ops requires {flag}"))
}

fn set_path(target: &mut Option<PathBuf>, value: &OsStr, flag: &str) -> Result<(), String> {
    if target.replace(PathBuf::from(value)).is_some() {
        Err(format!("{flag} was provided more than once"))
    } else {
        Ok(())
    }
}

fn set_text(target: &mut Option<String>, value: &OsStr, flag: &str) -> Result<(), String> {
    let value = value
        .to_str()
        .ok_or_else(|| format!("{flag} value must be UTF-8"))?;
    if target.replace(value.to_owned()).is_some() {
        Err(format!("{flag} was provided more than once"))
    } else {
        Ok(())
    }
}

fn require_git_sha(value: &str, label: &str) -> Result<(), String> {
    crate::promotion_policy::require_git_sha(value, label)
}

fn require_digest(value: &str, label: &str) -> Result<(), String> {
    crate::promotion_policy::require_digest(value, label)
}

fn require_atom(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'+' | b'=' | b'~' | b'%'
                )
        })
    {
        Err(format!("{label} is not a safe canonical atom"))
    } else {
        Ok(())
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes)
        .map_err(|error| format!("cannot write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("cannot replace {}: {error}", path.display()))
}

fn push_json(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value.is_control() => write!(output, "\\u{:04x}", u32::from(value))
                .expect("writing to String cannot fail"),
            value => output.push(value),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oracle_adapter_uses_no_shell_or_template_built_package_argv() {
        let source = include_str!("oracle_ops.rs");
        let shell_program = ["cmd", ".exe"].concat();
        let package_template = ["format!", "(\"{name}-{version}\")"].concat();
        assert!(!source.contains(&shell_program));
        assert!(!source.contains(&package_template));
    }

    #[test]
    fn dependency_plan_is_sorted_deduplicated_and_strict() {
        let dependencies = dependencies_from_output(b"z 2\na 1\na 1\n").unwrap();
        assert_eq!(
            dependencies,
            vec![
                ("a".to_owned(), "1".to_owned()),
                ("z".to_owned(), "2".to_owned())
            ]
        );
        assert!(dependencies_from_output(b"a 1 unexpected\n").is_err());
    }

    #[test]
    fn stack_configuration_rejects_unreviewed_local_and_mutable_sources() {
        let reviewed = "resolver: nightly-2024-10-21\nghc-options:\n  \"$everything\": \"-split-sections -j\"\n";
        let configuration =
            validate_stack_configuration_documents(reviewed, "packages: []\n").unwrap();
        assert_eq!(configuration.resolver, "nightly-2024-10-21");
        assert_eq!(configuration.declared_ghc_options.len(), 1);
        assert!(validate_stack_configuration_documents(
            "resolver: nightly-2024-10-21\npackages:\n  - ../outside\nghc-options:\n  all: -j\n",
            "packages: []\n"
        )
        .is_err());
        assert!(
            validate_stack_configuration_documents(
                reviewed,
                "packages:\n- original:\n    git: https://example.invalid/mutable.git\n"
            )
            .is_err()
        );
    }

    #[test]
    fn builder_subject_binds_identity_domain_run_and_all_typed_outputs() {
        let subject = builder_subject_json(&BuilderSubject {
            candidate: "candidate",
            epoch: "epoch",
            platform: "macos-arm64",
            source_commit: "source",
            source_tree: "tree",
            builder: "builder-one",
            trust_domain: "primary",
            run_identity: "run-one",
            trigger_actor_id: "101",
            trigger_actor_login: "review-trigger",
            trigger_repository_id: "202",
            trigger_run_id: "303",
            trigger_run_attempt: "1",
            trigger_workflow_ref: "Portfoligno/hell-rs/.github/workflows/oracle-reproduce.yml@refs/heads/main",
            trigger_event: "push",
            build_plan: "plan".to_owned(),
            sbom: "sbom".to_owned(),
            network: "network".to_owned(),
            acquisition: "acquisition".to_owned(),
            environment: "environment".to_owned(),
            policy: "policy".to_owned(),
            binary: "binary".to_owned(),
        });
        for value in [
            "builder-one",
            "primary",
            "run-one",
            "review-trigger",
            "Portfoligno/hell-rs/.github/workflows/oracle-reproduce.yml@refs/heads/main",
            "plan",
            "sbom",
            "network",
            "acquisition",
            "environment",
            "policy",
            "binary",
        ] {
            assert!(subject.contains(value));
        }
        assert!(subject.ends_with('\n'));
    }

    #[test]
    fn identity_fields_reject_control_characters_and_partial_digests() {
        assert!(require_atom("domain\nforged", "domain").is_err());
        assert!(require_atom("domain; forged", "domain").is_err());
        assert!(require_atom("domain$(forged)", "domain").is_err());
        assert!(require_git_sha("abc", "candidate").is_err());
        assert!(require_digest("abc", "epoch").is_err());
    }

    #[test]
    fn acquisition_inventory_accepts_only_observed_reviewed_https_endpoints() {
        let urls = acquisition_urls_from_text([
            "Downloading https://hackage.haskell.org/package/text-2.1.2/text-2.1.2.tar.gz",
            "Fetched (https://downloads.haskell.org/~ghc/9.8.4/ghc.tar.xz)",
        ])
        .unwrap();
        assert_eq!(urls.reviewed.len(), 2);
        assert!(urls.reviewed[0].starts_with("https://downloads.haskell.org/"));
        assert!(urls.reviewed[1].starts_with("https://hackage.haskell.org/"));
        assert!(urls.unexpected.is_empty());
        assert!(acquisition_urls_from_text(["cache hit without provider access"]).is_err());
        assert!(
            acquisition_urls_from_text([
                "https://hackage.haskell.org/package/text.tar.gz?mutable=1"
            ])
            .is_err()
        );
        assert!(
            acquisition_urls_from_text([
                "https://identity@hackage.haskell.org/package/text.tar.gz"
            ])
            .is_err()
        );
        let unexpected =
            acquisition_urls_from_text(["https://unreviewed.invalid/package/text.tar.gz"]).unwrap();
        assert!(unexpected.reviewed.is_empty());
        assert_eq!(unexpected.unexpected.len(), 1);
    }

    #[test]
    fn oracle_workflow_does_not_restore_a_stack_dependency_cache() {
        let workflow = include_str!("../../../.github/workflows/oracle-reproduce.yml");
        assert!(!workflow.contains(".stack/pantry"));
        assert!(!workflow.contains(".stack/programs"));
        assert!(workflow.contains("Acquire sources and collect pinned offline"));
        assert!(workflow.contains("Independently acquire sources and collect pinned offline"));
    }

    #[test]
    fn package_inventory_requires_observed_provider_access_for_every_retained_source() {
        let mut packages = vec![PackageSource {
            name: "text".to_owned(),
            version: "2.1.2".to_owned(),
            checksum: sha256_bytes(b"retained source"),
            retained_path: "package-sources/0".to_owned(),
            provider_urls: Vec::new(),
        }];
        let unrecorded = bind_package_accesses(
            &mut packages,
            &[
                "https://hackage.haskell.org/package/text-2.1.2/text-2.1.2.tar.gz".to_owned(),
                "https://github.com/unbound/source/archive.tar.gz".to_owned(),
            ],
        );
        assert_eq!(packages[0].provider_urls.len(), 1);
        assert_eq!(unrecorded.len(), 1);
    }

    #[test]
    fn real_oracle_renderers_round_trip_through_assurance_verifier() {
        let retained = std::env::temp_dir().join(format!(
            "oracle-producer-verifier-round-trip-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&retained);
        fs::create_dir_all(&retained).unwrap();
        let package_directory = retained.join("package-sources").join("0");
        fs::create_dir_all(&package_directory).unwrap();
        fs::write(
            package_directory.join("source.txt"),
            b"retained package source\n",
        )
        .unwrap();
        let provider_url =
            "https://hackage.haskell.org/package/example-1.0/example-1.0.tar.gz".to_owned();
        let package = PackageSource {
            name: "example".to_owned(),
            version: "1.0".to_owned(),
            checksum: directory_digest(&package_directory).unwrap(),
            retained_path: "package-sources/0".to_owned(),
            provider_urls: vec![provider_url.clone()],
        };
        let command = Command::new("rustc").arg("--version").output().unwrap();
        assert!(command.status.success());
        let lock = b"resolver-lock";
        let resolver = sha256_bytes(lock).hex();
        let digest = sha256_bytes(b"fixture").hex();
        let configuration = StackConfiguration {
            resolver: "nightly-2024-10-21".to_owned(),
            declared_ghc_options: vec!["all: -split-sections".to_owned()],
        };
        let plan = build_plan_json(
            UPSTREAM_COMMIT,
            &digest,
            "3.11.1",
            &digest,
            &digest,
            &resolver,
            &digest,
            &digest,
            &digest,
            &digest,
            &configuration,
            std::slice::from_ref(&package),
            true,
            &command,
            &command,
        );
        let sbom = sbom_json(&digest, std::slice::from_ref(&package), &resolver);
        let network = network_json(&NetworkInventoryInputs {
            lock,
            packages: std::slice::from_ref(&package),
            observed_urls: std::slice::from_ref(&provider_url),
            unexpected_urls: &[],
            unrecorded_urls: &[],
            acquisition: &command,
            dependency_validation: &command,
            build: &command,
        });
        let plan_path = retained.join("build-plan.json");
        let sbom_path = retained.join("sbom.spdx.json");
        let network_path = retained.join("network-inventory.json");
        write_atomic(&plan_path, plan.as_bytes()).unwrap();
        write_atomic(&sbom_path, sbom.as_bytes()).unwrap();
        write_atomic(&network_path, network.as_bytes()).unwrap();
        crate::assurance::verify_oracle_evidence_documents(&plan_path, &sbom_path, &network_path)
            .unwrap();
        fs::remove_dir_all(retained).unwrap();
    }
}
