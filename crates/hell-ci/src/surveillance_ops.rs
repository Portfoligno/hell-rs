use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use hell_testkit::{sha256_bytes, sha256_file};

fn component_path<const N: usize>(components: [&str; N]) -> PathBuf {
    components
        .into_iter()
        .fold(PathBuf::new(), |path, component| path.join(component))
}

fn github_value(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .ok_or_else(|| format!("surveillance requires a normalized {name}"))
}

fn github_positive(name: &str) -> Result<String, String> {
    let value = github_value(name)?;
    if value.parse::<u64>().ok().is_none_or(|number| number == 0) {
        return Err(format!("surveillance requires a positive {name}"));
    }
    Ok(value)
}

#[derive(Default)]
struct Options {
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    epoch_file: Option<PathBuf>,
    proposal: Option<PathBuf>,
    approval: Option<PathBuf>,
    gate: Option<PathBuf>,
    report: Option<PathBuf>,
    custody: Option<PathBuf>,
    objective: Option<PathBuf>,
    prior: Option<PathBuf>,
    policy: Option<PathBuf>,
    check_kind: Option<String>,
    observed_at: Option<String>,
    artifact_id: Option<String>,
}

const SURVEILLANCE_EVENTS: &[&str] = &[
    "accepted_divergence_expired",
    "artifact_attestation_invalidated",
    "critical_mutant_undetected",
    "custody_retrieval_failure",
    "platform_or_toolchain_support_expired",
    "promoted_claim_regression",
    "signing_identity_revoked",
];

#[derive(PartialEq, Eq)]
struct SurveillanceCadence {
    custody_scrub: u64,
    divergence_expiry: u64,
    mutation_suite: u64,
    differential_exploration: u64,
    runner_toolchain_drift: u64,
    trust_identity_revocation: u64,
    native_provenance_rebuild: u64,
}

#[derive(PartialEq, Eq)]
struct SurveillanceWarnings {
    divergence_expiry: Vec<u64>,
    custody_scrub_overdue: u64,
    mutation_report_maximum_age: u64,
}

#[derive(PartialEq, Eq)]
pub(crate) struct SurveillancePolicy {
    cadence: SurveillanceCadence,
    warnings: SurveillanceWarnings,
    at_risk: BTreeSet<String>,
    automatic_critical: BTreeSet<String>,
    require_signed_governance_action: bool,
    public_report_exposes_current_state: bool,
}

impl SurveillancePolicy {
    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        let document = fs::read_to_string(path)
            .map_err(|error| format!("cannot read surveillance policy: {error}"))?;
        let mut values = crate::strict_toml::assignments(&document)?;
        if crate::strict_toml::unsigned(&crate::strict_toml::take(&mut values, "schema_version")?)?
            != 1
            || !matches!(
                crate::strict_toml::string(&crate::strict_toml::take(&mut values, "state")?)?
                    .as_str(),
                "review-required" | "reviewed"
            )
        {
            return Err("surveillance policy schema or state is unsupported".to_owned());
        }
        let cadence = SurveillanceCadence {
            custody_scrub: policy_unsigned(&mut values, "cadence.custody_scrub_interval_days")?,
            divergence_expiry: policy_unsigned(
                &mut values,
                "cadence.divergence_expiry_check_interval_days",
            )?,
            mutation_suite: policy_unsigned(&mut values, "cadence.mutation_suite_interval_days")?,
            differential_exploration: policy_unsigned(
                &mut values,
                "cadence.differential_exploration_interval_days",
            )?,
            runner_toolchain_drift: policy_unsigned(
                &mut values,
                "cadence.runner_toolchain_drift_check_interval_days",
            )?,
            trust_identity_revocation: policy_unsigned(
                &mut values,
                "cadence.trust_identity_revocation_check_interval_days",
            )?,
            native_provenance_rebuild: policy_unsigned(
                &mut values,
                "cadence.native_provenance_rebuild_interval_days",
            )?,
        };
        let warnings = SurveillanceWarnings {
            divergence_expiry: crate::strict_toml::unsigned_array(&crate::strict_toml::take(
                &mut values,
                "warning_windows.divergence_expiry_days",
            )?)?,
            custody_scrub_overdue: policy_unsigned(
                &mut values,
                "warning_windows.custody_scrub_overdue_days",
            )?,
            mutation_report_maximum_age: policy_unsigned(
                &mut values,
                "warning_windows.mutation_report_maximum_age_days",
            )?,
        };
        validate_warning_windows(&warnings.divergence_expiry)?;
        let mut at_risk = BTreeSet::new();
        for event in SURVEILLANCE_EVENTS {
            if crate::strict_toml::boolean(&crate::strict_toml::take(
                &mut values,
                &format!("at_risk.{event}"),
            )?)? {
                at_risk.insert((*event).to_owned());
            }
        }
        let automatic_critical = crate::strict_toml::string_array(&crate::strict_toml::take(
            &mut values,
            "revocation.automatic_critical_events",
        )?)?
        .into_iter()
        .collect::<BTreeSet<_>>();
        if !automatic_critical
            .iter()
            .all(|event| SURVEILLANCE_EVENTS.contains(&event.as_str()))
        {
            return Err("surveillance policy names an unknown critical event".to_owned());
        }
        let require_signed_governance_action = crate::strict_toml::boolean(
            &crate::strict_toml::take(&mut values, "revocation.require_signed_governance_action")?,
        )?;
        let public_report_exposes_current_state =
            crate::strict_toml::boolean(&crate::strict_toml::take(
                &mut values,
                "revocation.public_report_exposes_current_state",
            )?)?;
        crate::strict_toml::finish(&values)?;
        Ok(Self {
            cadence,
            warnings,
            at_risk,
            automatic_critical,
            require_signed_governance_action,
            public_report_exposes_current_state,
        })
    }

    fn deadline_days(&self) -> u64 {
        [
            self.cadence.custody_scrub,
            self.cadence.divergence_expiry,
            self.cadence.mutation_suite,
            self.cadence.differential_exploration,
            self.cadence.runner_toolchain_drift,
            self.cadence.trust_identity_revocation,
            self.cadence.native_provenance_rebuild,
        ]
        .into_iter()
        .min()
        .expect("surveillance policy has fixed cadence fields")
    }

    fn event_passes(&self, event: &str, passed: bool) -> bool {
        passed || !self.at_risk.contains(event)
    }

    fn automatic_revocation(&self, event: &str, passed: bool) -> bool {
        !passed && self.automatic_critical.contains(event)
    }

    pub(crate) fn automatic_critical_events(&self) -> &BTreeSet<String> {
        &self.automatic_critical
    }

    pub(crate) fn divergence_warning_windows(&self) -> &[u64] {
        &self.warnings.divergence_expiry
    }
}

fn policy_unsigned(
    values: &mut std::collections::BTreeMap<String, String>,
    key: &str,
) -> Result<u64, String> {
    let value = crate::strict_toml::unsigned(&crate::strict_toml::take(values, key)?)?;
    (value != 0)
        .then_some(value)
        .ok_or_else(|| format!("surveillance policy {key} must be nonzero"))
}

fn validate_warning_windows(windows: &[u64]) -> Result<(), String> {
    if windows.is_empty()
        || windows.contains(&0)
        || windows.windows(2).any(|pair| pair[0] <= pair[1])
    {
        return Err(
            "divergence warning windows must be unique descending positive days".to_owned(),
        );
    }
    Ok(())
}

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments
        .first()
        .is_some_and(|value| value == "surveillance-ops")
}

pub(crate) fn run(arguments: &[OsString]) -> Result<String, String> {
    if let Some(action) = arguments.get(1).and_then(|value| value.to_str()) {
        match action {
            "workflow-final-record" => return workflow_final_record(),
            "workflow-impact" => return crate::surveillance_impact::workflow_impact(),
            "workflow-divergence-issues" => {
                return crate::surveillance_impact::workflow_divergence_issues();
            }
            "workflow-native-provenance" => return workflow_native_provenance(),
            "workflow-active-subject-selection" => {
                let (_, options) = parse(arguments)?;
                return workflow_active_subject_selection(&options);
            }
            "workflow-dispatch-native-provenance" => {
                return workflow_dispatch_native_provenance();
            }
            "workflow-retain-current-governance" => {
                return workflow_retain_current_governance();
            }
            "workflow-deadline" => return workflow_deadline(),
            "workflow-objective" => return workflow_objective(),
            "workflow-observe" => return workflow_observe(),
            "workflow-alert" => return workflow_alert(),
            "workflow-verify-approved-source" => return workflow_verify_approved_source(),
            "workflow-compare-active" => return workflow_compare_active(),
            _ => {}
        }
    }
    let (action, options) = parse(arguments)?;
    match action.as_str() {
        "final-record" => final_record(&options),
        "record" => transition_record(&options),
        "verify" => verify_transition(required_path(options.input.as_ref(), "--input")?),
        "require-promoted" => require_promoted(required_path(options.input.as_ref(), "--input")?),
        action => Err(format!("unknown surveillance-ops action {action:?}")),
    }
}

fn workflow_active_subject_selection(options: &Options) -> Result<String, String> {
    let active = component_path(["ci-out", "active-promotion-record"]);
    let promotion = read_text(&active.join("promotion-record.json"))?;
    let candidate = quoted_field(&promotion, "candidateCommit")?;
    let epoch = quoted_field(&promotion, "assuranceEpochSha256")?;
    require_git_sha(&candidate, "active subject candidate")?;
    require_digest(&epoch, "active subject epoch")?;
    let input = component_path(["ci-out", "surveillance", "active-subject"]);
    crate::suite::verify_retained_linux_surveillance_shard(&input, &active, &candidate, &epoch)?;
    let claim_index = input.join("evidence").join("claim-index.json");
    let claim_index_text = read_text(&claim_index)?;
    verify_active_executable_identity(&active, &input, &claim_index_text, &candidate, &epoch)?;
    let mutation = input.join("mutation").join("mutation-score.pending.json");
    crate::assurance::verify_surveillance_mutation_report(
        &input.join("subject-policy"),
        &mutation,
        &candidate,
        &epoch,
    )?;
    let artifact_id = options
        .artifact_id
        .clone()
        .or_else(|| std::env::var("ACTIVE_SUBJECT_ARTIFACT_ID").ok())
        .ok_or_else(|| "active subject selection requires --artifact-id".to_owned())?
        .parse::<u64>()
        .map_err(|_| "active subject artifact ID is invalid".to_owned())?;
    let run_id = github_positive("GITHUB_RUN_ID")?
        .parse::<u64>()
        .map_err(|_| "active subject run ID is invalid".to_owned())?;
    let run_attempt = github_positive("GITHUB_RUN_ATTEMPT")?
        .parse::<u64>()
        .map_err(|_| "active subject run attempt is invalid".to_owned())?;
    let event = github_value("GITHUB_EVENT_NAME")?;
    if !matches!(event.as_str(), "push" | "schedule" | "workflow_dispatch") {
        return Err("active subject artifact came from an unsupported event".to_owned());
    }
    let provider_head = github_value("GITHUB_SHA")?;
    let expected_archive_sha256 = github_value("ACTIVE_SUBJECT_ARCHIVE_SHA256")?;
    let expected_directory_sha256 = crate::custody_ops::directory_digest(&input)?;
    let output = component_path([
        "ci-out",
        "surveillance",
        "active-subject-provider-selection",
    ]);
    let selection = crate::assurance::verify_provider_artifact_selection_subject_to(
        &crate::assurance::ProviderArtifactSelectionSubject {
            root: Path::new("."),
            input_directory: &input,
            output_directory: &output,
            artifact_name: "ephemeralEvidence-active-subject-execution",
            workflow_path: ".github/workflows/promotion-surveillance.yml",
            event_name: &event,
            run_id,
            run_attempt,
            artifact_id,
            provider_head: &provider_head,
            candidate: &candidate,
            expected_directory_sha256: &expected_directory_sha256,
            expected_archive_sha256: &expected_archive_sha256,
        },
    )?;
    let selection_path = component_path([
        "ci-out",
        "surveillance",
        "active-subject-provider-selection.json",
    ]);
    write_atomic(&selection_path, selection.as_bytes())?;
    Ok("reverified exact provider-selected active subject execution and mutation facts".to_owned())
}

fn verify_active_executable_identity(
    active: &Path,
    input: &Path,
    claim_index: &str,
    candidate: &str,
    epoch: &str,
) -> Result<(), String> {
    let promoted_index = active
        .join("approved-proposal")
        .join("linux-amd64")
        .join("evidence")
        .join("claim-index.json");
    let promoted = read_text(&promoted_index)?;
    let executed_sha = quoted_field(claim_index, "candidateSha256")?;
    if quoted_field(claim_index, "candidateSourceCommit")? != candidate
        || quoted_field(claim_index, "assuranceEpochSha256")? != epoch
        || quoted_field(&promoted, "candidateSourceCommit")? != candidate
        || quoted_field(&promoted, "assuranceEpochSha256")? != epoch
        || quoted_field(&promoted, "candidateSha256")? != executed_sha
        || file_digest(&input.join("candidate").join("hell"))? != executed_sha
    {
        return Err(
            "executed active binary is not the exact immutable promoted executable identity"
                .to_owned(),
        );
    }
    Ok(())
}

fn workflow_deadline() -> Result<String, String> {
    const RUNS_ENDPOINT: &str = "repos/Portfoligno/hell-rs/actions/workflows/promotion-surveillance.yml/runs?event=schedule&per_page=1";
    const RUN_QUERY: &str = ".workflow_runs | if length == 1 then .[0] | [.id,.run_attempt,.created_at,.updated_at,.head_sha,.path,.event,.status,(.conclusion // \"pending\")] | @tsv else \"\" end";
    let observed_at = crate::custody_ops::current_utc_timestamp()?;
    let arguments = [
        OsString::from("api"),
        OsString::from("--method"),
        OsString::from("GET"),
        OsString::from(RUNS_ENDPOINT),
        OsString::from("--jq"),
        OsString::from(RUN_QUERY),
    ];
    let token = std::env::var("GITHUB_TOKEN")
        .ok()
        .filter(|token| !token.is_empty() && !token.chars().any(char::is_control))
        .ok_or_else(|| "surveillance watchdog token is unavailable or malformed".to_owned());
    let response = token
        .as_ref()
        .map_err(Clone::clone)
        .and_then(|token| github_request(token, &arguments));
    let (last_run, failure) = match response {
        Ok(output) => {
            let text = String::from_utf8(output.stdout)
                .map_err(|_| "surveillance watchdog response is not UTF-8".to_owned())?;
            let text = text.trim();
            if text.is_empty() {
                (None, Some("scheduled-run-absent"))
            } else {
                match parse_watchdog_run(text) {
                    Ok(run) => (Some(run), None),
                    Err(_) => (None, Some("scheduled-run-response-invalid")),
                }
            }
        }
        Err(_) => (None, Some("scheduled-run-api-unavailable")),
    };
    let evidence = last_run
        .as_ref()
        .zip(token.as_ref().ok())
        .map(|(run, token)| inspect_watchdog_run(token, run))
        .transpose();
    let (evidence, evidence_failure) = match evidence {
        Ok(value) => (value, None),
        Err(error) => (None, Some(error)),
    };
    let maximum_age = surveillance_deadline_days()?
        .checked_mul(86_400)
        .ok_or_else(|| "surveillance cadence exceeds supported duration".to_owned())?;
    let overdue = last_run.as_ref().is_none_or(|run| {
        crate::custody_ops::utc_age_seconds(&run.created_at)
            .map_or(true, |age| deadline_reached(age, maximum_age))
            || run.status != "completed"
            || run.conclusion != "success"
    });
    let public_state_verified = component_path([
        "ci-out",
        "surveillance",
        "public-current-state-observation.json",
    ])
    .is_file();
    let overdue = overdue
        || !public_state_verified
        || evidence.is_none()
        || evidence
            .as_ref()
            .is_some_and(|record| record.derived_state != "promoted");
    write_boolean_github_output("overdue", overdue)?;
    if !overdue {
        return Ok("verified the scheduled promotion surveillance deadline".to_owned());
    }
    retain_watchdog_failure(
        &observed_at,
        last_run.as_ref(),
        failure
            .or((!public_state_verified).then_some("public-current-state-invalid"))
            .or(evidence_failure.as_deref()),
        evidence.as_ref(),
    )
}

fn retain_watchdog_failure(
    observed_at: &str,
    last_run: Option<&WatchdogRun>,
    failure: Option<&str>,
    evidence: Option<&WatchdogEvidence>,
) -> Result<String, String> {
    let derived_failure = failure.or_else(|| {
        last_run.map(|run| {
            if run.status != "completed" {
                "scheduled-run-incomplete"
            } else if run.conclusion != "success" {
                "scheduled-run-failed"
            } else if evidence.is_some_and(|record| record.derived_state != "promoted") {
                "scheduled-transition-not-promoted"
            } else {
                "deadline-exceeded"
            }
        })
    });
    let selection_path =
        component_path(["ci-out", "surveillance", "watchdog-artifact-selection.json"]);
    let selection_digest = if selection_path.is_file() {
        file_digest(&selection_path)?
    } else {
        sha256_bytes(b"watchdog-artifact-selection-unavailable").hex()
    };
    let observation =
        watchdog_observation(observed_at, last_run, derived_failure, &selection_digest);
    let observation_path = component_path(["ci-out", "surveillance", "watchdog-observation.json"]);
    write_atomic(&observation_path, observation.as_bytes())?;
    let (observer_candidate, observer_epoch) = crate::assurance::epoch(Path::new("."))?;
    let observer_epoch = observer_epoch.hex();
    let active = active_watchdog_subject().ok();
    let subject = evidence.or(active.as_ref());
    let (subject_state, candidate, epoch, prior_state, supersedes) = subject.map_or_else(
        || {
            (
                "observer-source-only",
                observer_candidate,
                observer_epoch,
                "unknown".to_owned(),
                sha256_bytes(b"unavailable-watchdog-prior-state").hex(),
            )
        },
        |evidence| {
            (
                "known",
                evidence.candidate.clone(),
                evidence.epoch.clone(),
                evidence.derived_state.clone(),
                evidence.transition_sha256.clone(),
            )
        },
    );
    let observation_sha256 = file_digest(&observation_path)?;
    let policy_sha256 = file_digest(&component_path(["compat", "surveillance-policy.toml"]))?;
    let failure_sha256 = sha256_bytes(b"promotion-surveillance-deadline-missed").hex();
    let mut transition = String::from("{\n  \"schemaVersion\": 2");
    for (field, value) in [
        ("subjectState", subject_state),
        ("candidateCommit", candidate.as_str()),
        ("assuranceEpochSha256", epoch.as_str()),
        ("primaryObservationSha256", observation_sha256.as_str()),
        ("secondaryObservationSha256", observation_sha256.as_str()),
        ("surveillancePolicySha256", policy_sha256.as_str()),
        ("checkKind", "schedule-watchdog"),
        ("observedAt", observed_at),
        ("result", "fail"),
        ("priorState", prior_state.as_str()),
        ("derivedState", "at-risk"),
        ("failureSha256", failure_sha256.as_str()),
        ("supersedesSha256", supersedes.as_str()),
    ] {
        transition.push_str(",\n  \"");
        transition.push_str(field);
        transition.push_str("\": ");
        push_json(&mut transition, value);
    }
    transition.push_str(",\n  \"incidentRequired\": true\n}\n");
    let transition_path = component_path(["ci-out", "surveillance", "promotion-transition.json"]);
    write_atomic(&transition_path, transition.as_bytes())?;
    verify_transition(&transition_path)?;
    Ok("retained signed-ready at-risk transition for a missed surveillance deadline".to_owned())
}

fn deadline_reached(age_seconds: u64, maximum_seconds: u64) -> bool {
    age_seconds >= maximum_seconds
}

struct WatchdogRun {
    run_id: u64,
    run_attempt: u64,
    created_at: String,
    updated_at: String,
    head_sha: String,
    workflow_path: String,
    event: String,
    status: String,
    conclusion: String,
}

struct WatchdogEvidence {
    candidate: String,
    epoch: String,
    derived_state: String,
    transition_sha256: String,
}

fn parse_watchdog_run(value: &str) -> Result<WatchdogRun, String> {
    let fields = value.split('\t').collect::<Vec<_>>();
    if fields.len() != 9 {
        return Err("surveillance watchdog response has an unexpected shape".to_owned());
    }
    let run_id = require_nonzero(fields[0], "surveillance watchdog run ID")?;
    let run_attempt = require_nonzero(fields[1], "surveillance watchdog run attempt")?;
    crate::custody_ops::validate_utc_timestamp(fields[2])?;
    crate::custody_ops::validate_utc_timestamp(fields[3])?;
    require_git_sha(fields[4], "surveillance watchdog run head")?;
    if fields[5] != ".github/workflows/promotion-surveillance.yml" || fields[6] != "schedule" {
        return Err("surveillance watchdog selected the wrong workflow or event".to_owned());
    }
    for (label, field) in [("status", fields[7]), ("conclusion", fields[8])] {
        require_atom(field, label)?;
    }
    Ok(WatchdogRun {
        run_id,
        run_attempt,
        created_at: fields[2].to_owned(),
        updated_at: fields[3].to_owned(),
        head_sha: fields[4].to_owned(),
        workflow_path: fields[5].to_owned(),
        event: fields[6].to_owned(),
        status: fields[7].to_owned(),
        conclusion: fields[8].to_owned(),
    })
}

fn inspect_watchdog_run(token: &str, run: &WatchdogRun) -> Result<WatchdogEvidence, String> {
    let current_head =
        std::env::var("GITHUB_SHA").map_err(|_| "scheduled-run-head-unavailable".to_owned())?;
    if !watchdog_head_matches(&run.head_sha, &current_head) {
        return Err("scheduled-run-head-mismatch".to_owned());
    }
    let workflow_digest = file_digest(&component_path([
        ".github",
        "workflows",
        "promotion-surveillance.yml",
    ]))?;
    let endpoint = component_path(["repos", "Portfoligno", "hell-rs", "actions", "runs"])
        .join(run.run_id.to_string())
        .join("artifacts");
    let output = github_request(
        token,
        &[
            OsString::from("api"),
            OsString::from("--method"),
            OsString::from("GET"),
            endpoint.as_os_str().to_owned(),
            OsString::from("--jq"),
            OsString::from(
                ".artifacts[] | [.id,.name,.digest,.expired,.created_at,.expires_at] | @tsv",
            ),
        ],
    )
    .map_err(|_| "scheduled-run-artifact-api-unavailable".to_owned())?;
    let artifacts = String::from_utf8(output.stdout)
        .map_err(|_| "scheduled-run-artifact-response-invalid".to_owned())?;
    let expected_name = [
        "promotion-surveillance".to_owned(),
        run.run_id.to_string(),
        run.run_attempt.to_string(),
    ]
    .join("-");
    let artifact = artifacts
        .lines()
        .filter_map(|line| parse_watchdog_artifact(line).ok())
        .filter(|artifact| artifact.name == expected_name)
        .collect::<Vec<_>>();
    if artifact.len() != 1 {
        return Err("scheduled-run-artifact-not-exact".to_owned());
    }
    let artifact = &artifact[0];
    let destination = component_path(["ci-out", "watchdog-scheduled"]);
    let download = [
        OsString::from("run"),
        OsString::from("download"),
        OsString::from(run.run_id.to_string()),
        OsString::from("--repo"),
        OsString::from("Portfoligno/hell-rs"),
        OsString::from("--name"),
        OsString::from(&artifact.name),
        OsString::from("--dir"),
        destination.as_os_str().to_owned(),
    ];
    github_request(token, &download)
        .map_err(|_| "scheduled-run-artifact-download-failed".to_owned())?;
    let transition = destination.join("promotion-transition.json");
    let objective = destination.join("objective-checks.json");
    let envelope = destination.join("promotion-transition.dsse.json");
    verify_transition(&transition).map_err(|_| "scheduled-run-transition-invalid".to_owned())?;
    let transition_text = read_text(&transition)?;
    let candidate = quoted_field(&transition_text, "candidateCommit")?;
    let epoch = quoted_field(&transition_text, "assuranceEpochSha256")?;
    let objective_digest = file_digest(&objective)?;
    if objective_digest != quoted_field(&transition_text, "objectiveInputSha256")? {
        return Err("scheduled-run-objective-digest-mismatch".to_owned());
    }
    let required = BTreeSet::from([
        file_digest(&transition)?,
        objective_digest,
        quoted_field(&transition_text, "supersedesSha256")?,
    ]);
    crate::assurance::verify_review_binding(
        &envelope,
        &component_path(["compat", "reviews.allowed_signers"]),
        "custody-reviewer",
        &candidate,
        &epoch,
        &required,
    )
    .map_err(|_| "scheduled-run-transition-signature-invalid".to_owned())?;
    let metadata = watchdog_artifact_metadata(run, artifact, &workflow_digest, &objective)?;
    write_atomic(
        &component_path(["ci-out", "surveillance", "watchdog-artifact-selection.json"]),
        metadata.as_bytes(),
    )?;
    Ok(WatchdogEvidence {
        candidate,
        epoch,
        derived_state: quoted_field(&transition_text, "derivedState")?,
        transition_sha256: file_digest(&transition)?,
    })
}

fn active_watchdog_subject() -> Result<WatchdogEvidence, String> {
    let path = component_path([
        "ci-out",
        "active-promotion-record",
        "promotion-current-state.json",
    ]);
    let document = read_text(&path)?;
    let candidate = quoted_field(&document, "candidateCommit")?;
    let epoch = quoted_field(&document, "assuranceEpochSha256")?;
    require_git_sha(&candidate, "active watchdog candidate")?;
    require_digest(&epoch, "active watchdog epoch")?;
    Ok(WatchdogEvidence {
        candidate,
        epoch,
        derived_state: required_canonical_state(&document)?.to_owned(),
        transition_sha256: file_digest(&path)?,
    })
}

fn watchdog_head_matches(observed: &str, expected: &str) -> bool {
    observed == expected
}

struct WatchdogArtifact {
    artifact_id: u64,
    name: String,
    digest: String,
    created_at: String,
    expires_at: String,
}

fn parse_watchdog_artifact(value: &str) -> Result<WatchdogArtifact, String> {
    let fields = value.split('\t').collect::<Vec<_>>();
    if fields.len() != 6 || fields[3] != "false" {
        return Err("surveillance artifact metadata is incomplete or expired".to_owned());
    }
    let artifact_id = require_nonzero(fields[0], "surveillance artifact ID")?;
    require_atom(fields[1], "surveillance artifact name")?;
    let digest = fields[2]
        .strip_prefix("sha256:")
        .ok_or_else(|| "surveillance artifact lacks SHA-256 provider digest".to_owned())?;
    require_digest(digest, "surveillance provider artifact")?;
    crate::custody_ops::validate_utc_timestamp(fields[4])?;
    crate::custody_ops::validate_utc_timestamp(fields[5])?;
    Ok(WatchdogArtifact {
        artifact_id,
        name: fields[1].to_owned(),
        digest: digest.to_owned(),
        created_at: fields[4].to_owned(),
        expires_at: fields[5].to_owned(),
    })
}

fn watchdog_artifact_metadata(
    run: &WatchdogRun,
    artifact: &WatchdogArtifact,
    workflow_digest: &str,
    objective: &Path,
) -> Result<String, String> {
    let objective_digest = file_digest(objective)?;
    let mut output = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in [
        ("workflowPath", run.workflow_path.as_str()),
        ("workflowBlobSha256", workflow_digest),
        ("event", run.event.as_str()),
        ("headSha", run.head_sha.as_str()),
        ("createdAt", run.created_at.as_str()),
        ("updatedAt", run.updated_at.as_str()),
        ("artifactName", artifact.name.as_str()),
        ("artifactProviderSha256", artifact.digest.as_str()),
        ("artifactCreatedAt", artifact.created_at.as_str()),
        ("artifactExpiresAt", artifact.expires_at.as_str()),
        ("objectiveSha256", objective_digest.as_str()),
    ] {
        output.push_str(",\n  \"");
        output.push_str(field);
        output.push_str("\": ");
        push_json(&mut output, value);
    }
    write!(
        output,
        ",\n  \"runId\": {},\n  \"runAttempt\": {},\n  \"artifactId\": {}\n}}\n",
        run.run_id, run.run_attempt, artifact.artifact_id
    )
    .expect("writing to String cannot fail");
    Ok(output)
}

fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn surveillance_deadline_days() -> Result<u64, String> {
    Ok(
        SurveillancePolicy::load(&component_path(["compat", "surveillance-policy.toml"]))?
            .deadline_days(),
    )
}

fn watchdog_observation(
    observed_at: &str,
    run: Option<&WatchdogRun>,
    failure: Option<&str>,
    selection_digest: &str,
) -> String {
    let mut output = String::from("{\n  \"schemaVersion\": 1");
    output.push_str(",\n  \"observedAt\": ");
    push_json(&mut output, observed_at);
    output.push_str(",\n  \"lastRunKnown\": ");
    output.push_str(if run.is_some() { "true" } else { "false" });
    output.push_str(",\n  \"lastRunId\": ");
    output.push_str(&run.map_or(0, |value| value.run_id).to_string());
    for (field, value) in [
        (
            "lastRunCreatedAt",
            run.map_or("unknown", |value| value.created_at.as_str()),
        ),
        (
            "lastRunStatus",
            run.map_or("unknown", |value| value.status.as_str()),
        ),
        (
            "lastRunConclusion",
            run.map_or("unknown", |value| value.conclusion.as_str()),
        ),
        ("artifactSelectionSha256", selection_digest),
        ("failureCode", failure.unwrap_or("deadline-exceeded")),
    ] {
        output.push_str(",\n  \"");
        output.push_str(field);
        output.push_str("\": ");
        push_json(&mut output, value);
    }
    output.push_str("\n}\n");
    output
}

fn write_boolean_github_output(key: &str, value: bool) -> Result<(), String> {
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

fn workflow_alert() -> Result<String, String> {
    const REPOSITORY: &str = "Portfoligno/hell-rs";
    const TITLE: &str = "Promotion surveillance requires incident review";
    let repository = std::env::var("GITHUB_REPOSITORY")
        .map_err(|_| "incident alert lacks GITHUB_REPOSITORY".to_owned())?;
    if repository != REPOSITORY {
        return Err("incident alert repository identity is not authorized".to_owned());
    }
    let server = std::env::var("GITHUB_SERVER_URL")
        .map_err(|_| "incident alert lacks GITHUB_SERVER_URL".to_owned())?;
    if server != "https://github.com" {
        return Err("incident alert server identity is not authorized".to_owned());
    }
    let run_id = std::env::var("GITHUB_RUN_ID")
        .map_err(|_| "incident alert lacks GITHUB_RUN_ID".to_owned())?;
    require_nonzero(&run_id, "surveillance run ID")?;
    let token = std::env::var("GITHUB_TOKEN")
        .map_err(|_| "incident alert lacks its workflow token".to_owned())?;
    if token.is_empty() || token.chars().any(char::is_control) {
        return Err("incident alert workflow token is malformed".to_owned());
    }
    let body_path = component_path(["ci-out", "surveillance", "incident-body.md"]);
    let body = format!(
        "The scheduled promotion surveillance run failed closed. A signed at-risk transition is retained when the state-signing path remained available.\n\nRun: {server}/{REPOSITORY}/actions/runs/{run_id}\n\nReview `ci-out/surveillance/regression-impact.json` for exact affected claim cells, evidence references, review groups, and public statements. Also review retrieval, objective components, transition signing, and durable publication evidence before resolving this incident.\n"
    );
    write_atomic(&body_path, body.as_bytes())?;
    let existing = github_request(
        &token,
        &[
            OsString::from("issue"),
            OsString::from("list"),
            OsString::from("--repo"),
            OsString::from(REPOSITORY),
            OsString::from("--state"),
            OsString::from("open"),
            OsString::from("--search"),
            OsString::from("Promotion surveillance requires incident review in:title"),
            OsString::from("--json"),
            OsString::from("number,title"),
            OsString::from("--jq"),
            OsString::from(
                "map(select(.title == \"Promotion surveillance requires incident review\")) | .[0].number // empty",
            ),
        ],
    )?;
    let issue = String::from_utf8(existing.stdout)
        .map_err(|_| "GitHub issue selection is not UTF-8".to_owned())?;
    let issue = issue.trim();
    let mut arguments = if issue.is_empty() {
        vec![
            OsString::from("issue"),
            OsString::from("create"),
            OsString::from("--repo"),
            OsString::from(REPOSITORY),
            OsString::from("--title"),
            OsString::from(TITLE),
        ]
    } else {
        require_nonzero(issue, "existing incident issue number")?;
        vec![
            OsString::from("issue"),
            OsString::from("comment"),
            OsString::from(issue),
            OsString::from("--repo"),
            OsString::from(REPOSITORY),
        ]
    };
    arguments.push(OsString::from("--body-file"));
    arguments.push(body_path.as_os_str().to_owned());
    github_request(&token, &arguments)?;
    Ok("upserted promotion surveillance incident without exposing credentials".to_owned())
}

pub(crate) fn github_request(
    token: &str,
    arguments: &[OsString],
) -> Result<std::process::Output, String> {
    let output = Command::new("gh")
        .args(arguments)
        .env("GH_TOKEN", token)
        .env_remove("GITHUB_TOKEN")
        .output()
        .map_err(|error| format!("cannot execute typed GitHub request: {error}"))?;
    output
        .status
        .success()
        .then_some(output)
        .ok_or_else(|| "typed GitHub request failed; response content was redacted".to_owned())
}

fn require_promoted(path: &Path) -> Result<String, String> {
    verify_transition(path)?;
    let document = fs::read_to_string(path)
        .map_err(|error| format!("cannot read transition {}: {error}", path.display()))?;
    if quoted_field(&document, "derivedState")? != "promoted" {
        return Err("promotion surveillance derived at-risk or revoked state".to_owned());
    }
    Ok("promotion remains promoted after objective surveillance".to_owned())
}

fn workflow_compare_active() -> Result<String, String> {
    let primary = component_path(["ci-out", "active-primary"]);
    let secondary = component_path(["ci-out", "active-secondary"]);
    let primary_observation_path = primary.join("provider-observation.json");
    let secondary_observation_path = secondary.join("provider-observation.json");
    let primary_observation = fs::read_to_string(&primary_observation_path)
        .map_err(|error| format!("cannot read primary provider observation: {error}"))?;
    let secondary_observation = fs::read_to_string(&secondary_observation_path)
        .map_err(|error| format!("cannot read secondary provider observation: {error}"))?;
    let primary_signer = verify_provider_observation(&primary, &primary_observation)?;
    let secondary_signer = verify_provider_observation(&secondary, &secondary_observation)?;
    require_distinct_provider_signers(&primary_signer, &secondary_signer)?;
    if quoted_field(&primary_observation, "result")? != "pass"
        || quoted_field(&secondary_observation, "result")? != "pass"
    {
        for require_transition in [true, false] {
            for (root, observation) in [
                (&primary, primary_observation.as_str()),
                (&secondary, secondary_observation.as_str()),
            ] {
                if boolean_field(observation, "transitionAvailable")? == require_transition
                    && materialize_degraded_active(root, observation)?
                {
                    return Ok(
                        "retained one verifiable active provider and preserved fail-closed state"
                            .to_owned(),
                    );
                }
            }
        }
        return Err(
            "all signed provider observations failed without retrievable evidence".to_owned(),
        );
    }
    materialize_agreed_active(
        &primary,
        &secondary,
        &primary_observation,
        &secondary_observation,
    )
}

fn materialize_agreed_active(
    primary: &Path,
    secondary: &Path,
    primary_observation: &str,
    secondary_observation: &str,
) -> Result<String, String> {
    let primary_package = primary.join("package");
    let secondary_package = secondary.join("package");
    let primary_digest = crate::custody_ops::directory_digest(&primary_package)?;
    if primary_digest != crate::custody_ops::directory_digest(&secondary_package)? {
        return Err("active custody providers select different promotion packages".to_owned());
    }
    let primary_activation = primary.join("activation").join("activation-receipt.json");
    let secondary_activation = secondary.join("activation").join("activation-receipt.json");
    let primary_text = fs::read_to_string(&primary_activation)
        .map_err(|error| format!("cannot read primary activation: {error}"))?;
    let secondary_text = fs::read_to_string(&secondary_activation)
        .map_err(|error| format!("cannot read secondary activation: {error}"))?;
    for field in [
        "candidateCommit",
        "assuranceEpochSha256",
        "manifestSha256",
        "custodyGateSha256",
    ] {
        if quoted_field(&primary_text, field)? != quoted_field(&secondary_text, field)? {
            return Err(format!("active provider activations disagree on {field}"));
        }
    }
    for (activation, observation) in [
        (&primary_text, &primary_observation),
        (&secondary_text, &secondary_observation),
    ] {
        if quoted_field(activation, "candidateCommit")?
            != quoted_field(observation, "candidateCommit")?
            || quoted_field(activation, "assuranceEpochSha256")?
                != quoted_field(observation, "assuranceEpochSha256")?
        {
            return Err("signed provider observation differs from active activation".to_owned());
        }
    }
    if quoted_field(&primary_text, "provider")? == quoted_field(&secondary_text, "provider")?
        || quoted_field(&primary_text, "trustDomain")?
            == quoted_field(&secondary_text, "trustDomain")?
    {
        return Err("active promotion lacks two independent provider activations".to_owned());
    }
    verify_activation_envelope(primary)?;
    verify_activation_envelope(secondary)?;
    let primary_transition = verify_provider_current_transition(primary, primary_observation)?;
    let secondary_transition =
        verify_provider_current_transition(secondary, secondary_observation)?;
    let current_transition = require_agreed_current_transition(
        primary_transition.as_ref(),
        secondary_transition.as_ref(),
    )?;
    let output = component_path(["ci-out", "active-promotion-record"]);
    crate::custody_ops::materialize_verified_package(&primary_package, &output)?;
    let candidate = quoted_field(&primary_text, "candidateCommit")?;
    let epoch = quoted_field(&primary_text, "assuranceEpochSha256")?;
    if let Some(correlation) =
        verify_surveillance_trigger(&candidate, &epoch, &primary_text, &secondary_text)?
    {
        retain_initial_activation_correlation(
            &candidate,
            &epoch,
            &primary_text,
            &secondary_text,
            &correlation,
        )?;
    }
    let promoted_at = crate::custody_ops::current_utc_timestamp()?;
    let primary_dsse = primary
        .join("activation")
        .join("activation-receipt.dsse.json");
    let secondary_dsse = secondary
        .join("activation")
        .join("activation-receipt.dsse.json");
    let state = if let Some(transition) = current_transition {
        read_text(&transition.path)?
    } else {
        promotion_current_state_json(
            &candidate,
            &epoch,
            &file_digest(&output.join("promotion-record.json"))?,
            &file_digest(&primary_dsse)?,
            &file_digest(&secondary_dsse)?,
            &promoted_at,
        )
    };
    write_atomic(
        &output.join("promotion-current-state.json"),
        state.as_bytes(),
    )?;
    let linux_claim_index = read_text(
        &output
            .join("approved-proposal")
            .join("linux-amd64")
            .join("evidence")
            .join("claim-index.json"),
    )?;
    let oracle_sha256 = quoted_field(&linux_claim_index, "oracleSha256")?;
    require_digest(&oracle_sha256, "active Linux oracle")?;
    write_github_output("candidate", &candidate)?;
    write_github_output("oracle_sha256", &oracle_sha256)?;
    Ok("verified two signed active provider contexts and preserved their current state".to_owned())
}

fn verify_surveillance_trigger(
    candidate: &str,
    epoch: &str,
    primary_activation: &str,
    secondary_activation: &str,
) -> Result<Option<String>, String> {
    match std::env::var("GITHUB_EVENT_NAME").as_deref() {
        Ok("schedule") => Ok(None),
        Ok("push") => {
            let git_ref = github_value("GITHUB_REF")?;
            let workflow_ref = github_value("GITHUB_WORKFLOW_REF")?;
            let provider_head = github_value("GITHUB_SHA")?;
            let current_head = surveillance_current_head()?;
            if !trusted_push_surveillance_trigger(
                &git_ref,
                &workflow_ref,
                &provider_head,
                current_head.trim(),
            ) {
                return Err("push surveillance is not exact trusted main source".to_owned());
            }
            Ok(None)
        }
        Ok("workflow_dispatch") => {
            let inputs = surveillance_dispatch_inputs()?;
            let run_id = inputs
                .get("activation_run_id")
                .map(String::as_str)
                .and_then(|value| value.parse::<u64>().ok());
            let run_attempt = inputs
                .get("activation_run_attempt")
                .map(String::as_str)
                .and_then(|value| value.parse::<u64>().ok());
            if inputs.get("candidate_sha").map(String::as_str) != Some(candidate)
                || inputs.get("assurance_epoch_sha256").map(String::as_str) != Some(epoch)
                || run_id.is_none_or(|value| value == 0)
                || run_attempt.is_none_or(|value| value == 0)
            {
                return Err(
                    "initial surveillance dispatch differs from active promotion".to_owned(),
                );
            }
            crate::custody_ops::verify_activation_run_binding(
                primary_activation,
                secondary_activation,
                run_id.ok_or_else(|| "activation run ID is absent".to_owned())?,
                run_attempt.ok_or_else(|| "activation run attempt is absent".to_owned())?,
            )?;
            let correlation = crate::custody_ops::initial_activation_correlation(
                candidate,
                epoch,
                run_id.ok_or_else(|| "activation run ID is absent".to_owned())?,
                run_attempt.ok_or_else(|| "activation run attempt is absent".to_owned())?,
                &sha256_bytes(primary_activation.as_bytes()).hex(),
                &sha256_bytes(secondary_activation.as_bytes()).hex(),
            );
            if inputs
                .get("activation_correlation_sha256")
                .map(String::as_str)
                != Some(correlation.as_str())
            {
                return Err("initial surveillance activation correlation changed".to_owned());
            }
            Ok(Some(correlation))
        }
        _ => Err("promotion surveillance provider event is unsupported".to_owned()),
    }
}

fn surveillance_dispatch_inputs() -> Result<std::collections::BTreeMap<String, String>, String> {
    let inputs = crate::assurance::github_dispatch_object(&[
        "activation_correlation_sha256",
        "activation_run_attempt",
        "activation_run_id",
        "assurance_epoch_sha256",
        "candidate_sha",
        "selector_archive_sha256",
        "selector_artifact_id",
        "selector_directory_sha256",
        "selector_run_attempt",
        "selector_run_id",
        "selector_source_sha",
    ])?;
    for key in ["selector_archive_sha256", "selector_directory_sha256"] {
        require_digest(
            inputs
                .get(key)
                .map(String::as_str)
                .ok_or_else(|| format!("surveillance dispatch lacks {key}"))?,
            "surveillance selector digest",
        )?;
    }
    for key in [
        "selector_artifact_id",
        "selector_run_attempt",
        "selector_run_id",
    ] {
        require_nonzero(
            inputs
                .get(key)
                .map(String::as_str)
                .ok_or_else(|| format!("surveillance dispatch lacks {key}"))?,
            "surveillance selector provider identity",
        )?;
    }
    require_git_sha(
        inputs
            .get("selector_source_sha")
            .map(String::as_str)
            .ok_or_else(|| "surveillance dispatch lacks selector_source_sha".to_owned())?,
        "surveillance selector source",
    )?;
    Ok(inputs)
}

fn surveillance_current_head() -> Result<String, String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| format!("cannot resolve surveillance checkout: {error}"))?;
    if !output.status.success() {
        return Err("cannot resolve surveillance checkout".to_owned());
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| "surveillance checkout is not UTF-8".to_owned())
}

fn trusted_push_surveillance_trigger(
    git_ref: &str,
    workflow_ref: &str,
    provider_head: &str,
    current_head: &str,
) -> bool {
    crate::assurance::trusted_surveillance_subject_identity("push", git_ref, workflow_ref)
        && provider_head == current_head
        && require_git_sha(provider_head, "push surveillance head").is_ok()
}

fn retain_initial_activation_correlation(
    candidate: &str,
    epoch: &str,
    primary_activation: &str,
    secondary_activation: &str,
    correlation: &str,
) -> Result<(), String> {
    let output = component_path([
        "ci-out",
        "surveillance",
        "initial-activation-correlation.json",
    ]);
    fs::create_dir_all(
        output
            .parent()
            .ok_or_else(|| "activation correlation output has no parent".to_owned())?,
    )
    .map_err(|error| format!("cannot create activation correlation output: {error}"))?;
    let document = format!(
        "{{\n  \"schemaVersion\": 1,\n  \"candidateCommit\": \"{candidate}\",\n  \"assuranceEpochSha256\": \"{epoch}\",\n  \"activationRunId\": {},\n  \"activationRunAttempt\": {},\n  \"activationCorrelationSha256\": \"{correlation}\",\n  \"primaryActivationSha256\": \"{}\",\n  \"secondaryActivationSha256\": \"{}\",\n  \"state\": \"signed-dual-activation-bound\"\n}}\n",
        unsigned_field(primary_activation, "activationRunId")?,
        unsigned_field(primary_activation, "activationRunAttempt")?,
        sha256_bytes(primary_activation.as_bytes()).hex(),
        sha256_bytes(secondary_activation.as_bytes()).hex(),
    );
    write_atomic(&output, document.as_bytes())
}

struct VerifiedCurrentTransition {
    path: PathBuf,
    record_sha256: String,
    packet_sha256: String,
    dsse_sha256: String,
    derived_state: String,
    observed_at: String,
    supersedes_sha256: String,
}

fn verify_provider_current_transition(
    root: &Path,
    observation: &str,
) -> Result<Option<VerifiedCurrentTransition>, String> {
    let available = boolean_field(observation, "transitionAvailable")?;
    let empty = sha256_bytes(b"").hex();
    let record_sha256 = quoted_field(observation, "transitionRecordSha256")?;
    let packet_sha256 = quoted_field(observation, "transitionPacketSha256")?;
    let dsse_sha256 = quoted_field(observation, "transitionDsseSha256")?;
    let supersedes_sha256 = quoted_field(observation, "transitionSupersedesSha256")?;
    if !available {
        if [
            record_sha256.as_str(),
            packet_sha256.as_str(),
            dsse_sha256.as_str(),
            supersedes_sha256.as_str(),
        ]
        .iter()
        .any(|digest| *digest != empty)
            || quoted_field(observation, "transitionDerivedState")? != "initial-activation"
        {
            return Err("provider observation has inconsistent absent transition facts".to_owned());
        }
        return Ok(None);
    }
    for (label, digest) in [
        ("transition record", record_sha256.as_str()),
        ("transition packet", packet_sha256.as_str()),
        ("transition DSSE", dsse_sha256.as_str()),
        ("transition supersedes", supersedes_sha256.as_str()),
    ] {
        require_digest(digest, label)?;
    }
    let directory = root.join("transition");
    let record = directory.join("promotion-transition.json");
    let packet = directory.join("promotion-transition-packet.json");
    let dsse = directory.join("promotion-transition.dsse.json");
    for (path, expected) in [
        (&record, record_sha256.as_str()),
        (&packet, packet_sha256.as_str()),
        (&dsse, dsse_sha256.as_str()),
    ] {
        if file_digest(path)? != expected {
            return Err("provider transition object differs from signed observation".to_owned());
        }
    }
    verify_transition(&record)?;
    let record_text = read_text(&record)?;
    if quoted_field(&record_text, "candidateCommit")?
        != quoted_field(observation, "candidateCommit")?
        || quoted_field(&record_text, "assuranceEpochSha256")?
            != quoted_field(observation, "assuranceEpochSha256")?
        || quoted_field(&record_text, "derivedState")?
            != quoted_field(observation, "transitionDerivedState")?
        || quoted_field(&record_text, "observedAt")?
            != quoted_field(observation, "transitionObservedAt")?
        || quoted_field(&record_text, "supersedesSha256")? != supersedes_sha256
    {
        return Err("provider transition record differs from signed observation facts".to_owned());
    }
    crate::assurance::verify_review_packet_first_artifact(
        &packet,
        "custody-reviewer",
        &quoted_field(&record_text, "candidateCommit")?,
        &quoted_field(&record_text, "assuranceEpochSha256")?,
        &record_sha256,
    )?;
    verify_review_envelope(&dsse, "custody-reviewer")?;
    Ok(Some(VerifiedCurrentTransition {
        path: record,
        record_sha256,
        packet_sha256,
        dsse_sha256,
        derived_state: quoted_field(&record_text, "derivedState")?,
        observed_at: quoted_field(&record_text, "observedAt")?,
        supersedes_sha256,
    }))
}

fn require_agreed_current_transition<'a>(
    primary: Option<&'a VerifiedCurrentTransition>,
    secondary: Option<&VerifiedCurrentTransition>,
) -> Result<Option<&'a VerifiedCurrentTransition>, String> {
    match (primary, secondary) {
        (None, None) => Ok(None),
        (Some(first), Some(second))
            if first.record_sha256 == second.record_sha256
                && first.packet_sha256 == second.packet_sha256
                && first.dsse_sha256 == second.dsse_sha256
                && first.derived_state == second.derived_state
                && first.observed_at == second.observed_at
                && first.supersedes_sha256 == second.supersedes_sha256 =>
        {
            Ok(Some(first))
        }
        _ => Err("active providers disagree on the signed current transition".to_owned()),
    }
}

fn verify_provider_observation(root: &Path, document: &str) -> Result<(String, String), String> {
    let candidate = quoted_field(document, "candidateCommit")?;
    let epoch = quoted_field(document, "assuranceEpochSha256")?;
    let manifest = quoted_field(document, "manifestSha256")?;
    require_git_sha(&candidate, "provider observation candidate")?;
    require_digest(&epoch, "provider observation epoch")?;
    require_digest(&manifest, "provider observation manifest")?;
    let observation = root.join("provider-observation.json");
    let observation_digest = file_digest(&observation)?;
    let required_artifacts = BTreeSet::from([manifest, observation_digest]);
    crate::assurance::verify_review_binding(
        &root.join("provider-observation.dsse.json"),
        &component_path(["compat", "reviews.allowed_signers"]),
        "custody-provider",
        &candidate,
        &epoch,
        &required_artifacts,
    )
}

fn require_distinct_provider_signers(
    primary: &(String, String),
    secondary: &(String, String),
) -> Result<(), String> {
    if crate::assurance_control_mutant_active("custody-same-subject-retrieval") {
        return Ok(());
    }
    if primary.0 == secondary.0 || primary.1 == secondary.1 {
        Err("custody surveillance providers reuse a signer subject or SSH key".to_owned())
    } else {
        Ok(())
    }
}

fn materialize_degraded_active(root: &Path, observation: &str) -> Result<bool, String> {
    if !boolean_field(observation, "subjectKnown")?
        || !root.join("package").is_dir()
        || !root
            .join("activation")
            .join("activation-receipt.json")
            .is_file()
        || !root
            .join("activation")
            .join("activation-receipt.dsse.json")
            .is_file()
    {
        return Ok(false);
    }
    let candidate = quoted_field(observation, "candidateCommit")?;
    let epoch = quoted_field(observation, "assuranceEpochSha256")?;
    require_git_sha(&candidate, "degraded active candidate")?;
    require_digest(&epoch, "degraded active epoch")?;
    verify_activation_envelope(root)?;
    let prior_transition = verify_provider_current_transition(root, observation)?;
    let activation = fs::read_to_string(root.join("activation").join("activation-receipt.json"))
        .map_err(|error| format!("cannot read degraded activation: {error}"))?;
    if quoted_field(&activation, "candidateCommit")? != candidate
        || quoted_field(&activation, "assuranceEpochSha256")? != epoch
    {
        return Err("degraded provider observation differs from signed activation".to_owned());
    }
    let output = component_path(["ci-out", "active-promotion-record"]);
    crate::custody_ops::materialize_verified_package(&root.join("package"), &output)?;
    let observed_at = crate::custody_ops::current_utc_timestamp()?;
    let observation_dsse = root.join("provider-observation.dsse.json");
    let promotion_record_sha256 = file_digest(&output.join("promotion-record.json"))?;
    let provider_observation_sha256 = file_digest(&observation_dsse)?;
    let derived_state = prior_transition.as_ref().map_or("at-risk", |transition| {
        if transition.derived_state == "revoked" {
            "revoked"
        } else {
            "at-risk"
        }
    });
    let mut state = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in [
        ("candidateCommit", candidate.as_str()),
        ("assuranceEpochSha256", epoch.as_str()),
        ("promotionRecordSha256", promotion_record_sha256.as_str()),
        (
            "providerObservationSha256",
            provider_observation_sha256.as_str(),
        ),
        ("observedAt", observed_at.as_str()),
        ("state", derived_state),
    ] {
        state.push_str(",\n  \"");
        state.push_str(field);
        state.push_str("\": ");
        push_json(&mut state, value);
    }
    state.push_str("\n}\n");
    write_atomic(
        &output.join("promotion-current-state.json"),
        state.as_bytes(),
    )?;
    write_github_output("candidate", &candidate)?;
    Ok(true)
}

fn write_github_output(key: &str, value: &str) -> Result<(), String> {
    require_atom(key, "GitHub output key")?;
    require_git_sha(value, "GitHub candidate output")?;
    let path = std::env::var_os("GITHUB_OUTPUT")
        .ok_or_else(|| "GITHUB_OUTPUT is unavailable".to_owned())?;
    let mut output = fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .map_err(|error| format!("cannot open GITHUB_OUTPUT: {error}"))?;
    writeln!(output, "{key}={value}")
        .map_err(|error| format!("cannot write GITHUB_OUTPUT: {error}"))
}

fn verify_activation_envelope(root: &Path) -> Result<(), String> {
    let activation = root.join("activation");
    let record = activation.join("activation-receipt.json");
    let packet = activation.join("activation-packet.json");
    let dsse = activation.join("activation-receipt.dsse.json");
    let record_digest = file_digest(&record)?;
    let packet_text = fs::read_to_string(&packet)
        .map_err(|error| format!("cannot read activation packet: {error}"))?;
    if !packet_text.contains(&format!("\"{record_digest}\"")) {
        return Err("activation packet does not bind activation record".to_owned());
    }
    verify_review_envelope(&dsse, "custody-provider")
}

fn verify_review_envelope(path: &Path, role: &str) -> Result<(), String> {
    let status = Command::new(
        std::env::current_exe().map_err(|error| format!("cannot locate hell-ci: {error}"))?,
    )
    .args([
        OsStr::new("review-verify"),
        OsStr::new("--input"),
        path.as_os_str(),
        OsStr::new("--policy"),
        OsStr::new("compat/reviews.allowed_signers"),
        OsStr::new("--role"),
        OsStr::new(role),
    ])
    .status()
    .map_err(|error| format!("cannot verify review envelope: {error}"))?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| "review envelope verification failed".to_owned())
}

fn promotion_current_state_json(
    candidate: &str,
    epoch: &str,
    promotion_record: &str,
    first_activation: &str,
    second_activation: &str,
    promoted_at: &str,
) -> String {
    let mut output = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in [
        ("candidateCommit", candidate),
        ("assuranceEpochSha256", epoch),
        ("promotionRecordSha256", promotion_record),
        ("firstActivationSha256", first_activation),
        ("secondActivationSha256", second_activation),
        ("promotedAt", promoted_at),
        ("state", "promoted"),
    ] {
        output.push_str(",\n  \"");
        output.push_str(field);
        output.push_str("\": ");
        push_json(&mut output, value);
    }
    output.push_str("\n}\n");
    output
}

fn workflow_verify_approved_source() -> Result<String, String> {
    const KEYS: &[&str] = &[
        "assurance_epoch_sha256",
        "candidate_sha",
        "promotion_proposal_sha256",
        "proposal_artifact_id",
        "proposal_provider_archive_sha256",
        "proposal_package_sha256",
        "proposal_run_attempt",
        "proposal_run_id",
        "require_promotion",
    ];
    let inputs = crate::assurance::github_dispatch_object(KEYS)?;
    if inputs.get("require_promotion").map(String::as_str) != Some("true") {
        return Err("approved proposal selection requires promotion dispatch".to_owned());
    }
    let root = component_path(["ci-out", "native-shards"]);
    let expected = required_map(&inputs, "proposal_package_sha256")?;
    require_digest(expected, "approved proposal directory")?;
    let observed = crate::custody_ops::directory_digest(&root)?;
    if observed != expected {
        return Err("approved proposal provider directory digest mismatch".to_owned());
    }
    let proposal = root.join("promotion-proposal.json");
    let proposal_digest = file_digest(&proposal)?;
    if proposal_digest != required_map(&inputs, "promotion_proposal_sha256")? {
        return Err("approved proposal content digest differs from dispatch".to_owned());
    }
    let epoch = root.join("assurance-epoch.json");
    let (candidate, epoch_digest) = crate::assurance::retained_epoch_digest(&epoch)?;
    if candidate != required_map(&inputs, "candidate_sha")?
        || epoch_digest != required_map(&inputs, "assurance_epoch_sha256")?
    {
        return Err("approved proposal candidate or epoch differs from dispatch".to_owned());
    }
    let run_id = require_nonzero(required_map(&inputs, "proposal_run_id")?, "proposal run ID")?;
    let run_attempt = require_nonzero(
        required_map(&inputs, "proposal_run_attempt")?,
        "proposal run attempt",
    )?;
    let artifact_id = require_nonzero(
        required_map(&inputs, "proposal_artifact_id")?,
        "proposal artifact ID",
    )?;
    let provider_selection = crate::assurance::verify_provider_artifact_selection(
        Path::new("."),
        &root,
        "promotion-approved-proposal",
        ".github/workflows/promotion-approval.yml",
        "workflow_dispatch",
        run_id,
        run_attempt,
        artifact_id,
        &candidate,
        &observed,
        required_map(&inputs, "proposal_provider_archive_sha256")?,
    )?;
    crate::assurance::verify_selection_archive(
        &provider_selection,
        required_map(&inputs, "proposal_provider_archive_sha256")?,
    )?;
    let provider_selection_sha256 = sha256_bytes(provider_selection.as_bytes()).hex();
    write_atomic(
        &root.join("approved-provider-api-selection.json"),
        provider_selection.as_bytes(),
    )?;
    let receipt = format!(
        "{{\n  \"schemaVersion\": 2,\n  \"artifact\": \"promotion-approved-proposal\",\n  \"workflowPath\": \".github/workflows/promotion-approval.yml\",\n  \"providerRunId\": {run_id},\n  \"providerRunAttempt\": {run_attempt},\n  \"providerArtifactId\": {artifact_id},\n  \"providerSelectionSha256\": \"{provider_selection_sha256}\",\n  \"candidateCommit\": \"{candidate}\",\n  \"assuranceEpochSha256\": \"{epoch_digest}\",\n  \"proposalSha256\": \"{proposal_digest}\",\n  \"directorySha256\": \"{observed}\",\n  \"selectionState\": \"exact-provider-object\"\n}}\n"
    );
    write_atomic(
        &root.join("approved-provider-selection.json"),
        receipt.as_bytes(),
    )?;
    Ok("verified exact approved-proposal provider object".to_owned())
}

fn required_map<'a>(
    values: &'a std::collections::BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, String> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("dispatch lacks {key}"))
}

fn require_nonzero(value: &str, label: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| format!("{label} must be nonzero"))
}

struct NativeProvenanceRun {
    run_id: u64,
    run_attempt: u64,
    created_at: String,
    updated_at: String,
    head_sha: String,
    event: String,
    status: String,
    conclusion: String,
}

struct NativeProvenanceArtifact {
    artifact_id: u64,
    name: String,
    size: u64,
    digest: String,
    created_at: String,
    expires_at: String,
}

struct SelectedNativeProvenance {
    run: NativeProvenanceRun,
    macos: NativeProvenanceArtifact,
    windows: NativeProvenanceArtifact,
    macos_path: PathBuf,
    windows_path: PathBuf,
    macos_archive_sha256: String,
    windows_archive_sha256: String,
    macos_tree_sha256: String,
    windows_tree_sha256: String,
    macos_provider_selection_sha256: String,
    windows_provider_selection_sha256: String,
}

fn workflow_dispatch_native_provenance() -> Result<String, String> {
    let token = workflow_github_token("native provenance dispatch")?;
    let active = component_path(["ci-out", "active-promotion-record"]);
    let promotion = read_text(&active.join("promotion-record.json"))?;
    let candidate = quoted_field(&promotion, "candidateCommit")?;
    let epoch = quoted_field(&promotion, "assuranceEpochSha256")?;
    require_git_sha(&candidate, "native provenance dispatch candidate")?;
    require_digest(&epoch, "native provenance dispatch epoch")?;
    let mut body = String::from("{\"ref\":\"main\",\"inputs\":{\"candidate_sha\":");
    push_json(&mut body, &candidate);
    body.push_str(",\"assurance_epoch_sha256\":");
    push_json(&mut body, &epoch);
    body.push_str("}}\n");
    let endpoint = component_path([
        "repos",
        "Portfoligno",
        "hell-rs",
        "actions",
        "workflows",
        "oracle-reproduce.yml",
        "dispatches",
    ]);
    let mut child = Command::new("gh")
        .args([
            OsStr::new("api"),
            OsStr::new("--method"),
            OsStr::new("POST"),
            endpoint.as_os_str(),
            OsStr::new("--input"),
            OsStr::new("-"),
        ])
        .env("GH_TOKEN", token)
        .env_remove("GITHUB_TOKEN")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|error| format!("cannot start native provenance dispatch: {error}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "native provenance dispatch lacks stdin".to_owned())?
        .write_all(body.as_bytes())
        .map_err(|error| format!("cannot write native provenance dispatch: {error}"))?;
    let response = child
        .wait_with_output()
        .map_err(|error| format!("cannot wait for native provenance dispatch: {error}"))?;
    if !response.status.success() || !response.stdout.is_empty() {
        return Err("native provenance dispatch failed or returned an unexpected body".to_owned());
    }
    let receipt = format!(
        "{{\n  \"schemaVersion\": 1,\n  \"candidateCommit\": \"{candidate}\",\n  \"assuranceEpochSha256\": \"{epoch}\",\n  \"workflowPath\": \".github/workflows/oracle-reproduce.yml\",\n  \"ref\": \"main\",\n  \"requestSha256\": \"{}\",\n  \"state\": \"dispatch-accepted\"\n}}\n",
        sha256_bytes(body.as_bytes()).hex(),
    );
    write_atomic(
        &component_path(["ci-out", "surveillance", "native-provenance-dispatch.json"]),
        receipt.as_bytes(),
    )?;
    Ok("dispatched exact active-candidate native provenance rebuild".to_owned())
}

fn workflow_retain_current_governance() -> Result<String, String> {
    let token = workflow_github_token("current governance retention")?;
    let commit = std::env::var("GITHUB_SHA")
        .map_err(|_| "current governance retention lacks GITHUB_SHA".to_owned())?;
    let repository_id = std::env::var("GITHUB_REPOSITORY_ID")
        .map_err(|_| "current governance retention lacks GITHUB_REPOSITORY_ID".to_owned())?;
    require_git_sha(&commit, "current governance commit")?;
    require_nonzero(&repository_id, "current governance repository ID")?;
    let root = component_path(["ci-out", "surveillance", "current-governance-source"]);
    let revocations = provider_source_file(
        &token,
        &commit,
        &["compat", "review-revocations.toml"],
        &root,
    )?;
    for name in [
        "surveillance-policy.toml",
        "divergences.toml",
        "reviews.allowed_signers",
        "review-policy.toml",
        "trust-roots.toml",
    ] {
        provider_source_file(&token, &commit, &["compat", name], &root)?;
    }
    let revocations_sha256 = file_digest(&revocations)?;
    let record = format!(
        "{{\n  \"schemaVersion\": 1,\n  \"repositoryId\": \"{repository_id}\",\n  \"providerCommit\": \"{commit}\",\n  \"revocationsPath\": \"ci-out/surveillance/current-governance-source/compat/review-revocations.toml\",\n  \"revocationsSha256\": \"{revocations_sha256}\",\n  \"state\": \"exact-current-provider-source\"\n}}\n"
    );
    write_atomic(
        &component_path(["ci-out", "surveillance", "current-governance-source.json"]),
        record.as_bytes(),
    )?;
    Ok("retained exact current provider governance source".to_owned())
}

fn current_governance_path(name: &str) -> PathBuf {
    component_path([
        "ci-out",
        "surveillance",
        "current-governance-source",
        "compat",
    ])
    .join(name)
}

fn workflow_native_provenance() -> Result<String, String> {
    let token = workflow_github_token("native provenance selection")?;
    let active = component_path(["ci-out", "active-promotion-record"]);
    let promotion = read_text(&active.join("promotion-record.json"))?;
    let candidate = quoted_field(&promotion, "candidateCommit")?;
    let epoch = quoted_field(&promotion, "assuranceEpochSha256")?;
    let runs = native_provenance_runs(&token)?;
    let policy = SurveillancePolicy::load(&current_governance_path("surveillance-policy.toml"))?;
    for run in runs {
        if run.status != "completed"
            || run.conclusion != "success"
            || !matches!(run.event.as_str(), "push" | "workflow_dispatch")
            || crate::custody_ops::utc_age_days(&run.updated_at)?
                > policy.cadence.native_provenance_rebuild
        {
            continue;
        }
        let artifacts = native_provenance_artifacts(&token, run.run_id)?;
        if let Some(selection) = select_native_provenance_run(
            &token,
            run,
            &artifacts,
            &candidate,
            &epoch,
            policy.cadence.native_provenance_rebuild,
        )? {
            let output = native_provenance_selection_json(&selection, &candidate, &epoch)?;
            write_atomic(
                &component_path(["ci-out", "surveillance", "native-provenance-selection.json"]),
                output.as_bytes(),
            )?;
            return Ok(format!(
                "selected exact current reviewed native provenance run {}",
                selection.run.run_id
            ));
        }
    }
    Err(
        "no current reviewed native provenance run matches the active candidate and epoch"
            .to_owned(),
    )
}

fn workflow_github_token(label: &str) -> Result<String, String> {
    let repository = std::env::var("GITHUB_REPOSITORY")
        .map_err(|_| format!("{label} lacks GITHUB_REPOSITORY"))?;
    let server =
        std::env::var("GITHUB_SERVER_URL").map_err(|_| format!("{label} lacks server URL"))?;
    let token = std::env::var("GITHUB_TOKEN").map_err(|_| format!("{label} lacks token"))?;
    if repository != "Portfoligno/hell-rs"
        || server != "https://github.com"
        || token.is_empty()
        || token.chars().any(char::is_control)
    {
        return Err(format!("{label} provider identity is invalid"));
    }
    Ok(token)
}

fn native_provider_workflow_source(
    token: &str,
    head_sha: &str,
    root: &Path,
) -> Result<PathBuf, String> {
    provider_source_file(
        token,
        head_sha,
        &[".github", "workflows", "oracle-reproduce.yml"],
        root,
    )
}

fn provider_source_file(
    token: &str,
    head_sha: &str,
    components: &[&str],
    root: &Path,
) -> Result<PathBuf, String> {
    require_git_sha(head_sha, "provider source commit")?;
    let endpoint = components.iter().fold(
        component_path(["repos", "Portfoligno", "hell-rs", "contents"]),
        |path, component| path.join(component),
    );
    let response = github_request(
        token,
        &[
            OsString::from("api"),
            OsString::from("--method"),
            OsString::from("GET"),
            endpoint.as_os_str().to_owned(),
            OsString::from("-f"),
            native_provider_ref_argument(head_sha)?,
            OsString::from("--header"),
            OsString::from("Accept: application/vnd.github.raw+json"),
        ],
    )?;
    if response.stdout.is_empty() || std::str::from_utf8(&response.stdout).is_err() {
        return Err("provider workflow source response is empty or non-UTF-8".to_owned());
    }
    let path = components
        .iter()
        .fold(root.to_path_buf(), |path, component| path.join(component));
    write_atomic(&path, &response.stdout)?;
    Ok(path)
}

fn native_provider_ref_argument(head_sha: &str) -> Result<OsString, String> {
    require_git_sha(head_sha, "native provider workflow source ref")?;
    let mut value = String::with_capacity("ref=".len().saturating_add(head_sha.len()));
    value.push_str("ref=");
    value.push_str(head_sha);
    if value.strip_prefix("ref=") != Some(head_sha) {
        return Err("native provider ref encoding failed to round trip".to_owned());
    }
    Ok(OsString::from(value))
}

fn verify_native_provider_workflow_source(
    token: &str,
    head_sha: &str,
    root: &Path,
) -> Result<bool, String> {
    let retained = root.join(component_path([
        ".github",
        "workflows",
        "oracle-reproduce.yml",
    ]));
    let retained_bytes = fs::read(&retained)
        .map_err(|error| format!("cannot read retained provider workflow source: {error}"))?;
    let temporary = root.join("provider-api-reverification");
    let queried = native_provider_workflow_source(token, head_sha, &temporary)?;
    let queried_bytes = fs::read(queried)
        .map_err(|error| format!("cannot read requeried provider workflow source: {error}"))?;
    Ok(retained_bytes == queried_bytes)
}

fn native_provenance_runs(token: &str) -> Result<Vec<NativeProvenanceRun>, String> {
    let endpoint = component_path([
        "repos",
        "Portfoligno",
        "hell-rs",
        "actions",
        "workflows",
        "oracle-reproduce.yml",
        "runs",
    ]);
    let response = github_request(
        token,
        &[
            OsString::from("api"),
            OsString::from("--method"),
            OsString::from("GET"),
            endpoint.as_os_str().to_owned(),
            OsString::from("-f"),
            OsString::from("status=completed"),
            OsString::from("-f"),
            OsString::from("per_page=100"),
            OsString::from("--paginate"),
            OsString::from("--jq"),
            OsString::from(
                ".workflow_runs[] | [.id,.run_attempt,.created_at,.updated_at,.head_sha,.event,.status,.conclusion] | @tsv",
            ),
        ],
    )?;
    let text = String::from_utf8(response.stdout)
        .map_err(|_| "native provenance run API response is not UTF-8".to_owned())?;
    let mut runs = text
        .lines()
        .map(parse_native_provenance_run)
        .collect::<Result<Vec<_>, _>>()?;
    runs.sort_by(|left, right| right.created_at.cmp(&left.created_at));
    Ok(runs)
}

fn parse_native_provenance_run(line: &str) -> Result<NativeProvenanceRun, String> {
    let fields = line.split('\t').collect::<Vec<_>>();
    if fields.len() != 8 {
        return Err("native provenance run response has an unexpected shape".to_owned());
    }
    crate::custody_ops::validate_utc_timestamp(fields[2])?;
    crate::custody_ops::validate_utc_timestamp(fields[3])?;
    require_git_sha(fields[4], "native provenance run head")?;
    for (label, value) in [
        ("event", fields[5]),
        ("status", fields[6]),
        ("conclusion", fields[7]),
    ] {
        require_atom(value, label)?;
    }
    Ok(NativeProvenanceRun {
        run_id: require_nonzero(fields[0], "native provenance run ID")?,
        run_attempt: require_nonzero(fields[1], "native provenance run attempt")?,
        created_at: fields[2].to_owned(),
        updated_at: fields[3].to_owned(),
        head_sha: fields[4].to_owned(),
        event: fields[5].to_owned(),
        status: fields[6].to_owned(),
        conclusion: fields[7].to_owned(),
    })
}

fn native_provenance_artifacts(
    token: &str,
    run_id: u64,
) -> Result<Vec<NativeProvenanceArtifact>, String> {
    let endpoint = component_path(["repos", "Portfoligno", "hell-rs", "actions", "runs"])
        .join(run_id.to_string())
        .join("artifacts");
    let response = github_request(
        token,
        &[
            OsString::from("api"),
            OsString::from("--method"),
            OsString::from("GET"),
            endpoint.as_os_str().to_owned(),
            OsString::from("-f"),
            OsString::from("per_page=100"),
            OsString::from("--paginate"),
            OsString::from("--jq"),
            OsString::from(
                ".artifacts[] | [.id,.name,.size_in_bytes,.digest,.expired,.created_at,.expires_at] | @tsv",
            ),
        ],
    )?;
    let text = String::from_utf8(response.stdout)
        .map_err(|_| "native provenance artifact API response is not UTF-8".to_owned())?;
    let artifacts = text
        .lines()
        .map(parse_native_provenance_artifact)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(artifacts)
}

fn parse_native_provenance_artifact(line: &str) -> Result<NativeProvenanceArtifact, String> {
    let fields = line.split('\t').collect::<Vec<_>>();
    if fields.len() != 7 || fields[4] != "false" {
        return Err("native provenance artifact response is invalid or expired".to_owned());
    }
    let digest = fields[3]
        .strip_prefix("sha256:")
        .ok_or_else(|| "native provenance artifact lacks SHA-256 provider digest".to_owned())?;
    require_digest(digest, "native provenance provider archive")?;
    crate::custody_ops::validate_utc_timestamp(fields[5])?;
    crate::custody_ops::validate_utc_timestamp(fields[6])?;
    Ok(NativeProvenanceArtifact {
        artifact_id: require_nonzero(fields[0], "native provenance artifact ID")?,
        name: fields[1].to_owned(),
        size: require_nonzero(fields[2], "native provenance artifact size")?,
        digest: digest.to_owned(),
        created_at: fields[5].to_owned(),
        expires_at: fields[6].to_owned(),
    })
}

fn select_native_provenance_run(
    token: &str,
    run: NativeProvenanceRun,
    artifacts: &[NativeProvenanceArtifact],
    candidate: &str,
    epoch: &str,
    maximum_age_days: u64,
) -> Result<Option<SelectedNativeProvenance>, String> {
    let macos =
        exact_named_native_artifact(artifacts, "ephemeralEvidence-oracle-reviewed-macos-arm64")?;
    let windows =
        exact_named_native_artifact(artifacts, "ephemeralEvidence-oracle-reviewed-windows-amd64")?;
    let root = component_path(["ci-out", "surveillance", "current-native-provenance"])
        .join(run.run_id.to_string())
        .join(run.run_attempt.to_string());
    let macos_download = download_native_provenance(token, &macos, &root.join("macos-arm64"))?;
    let windows_download =
        download_native_provenance(token, &windows, &root.join("windows-amd64"))?;
    for (path, platform) in [
        (&macos_download.provenance_path, "macos-arm64"),
        (&windows_download.provenance_path, "windows-amd64"),
    ] {
        let document = read_text(path)?;
        if quoted_field(&document, "candidateCommit")? != candidate
            || quoted_field(&document, "assuranceEpochSha256")? != epoch
        {
            return Ok(None);
        }
        let verification_root = native_provenance_verification_root(path)?;
        if crate::assurance::verify_surveillance_oracle_provenance(
            verification_root,
            path,
            &current_governance_path("reviews.allowed_signers"),
            maximum_age_days,
        )? != platform
        {
            return Err("selected native provenance platform is substituted".to_owned());
        }
    }
    let selection_root = root.join("provider-selection");
    let workflow_source_root = root.join("provider-workflow-source");
    native_provider_workflow_source(token, &run.head_sha, &workflow_source_root)?;
    let macos_output = selection_root.join("macos-arm64");
    let macos_provider_selection = crate::assurance::verify_provider_artifact_selection_subject_to(
        &crate::assurance::ProviderArtifactSelectionSubject {
            root: &workflow_source_root,
            input_directory: &macos_download.extracted_root,
            output_directory: &macos_output,
            artifact_name: &macos.name,
            workflow_path: ".github/workflows/oracle-reproduce.yml",
            event_name: &run.event,
            run_id: run.run_id,
            run_attempt: run.run_attempt,
            artifact_id: macos.artifact_id,
            provider_head: &run.head_sha,
            candidate,
            expected_directory_sha256: &macos_download.tree_sha256,
            expected_archive_sha256: &macos_download.archive_sha256,
        },
    )?;
    let windows_provider_selection =
        crate::assurance::verify_provider_artifact_selection_subject_to(
            &crate::assurance::ProviderArtifactSelectionSubject {
                root: &workflow_source_root,
                input_directory: &windows_download.extracted_root,
                output_directory: &selection_root.join("windows-amd64"),
                artifact_name: &windows.name,
                workflow_path: ".github/workflows/oracle-reproduce.yml",
                event_name: &run.event,
                run_id: run.run_id,
                run_attempt: run.run_attempt,
                artifact_id: windows.artifact_id,
                provider_head: &run.head_sha,
                candidate,
                expected_directory_sha256: &windows_download.tree_sha256,
                expected_archive_sha256: &windows_download.archive_sha256,
            },
        )?;
    let macos_provider_selection_sha256 = sha256_bytes(macos_provider_selection.as_bytes()).hex();
    let windows_provider_selection_sha256 =
        sha256_bytes(windows_provider_selection.as_bytes()).hex();
    write_atomic(
        &selection_root.join("macos-arm64.json"),
        macos_provider_selection.as_bytes(),
    )?;
    write_atomic(
        &selection_root.join("windows-amd64.json"),
        windows_provider_selection.as_bytes(),
    )?;
    Ok(Some(SelectedNativeProvenance {
        run,
        macos,
        windows,
        macos_path: macos_download.provenance_path,
        windows_path: windows_download.provenance_path,
        macos_archive_sha256: macos_download.archive_sha256,
        windows_archive_sha256: windows_download.archive_sha256,
        macos_tree_sha256: macos_download.tree_sha256,
        windows_tree_sha256: windows_download.tree_sha256,
        macos_provider_selection_sha256,
        windows_provider_selection_sha256,
    }))
}

fn native_provenance_verification_root(path: &Path) -> Result<&Path, String> {
    path.ancestors()
        .find(|ancestor| ancestor.file_name() == Some(OsStr::new("ci-out")))
        .and_then(Path::parent)
        .ok_or_else(|| "native provenance extraction lacks its canonical ci-out root".to_owned())
}

fn exact_named_native_artifact(
    artifacts: &[NativeProvenanceArtifact],
    name: &str,
) -> Result<NativeProvenanceArtifact, String> {
    let matching = artifacts
        .iter()
        .filter(|artifact| artifact.name == name)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(format!(
            "native provenance run does not contain exactly one {name}"
        ));
    }
    let artifact = matching[0];
    Ok(NativeProvenanceArtifact {
        artifact_id: artifact.artifact_id,
        name: artifact.name.clone(),
        size: artifact.size,
        digest: artifact.digest.clone(),
        created_at: artifact.created_at.clone(),
        expires_at: artifact.expires_at.clone(),
    })
}

struct DownloadedNativeProvenance {
    provenance_path: PathBuf,
    extracted_root: PathBuf,
    archive_sha256: String,
    tree_sha256: String,
}

fn download_native_provenance(
    token: &str,
    artifact: &NativeProvenanceArtifact,
    root: &Path,
) -> Result<DownloadedNativeProvenance, String> {
    let endpoint = component_path(["repos", "Portfoligno", "hell-rs", "actions", "artifacts"])
        .join(artifact.artifact_id.to_string())
        .join("zip");
    let response = github_request(
        token,
        &[
            OsString::from("api"),
            OsString::from("--method"),
            OsString::from("GET"),
            endpoint.as_os_str().to_owned(),
        ],
    )?;
    if u64::try_from(response.stdout.len()).ok() != Some(artifact.size) {
        return Err("native provenance archive size differs from provider API".to_owned());
    }
    let archive_sha256 = sha256_bytes(&response.stdout).hex();
    if archive_sha256 != artifact.digest {
        return Err("native provenance archive digest differs from provider API".to_owned());
    }
    let archive = root.join("artifact.zip");
    write_atomic(&archive, &response.stdout)?;
    let extracted = root.join("ci-out");
    crate::assurance::extract_external_zip(&archive, &extracted)?;
    let provenance = exact_named_file(&extracted, "oracle-provenance.json")?;
    let tree_sha256 = crate::custody_ops::directory_digest(&extracted)?;
    Ok(DownloadedNativeProvenance {
        provenance_path: provenance,
        extracted_root: extracted,
        archive_sha256,
        tree_sha256,
    })
}

fn exact_named_file(root: &Path, name: &str) -> Result<PathBuf, String> {
    let mut directories = vec![root.to_path_buf()];
    let mut matches = Vec::new();
    while let Some(directory) = directories.pop() {
        let mut entries = fs::read_dir(&directory)
            .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot enumerate {}: {error}", directory.display()))?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let file_type = entry
                .file_type()
                .map_err(|error| format!("cannot inspect {}: {error}", entry.path().display()))?;
            if file_type.is_symlink() {
                return Err("native provenance extraction contains a symlink".to_owned());
            }
            if file_type.is_dir() {
                directories.push(entry.path());
            } else if file_type.is_file() && entry.file_name() == OsStr::new(name) {
                matches.push(entry.path());
            }
        }
    }
    if matches.len() != 1 {
        return Err(format!(
            "native provenance artifact contains {} files named {name}",
            matches.len()
        ));
    }
    Ok(matches.remove(0))
}

fn native_provenance_selection_json(
    selection: &SelectedNativeProvenance,
    candidate: &str,
    epoch: &str,
) -> Result<String, String> {
    let macos_path = path_text(&selection.macos_path)?;
    let macos_sha256 = file_digest(&selection.macos_path)?;
    let windows_path = path_text(&selection.windows_path)?;
    let windows_sha256 = file_digest(&selection.windows_path)?;
    let mut output = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in [
        ("candidateCommit", candidate),
        ("assuranceEpochSha256", epoch),
        ("workflowPath", ".github/workflows/oracle-reproduce.yml"),
        ("event", selection.run.event.as_str()),
        ("headSha", selection.run.head_sha.as_str()),
        ("updatedAt", selection.run.updated_at.as_str()),
        ("macosArtifactName", selection.macos.name.as_str()),
        (
            "macosDownloadedArchiveSha256",
            selection.macos_archive_sha256.as_str(),
        ),
        (
            "macosExtractedTreeSha256",
            selection.macos_tree_sha256.as_str(),
        ),
        (
            "macosProviderSelectionSha256",
            selection.macos_provider_selection_sha256.as_str(),
        ),
        ("macosProvenancePath", macos_path.as_str()),
        ("macosProvenanceSha256", macos_sha256.as_str()),
        ("windowsArtifactName", selection.windows.name.as_str()),
        (
            "windowsDownloadedArchiveSha256",
            selection.windows_archive_sha256.as_str(),
        ),
        (
            "windowsExtractedTreeSha256",
            selection.windows_tree_sha256.as_str(),
        ),
        (
            "windowsProviderSelectionSha256",
            selection.windows_provider_selection_sha256.as_str(),
        ),
        ("windowsProvenancePath", windows_path.as_str()),
        ("windowsProvenanceSha256", windows_sha256.as_str()),
    ] {
        output.push_str(",\n  \"");
        output.push_str(field);
        output.push_str("\": ");
        push_json(&mut output, value);
    }
    write!(
        output,
        ",\n  \"runId\": {},\n  \"runAttempt\": {},\n  \"macosArtifactId\": {},\n  \"windowsArtifactId\": {}\n}}\n",
        selection.run.run_id,
        selection.run.run_attempt,
        selection.macos.artifact_id,
        selection.windows.artifact_id,
    )
    .expect("writing to String cannot fail");
    Ok(output)
}

fn workflow_objective() -> Result<String, String> {
    let epoch_path = component_path(["ci-out", "assurance-epoch.json"]);
    let (candidate, epoch) = crate::assurance::retained_epoch_digest(&epoch_path)?;
    let observed_at = crate::custody_ops::current_utc_timestamp()?;
    let policy_path = current_governance_path("surveillance-policy.toml");
    let policy = SurveillancePolicy::load(&policy_path)?;
    let active = component_path(["ci-out", "active-promotion-record"]);
    let promotion = fs::read_to_string(active.join("promotion-record.json"))
        .map_err(|error| format!("cannot read active promotion record: {error}"))?;
    if quoted_field(&promotion, "candidateCommit")? != candidate
        || quoted_field(&promotion, "assuranceEpochSha256")? != epoch
    {
        return Err("active promotion record does not bind current candidate and epoch".to_owned());
    }
    let inputs = objective_component_paths(&active, &observed_at)?;
    let checks = ObjectiveChecks {
        candidate: &candidate,
        epoch: &epoch,
        observed_at: &observed_at,
        assurance_path: path_text(&inputs.assurance)?,
        assurance: &file_digest(&inputs.assurance)?,
        differential_path: path_text(&inputs.differential)?,
        differential: &file_digest(&inputs.differential)?,
        impact_path: path_text(&inputs.impact)?,
        impact: &file_digest(&inputs.impact)?,
        public_state_path: path_text(&inputs.public_state)?,
        public_state: &file_digest(&inputs.public_state)?,
        native_provenance_selection_path: path_text(&inputs.native_provenance_selection)?,
        native_provenance_selection: &file_digest(&inputs.native_provenance_selection)?,
        active_subject_selection_path: path_text(&inputs.active_subject_selection)?,
        active_subject_selection: &file_digest(&inputs.active_subject_selection)?,
        divergence_issue_manifest_path: path_text(&inputs.divergence_issue_manifest)?,
        divergence_issue_manifest: &file_digest(&inputs.divergence_issue_manifest)?,
        divergence_warnings_path: path_text(&inputs.divergence_warnings)?,
        divergence_warnings: &file_digest(&inputs.divergence_warnings)?,
        mutation_path: path_text(&inputs.mutation)?,
        mutation: &file_digest(&inputs.mutation)?,
        macos_provenance_path: path_text(&inputs.macos_provenance)?,
        macos_provenance: &file_digest(&inputs.macos_provenance)?,
        windows_provenance_path: path_text(&inputs.windows_provenance)?,
        windows_provenance: &file_digest(&inputs.windows_provenance)?,
        first_custody_path: path_text(&inputs.first_custody)?,
        first_custody: &file_digest(&inputs.first_custody)?,
        second_custody_path: path_text(&inputs.second_custody)?,
        second_custody: &file_digest(&inputs.second_custody)?,
        first_custody_dsse_path: path_text(&inputs.first_custody_dsse)?,
        first_custody_dsse: &file_digest(&inputs.first_custody_dsse)?,
        second_custody_dsse_path: path_text(&inputs.second_custody_dsse)?,
        second_custody_dsse: &file_digest(&inputs.second_custody_dsse)?,
        runner_baseline_path: path_text(&inputs.baseline_runner)?,
        runner_baseline: &file_digest(&inputs.baseline_runner)?,
        runner_current_path: path_text(&inputs.current_runner)?,
        runner_current: &file_digest(&inputs.current_runner)?,
        revocations_path:
            "ci-out/surveillance/current-governance-source/compat/review-revocations.toml"
                .to_owned(),
        revocations: &file_digest(&component_path([
            "ci-out",
            "surveillance",
            "current-governance-source",
            "compat",
            "review-revocations.toml",
        ]))?,
        divergences_path: "ci-out/surveillance/current-governance-source/compat/divergences.toml"
            .to_owned(),
        divergences: &file_digest(&current_governance_path("divergences.toml"))?,
        policy_path: path_text(&policy_path)?,
        policy: &file_digest(&policy_path)?,
        require_signed_governance_action: policy.require_signed_governance_action,
        public_report_exposes_current_state: policy.public_report_exposes_current_state,
    };
    let output = objective_json(&checks);
    write_atomic(
        &component_path(["ci-out", "surveillance", "objective-checks.json"]),
        output.as_bytes(),
    )?;
    write_boolean_github_output(
        "require_signed_governance_action",
        policy.require_signed_governance_action,
    )?;
    write_boolean_github_output(
        "public_report_exposes_current_state",
        policy.public_report_exposes_current_state,
    )?;
    Ok("derived objective weekly promotion surveillance checks".to_owned())
}

struct ObjectiveComponentPaths {
    assurance: PathBuf,
    differential: PathBuf,
    impact: PathBuf,
    public_state: PathBuf,
    native_provenance_selection: PathBuf,
    active_subject_selection: PathBuf,
    divergence_issue_manifest: PathBuf,
    divergence_warnings: PathBuf,
    mutation: PathBuf,
    macos_provenance: PathBuf,
    windows_provenance: PathBuf,
    first_custody: PathBuf,
    second_custody: PathBuf,
    first_custody_dsse: PathBuf,
    second_custody_dsse: PathBuf,
    baseline_runner: PathBuf,
    current_runner: PathBuf,
}

fn objective_component_paths(
    active: &Path,
    observed_at: &str,
) -> Result<ObjectiveComponentPaths, String> {
    let surveillance = component_path(["ci-out", "surveillance"]);
    let resolve = |name: &str, path: PathBuf| component_or_failure(name, &path, observed_at);
    let native_provenance_selection = resolve(
        "native-provenance-selection",
        surveillance.join("native-provenance-selection.json"),
    )?;
    let selection_text = read_text(&native_provenance_selection)?;
    let current_runner = surveillance.join("runner-toolchain.json");
    write_atomic(&current_runner, runner_identity_json()?.as_bytes())?;
    Ok(ObjectiveComponentPaths {
        assurance: resolve(
            "repository-assurance",
            surveillance.join("assurance-policy.json"),
        )?,
        differential: resolve("differential-property", surveillance.join("nightly.json"))?,
        impact: resolve(
            "regression-impact",
            surveillance.join("regression-impact.json"),
        )?,
        public_state: resolve(
            "public-current-state",
            surveillance.join("public-current-state-observation.json"),
        )?,
        native_provenance_selection,
        active_subject_selection: resolve(
            "active-subject-provider-selection",
            surveillance.join("active-subject-provider-selection.json"),
        )?,
        divergence_issue_manifest: resolve(
            "divergence-issue-manifest",
            surveillance
                .join("divergence-issue-comments")
                .join("manifest.json"),
        )?,
        divergence_warnings: resolve(
            "divergence-expiry-warnings",
            surveillance.join("divergence-expiry-warnings.json"),
        )?,
        mutation: resolve(
            "mutation-mechanical-campaign",
            surveillance
                .join("mutation")
                .join("mutation-score.pending.json"),
        )?,
        macos_provenance: resolve(
            "macos-native-provenance",
            portable_relative_path(&quoted_field(&selection_text, "macosProvenancePath")?)?,
        )?,
        windows_provenance: resolve(
            "windows-native-provenance",
            portable_relative_path(&quoted_field(&selection_text, "windowsProvenancePath")?)?,
        )?,
        first_custody: resolve(
            "primary-custody",
            component_path(["ci-out", "active-primary", "provider-observation.json"]),
        )?,
        second_custody: resolve(
            "secondary-custody",
            component_path(["ci-out", "active-secondary", "provider-observation.json"]),
        )?,
        first_custody_dsse: resolve(
            "primary-custody-dsse",
            component_path(["ci-out", "active-primary", "provider-observation.dsse.json"]),
        )?,
        second_custody_dsse: resolve(
            "secondary-custody-dsse",
            component_path([
                "ci-out",
                "active-secondary",
                "provider-observation.dsse.json",
            ]),
        )?,
        baseline_runner: resolve("runner-baseline", active.join("runner-toolchain.json"))?,
        current_runner,
    })
}

fn component_or_failure(name: &str, path: &Path, observed_at: &str) -> Result<PathBuf, String> {
    if require_regular_file(path).is_ok() {
        return Ok(path.to_path_buf());
    }
    require_atom(name, "surveillance component name")?;
    let failure_path = component_path(["ci-out", "surveillance", "component-failures"])
        .join(name)
        .with_extension("json");
    let expected_path = path_text(path)?;
    let mut output = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in [
        ("component", name),
        ("expectedPath", expected_path.as_str()),
        ("observedAt", observed_at),
        ("state", "missing-or-nonregular"),
    ] {
        output.push_str(",\n  \"");
        output.push_str(field);
        output.push_str("\": ");
        push_json(&mut output, value);
    }
    output.push_str("\n}\n");
    write_atomic(&failure_path, output.as_bytes())?;
    Ok(failure_path)
}

struct ObjectiveChecks<'a> {
    candidate: &'a str,
    epoch: &'a str,
    observed_at: &'a str,
    assurance_path: String,
    assurance: &'a str,
    differential_path: String,
    differential: &'a str,
    impact_path: String,
    impact: &'a str,
    public_state_path: String,
    public_state: &'a str,
    native_provenance_selection_path: String,
    native_provenance_selection: &'a str,
    active_subject_selection_path: String,
    active_subject_selection: &'a str,
    divergence_issue_manifest_path: String,
    divergence_issue_manifest: &'a str,
    divergence_warnings_path: String,
    divergence_warnings: &'a str,
    mutation_path: String,
    mutation: &'a str,
    macos_provenance_path: String,
    macos_provenance: &'a str,
    windows_provenance_path: String,
    windows_provenance: &'a str,
    first_custody_path: String,
    first_custody: &'a str,
    second_custody_path: String,
    second_custody: &'a str,
    first_custody_dsse_path: String,
    first_custody_dsse: &'a str,
    second_custody_dsse_path: String,
    second_custody_dsse: &'a str,
    runner_baseline_path: String,
    runner_baseline: &'a str,
    runner_current_path: String,
    runner_current: &'a str,
    revocations_path: String,
    revocations: &'a str,
    divergences_path: String,
    divergences: &'a str,
    policy_path: String,
    policy: &'a str,
    require_signed_governance_action: bool,
    public_report_exposes_current_state: bool,
}

fn objective_json(checks: &ObjectiveChecks<'_>) -> String {
    let mut output = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in [
        ("candidateCommit", checks.candidate),
        ("assuranceEpochSha256", checks.epoch),
        ("checkKind", "weekly-composite"),
        ("observedAt", checks.observed_at),
    ] {
        output.push_str(",\n  \"");
        output.push_str(field);
        output.push_str("\": ");
        push_json(&mut output, value);
    }
    for (field, value) in objective_evidence_fields(checks) {
        output.push_str(",\n  \"");
        output.push_str(field);
        output.push_str("\": ");
        push_json(&mut output, value);
    }
    write!(
        output,
        ",\n  \"requireSignedGovernanceAction\": {},\n  \"publicReportExposesCurrentState\": {}",
        checks.require_signed_governance_action, checks.public_report_exposes_current_state
    )
    .expect("writing to String cannot fail");
    output.push_str("\n}\n");
    output
}

fn objective_evidence_fields<'a>(checks: &'a ObjectiveChecks<'a>) -> Vec<(&'static str, &'a str)> {
    vec![
        ("repositoryAssurancePath", checks.assurance_path.as_str()),
        ("repositoryAssuranceSha256", checks.assurance),
        (
            "differentialPropertyPath",
            checks.differential_path.as_str(),
        ),
        ("differentialPropertySha256", checks.differential),
        ("regressionImpactPath", checks.impact_path.as_str()),
        ("regressionImpactSha256", checks.impact),
        ("publicCurrentStatePath", checks.public_state_path.as_str()),
        ("publicCurrentStateSha256", checks.public_state),
        (
            "nativeProvenanceSelectionPath",
            checks.native_provenance_selection_path.as_str(),
        ),
        (
            "nativeProvenanceSelectionSha256",
            checks.native_provenance_selection,
        ),
        (
            "activeSubjectSelectionPath",
            checks.active_subject_selection_path.as_str(),
        ),
        (
            "activeSubjectSelectionSha256",
            checks.active_subject_selection,
        ),
        (
            "divergenceIssueManifestPath",
            checks.divergence_issue_manifest_path.as_str(),
        ),
        (
            "divergenceIssueManifestSha256",
            checks.divergence_issue_manifest,
        ),
        (
            "divergenceWarningsPath",
            checks.divergence_warnings_path.as_str(),
        ),
        ("divergenceWarningsSha256", checks.divergence_warnings),
        ("mutationPath", checks.mutation_path.as_str()),
        ("mutationSha256", checks.mutation),
        (
            "macosNativeProvenancePath",
            checks.macos_provenance_path.as_str(),
        ),
        ("macosNativeProvenanceSha256", checks.macos_provenance),
        (
            "windowsNativeProvenancePath",
            checks.windows_provenance_path.as_str(),
        ),
        ("windowsNativeProvenanceSha256", checks.windows_provenance),
        ("firstCustodyPath", checks.first_custody_path.as_str()),
        ("firstCustodySha256", checks.first_custody),
        ("secondCustodyPath", checks.second_custody_path.as_str()),
        ("secondCustodySha256", checks.second_custody),
        (
            "firstCustodyDssePath",
            checks.first_custody_dsse_path.as_str(),
        ),
        ("firstCustodyDsseSha256", checks.first_custody_dsse),
        (
            "secondCustodyDssePath",
            checks.second_custody_dsse_path.as_str(),
        ),
        ("secondCustodyDsseSha256", checks.second_custody_dsse),
        (
            "runnerToolchainBaselinePath",
            checks.runner_baseline_path.as_str(),
        ),
        ("runnerToolchainBaselineSha256", checks.runner_baseline),
        (
            "runnerToolchainCurrentPath",
            checks.runner_current_path.as_str(),
        ),
        ("runnerToolchainCurrentSha256", checks.runner_current),
        ("reviewRevocationsPath", checks.revocations_path.as_str()),
        ("reviewRevocationsSha256", checks.revocations),
        ("divergencesPath", checks.divergences_path.as_str()),
        ("divergencesSha256", checks.divergences),
        ("surveillancePolicyPath", checks.policy_path.as_str()),
        ("surveillancePolicySha256", checks.policy),
    ]
}

fn workflow_final_record() -> Result<String, String> {
    final_record(&Options {
        input: Some(component_path(["ci-out", "native-shards"])),
        output: Some(component_path(["ci-out", "promotion-record"])),
        epoch_file: Some(component_path([
            "ci-out",
            "native-shards",
            "assurance-epoch.json",
        ])),
        proposal: Some(PathBuf::from(
            "ci-out/native-shards/promotion-proposal.json",
        )),
        approval: Some(PathBuf::from(
            "ci-out/native-shards/promotion-proposal-approval.dsse.json",
        )),
        gate: Some(component_path(["ci-out", "promotion-gate.json"])),
        report: Some(component_path(["ci-out", "compatibility-report.md"])),
        custody: Some(PathBuf::from(
            "ci-out/native-shards/evidence/custody/custody-receipt.json",
        )),
        ..Options::default()
    })
}

fn workflow_observe() -> Result<String, String> {
    let observed_at = crate::custody_ops::current_utc_timestamp()?;
    let options = Options {
        input: Some(component_path(["ci-out", "active-promotion-record"])),
        output: Some(PathBuf::from(
            "ci-out/surveillance/promotion-transition.json",
        )),
        epoch_file: Some(component_path(["ci-out", "assurance-epoch.json"])),
        proposal: Some(PathBuf::from(
            "ci-out/active-promotion-record/approved-proposal/promotion-proposal.json",
        )),
        approval: Some(PathBuf::from(
            "ci-out/active-promotion-record/approved-proposal/promotion-proposal-approval.dsse.json",
        )),
        gate: Some(PathBuf::from(
            "ci-out/active-promotion-record/promotion-gate.json",
        )),
        report: Some(PathBuf::from(
            "ci-out/active-promotion-record/compatibility-report.md",
        )),
        custody: Some(PathBuf::from(
            "ci-out/active-promotion-record/approved-proposal/evidence/custody/custody-receipt.json",
        )),
        objective: Some(component_path([
            "ci-out",
            "surveillance",
            "objective-checks.json",
        ])),
        prior: Some(PathBuf::from(
            "ci-out/active-promotion-record/promotion-current-state.json",
        )),
        policy: Some(current_governance_path("surveillance-policy.toml")),
        check_kind: Some("weekly-composite".to_owned()),
        observed_at: Some(observed_at.clone()),
        artifact_id: None,
    };
    let message = match transition_record(&options) {
        Ok(message) => message,
        Err(error) => emergency_transition(&observed_at, &error)?,
    };
    retain_public_release_files()?;
    Ok(message)
}

fn retain_public_release_files() -> Result<(), String> {
    let active = component_path(["ci-out", "active-promotion-record"]);
    let public = component_path(["ci-out", "surveillance"]);
    let transition = public.join("promotion-transition.json");
    let transition_text = read_text(&transition)?;
    let report = active.join("compatibility-report.md");
    if file_digest(&report)? != quoted_field(&transition_text, "compatibilityReportSha256")? {
        return Err("public compatibility report differs from transition binding".to_owned());
    }
    copy_file(&report, &public.join("compatibility-report.md"))?;
    let divergences = active
        .join("approved-proposal")
        .join("evidence")
        .join("review")
        .join("divergence-report.json");
    let public_divergences = crate::assurance::public_divergence_details_bytes(&divergences)?;
    write_atomic(
        &public.join("accepted-divergences.json"),
        &public_divergences,
    )?;
    let report_sha256 = file_digest(&public.join("compatibility-report.md"))?;
    let divergences_sha256 = file_digest(&public.join("accepted-divergences.json"))?;
    let transition_sha256 = file_digest(&transition)?;
    let statement = format!(
        "{{\n  \"schemaVersion\": 1,\n  \"candidateCommit\": \"{}\",\n  \"assuranceEpochSha256\": \"{}\",\n  \"promotionState\": \"{}\",\n  \"compatibilityReportSha256\": \"{report_sha256}\",\n  \"acceptedDivergencesSha256\": \"{divergences_sha256}\",\n  \"transitionSha256\": \"{transition_sha256}\",\n  \"issuedAt\": \"{}\",\n  \"claim\": \"compatibility is bounded to the retained claim-cell, platform, profile, normalizer, divergence, and custody evidence in this report\"\n}}\n",
        quoted_field(&transition_text, "candidateCommit")?,
        quoted_field(&transition_text, "assuranceEpochSha256")?,
        quoted_field(&transition_text, "derivedState")?,
        quoted_field(&transition_text, "observedAt")?,
    );
    write_atomic(
        &public.join("public-release-statement.json"),
        statement.as_bytes(),
    )?;
    Ok(())
}

fn emergency_transition(observed_at: &str, failure: &str) -> Result<String, String> {
    let primary_path = component_path(["ci-out", "active-primary", "provider-observation.json"]);
    let secondary_path =
        component_path(["ci-out", "active-secondary", "provider-observation.json"]);
    let primary = component_or_failure("primary-provider-observation", &primary_path, observed_at)?;
    let secondary = component_or_failure(
        "secondary-provider-observation",
        &secondary_path,
        observed_at,
    )?;
    let primary_text = fs::read_to_string(&primary).unwrap_or_default();
    let secondary_text = fs::read_to_string(&secondary).unwrap_or_default();
    let primary_subject = observation_subject(&primary_text);
    let secondary_subject = observation_subject(&secondary_text);
    let common_subject = match (primary_subject, secondary_subject) {
        (Some(first), Some(second)) if first == second => Some(first),
        (Some(subject), None) | (None, Some(subject)) => Some(subject),
        _ => None,
    };
    let (candidate, epoch, subject_state) = if let Some((candidate, epoch)) = common_subject {
        (candidate, epoch, "known")
    } else {
        let (candidate, epoch) = crate::assurance::epoch(Path::new("."))?;
        (candidate, epoch.hex(), "observer-source-only")
    };
    let policy = component_or_failure(
        "surveillance-policy",
        &current_governance_path("surveillance-policy.toml"),
        observed_at,
    )?;
    let mut output = String::from("{\n  \"schemaVersion\": 2");
    let failure_sha256 = sha256_bytes(failure.as_bytes()).hex();
    let supersedes = sha256_bytes(b"unavailable-prior-promotion-state").hex();
    let primary_sha256 = file_digest(&primary)?;
    let secondary_sha256 = file_digest(&secondary)?;
    let policy_sha256 = file_digest(&policy)?;
    for (field, value) in [
        ("subjectState", subject_state),
        ("candidateCommit", candidate.as_str()),
        ("assuranceEpochSha256", epoch.as_str()),
        ("primaryObservationSha256", primary_sha256.as_str()),
        ("secondaryObservationSha256", secondary_sha256.as_str()),
        ("surveillancePolicySha256", policy_sha256.as_str()),
        ("checkKind", "weekly-composite"),
        ("observedAt", observed_at),
        ("result", "fail"),
        ("priorState", "unknown"),
        ("derivedState", "at-risk"),
        ("failureSha256", failure_sha256.as_str()),
        ("supersedesSha256", supersedes.as_str()),
    ] {
        output.push_str(",\n  \"");
        output.push_str(field);
        output.push_str("\": ");
        push_json(&mut output, value);
    }
    output.push_str(",\n  \"incidentRequired\": true\n}\n");
    let path = component_path(["ci-out", "surveillance", "promotion-transition.json"]);
    write_atomic(&path, output.as_bytes())?;
    verify_transition(&path)?;
    Ok("derived signed-ready emergency at-risk surveillance transition".to_owned())
}

fn observation_subject(document: &str) -> Option<(String, String)> {
    if boolean_field(document, "subjectKnown").ok()? {
        let candidate = quoted_field(document, "candidateCommit").ok()?;
        let epoch = quoted_field(document, "assuranceEpochSha256").ok()?;
        require_git_sha(&candidate, "provider observation candidate").ok()?;
        require_digest(&epoch, "provider observation epoch").ok()?;
        Some((candidate, epoch))
    } else {
        None
    }
}

fn parse(arguments: &[OsString]) -> Result<(String, Options), String> {
    let action = arguments
        .get(1)
        .and_then(|value| value.to_str())
        .ok_or_else(|| "surveillance-ops requires an action".to_owned())?
        .to_owned();
    let mut options = Options::default();
    let mut index = 2;
    while index < arguments.len() {
        let flag = arguments[index]
            .to_str()
            .ok_or_else(|| "surveillance-ops option must be UTF-8".to_owned())?;
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match flag {
            "--input" => set_path(&mut options.input, value, flag)?,
            "--output" => set_path(&mut options.output, value, flag)?,
            "--epoch-file" => set_path(&mut options.epoch_file, value, flag)?,
            "--proposal" => set_path(&mut options.proposal, value, flag)?,
            "--approval" => set_path(&mut options.approval, value, flag)?,
            "--gate" => set_path(&mut options.gate, value, flag)?,
            "--report" => set_path(&mut options.report, value, flag)?,
            "--custody" => set_path(&mut options.custody, value, flag)?,
            "--objective" => set_path(&mut options.objective, value, flag)?,
            "--prior" => set_path(&mut options.prior, value, flag)?,
            "--policy" => set_path(&mut options.policy, value, flag)?,
            "--check-kind" => set_text(&mut options.check_kind, value, flag)?,
            "--observed-at" => set_text(&mut options.observed_at, value, flag)?,
            "--artifact-id" => set_text(&mut options.artifact_id, value, flag)?,
            _ => return Err(format!("unknown surveillance-ops option {flag:?}")),
        }
        index += 2;
    }
    Ok((action, options))
}

fn final_record(options: &Options) -> Result<String, String> {
    let input = required_path(options.input.as_ref(), "--input")?;
    let output = required_path(options.output.as_ref(), "--output")?;
    if output.exists() || output.starts_with(input) {
        return Err("promotion-record output must be a new directory outside its input".to_owned());
    }
    let epoch_path = required_path(options.epoch_file.as_ref(), "--epoch-file")?;
    let proposal = required_path(options.proposal.as_ref(), "--proposal")?;
    let approval = required_path(options.approval.as_ref(), "--approval")?;
    let gate = required_path(options.gate.as_ref(), "--gate")?;
    let report = required_path(options.report.as_ref(), "--report")?;
    let custody = required_path(options.custody.as_ref(), "--custody")?;
    for path in [proposal, approval, gate, report, custody] {
        require_regular_file(path)?;
    }
    let (candidate, epoch) = crate::assurance::retained_epoch_digest(epoch_path)?;
    require_digest_sibling(proposal)?;
    require_digest_sibling(gate)?;
    let approved = output.join("approved-proposal");
    copy_tree(input, &approved)?;
    copy_file(gate, &output.join("promotion-gate.json"))?;
    copy_file(
        &gate.with_extension("sha256"),
        &output.join("promotion-gate.sha256"),
    )?;
    copy_file(report, &output.join("compatibility-report.md"))?;
    let report_digest = sha256_file(report).map_err(|error| error.to_string())?;
    write_atomic(
        &output.join("compatibility-report.sha256"),
        format!("{}  compatibility-report.md\n", report_digest.hex()).as_bytes(),
    )?;
    let promoted_at = crate::custody_ops::current_utc_timestamp()?;
    let runner = runner_identity_json()?;
    write_atomic(&output.join("runner-toolchain.json"), runner.as_bytes())?;
    let proposal_digest = file_digest(proposal)?;
    let approval_digest = file_digest(approval)?;
    let gate_digest = file_digest(gate)?;
    let custody_digest = file_digest(custody)?;
    let report_digest_text = report_digest.hex();
    let runner_digest = file_digest(&output.join("runner-toolchain.json"))?;
    let manifest_fields = PromotionRecordFields {
        candidate: &candidate,
        epoch: &epoch,
        proposal: &proposal_digest,
        approval: &approval_digest,
        gate: &gate_digest,
        report: &report_digest_text,
        custody: &custody_digest,
        runner_toolchain: &runner_digest,
        promoted_at: &promoted_at,
    };
    let manifest = promotion_record_json(&manifest_fields);
    write_atomic(&output.join("promotion-record.json"), manifest.as_bytes())?;
    write_atomic(
        &output.join("promotion-record.sha256"),
        format!(
            "{}  promotion-record.json\n",
            sha256_bytes(manifest.as_bytes()).hex()
        )
        .as_bytes(),
    )?;
    Ok(format!(
        "assembled immutable promotion record {}",
        output.display()
    ))
}

struct PromotionRecordFields<'a> {
    candidate: &'a str,
    epoch: &'a str,
    proposal: &'a str,
    approval: &'a str,
    gate: &'a str,
    report: &'a str,
    custody: &'a str,
    runner_toolchain: &'a str,
    promoted_at: &'a str,
}

fn promotion_record_json(fields: &PromotionRecordFields<'_>) -> String {
    let mut output = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in [
        ("candidateCommit", fields.candidate),
        ("assuranceEpochSha256", fields.epoch),
        ("promotionProposalSha256", fields.proposal),
        ("promotionApprovalSha256", fields.approval),
        ("promotionGateSha256", fields.gate),
        ("compatibilityReportSha256", fields.report),
        ("prePromotionCustodySha256", fields.custody),
        ("runnerToolchainSha256", fields.runner_toolchain),
        ("promotedAt", fields.promoted_at),
        ("state", "pending-durable-custody"),
    ] {
        output.push_str(",\n  \"");
        output.push_str(field);
        output.push_str("\": ");
        push_json(&mut output, value);
    }
    output.push_str("\n}\n");
    output
}

fn runner_identity_json() -> Result<String, String> {
    let output = Command::new("rustc")
        .args(["--version", "--verbose"])
        .output()
        .map_err(|error| format!("cannot execute rustc identity probe: {error}"))?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err("rustc identity probe failed or wrote stderr".to_owned());
    }
    let rustc =
        String::from_utf8(output.stdout).map_err(|_| "rustc identity is not UTF-8".to_owned())?;
    let runner_name = environment_atom("RUNNER_NAME")?;
    let runner_os = environment_atom("RUNNER_OS")?;
    let runner_arch = environment_atom("RUNNER_ARCH")?;
    let image_os = environment_atom("ImageOS")?;
    let image_version = environment_atom("ImageVersion")?;
    let rustc_digest = sha256_bytes(rustc.as_bytes()).hex();
    let mut json = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in [
        ("runnerName", runner_name.as_str()),
        ("runnerOs", runner_os.as_str()),
        ("runnerArch", runner_arch.as_str()),
        ("imageOs", image_os.as_str()),
        ("imageVersion", image_version.as_str()),
        ("rustcVerboseSha256", rustc_digest.as_str()),
    ] {
        json.push_str(",\n  \"");
        json.push_str(field);
        json.push_str("\": ");
        push_json(&mut json, value);
    }
    json.push_str("\n}\n");
    Ok(json)
}

fn environment_atom(name: &str) -> Result<String, String> {
    let value = std::env::var(name).map_err(|_| format!("runner identity lacks {name}"))?;
    require_atom(&value, name)?;
    Ok(value)
}

fn transition_record(options: &Options) -> Result<String, String> {
    let retained = required_path(options.input.as_ref(), "--input")?;
    let output = required_path(options.output.as_ref(), "--output")?;
    let epoch_path = required_path(options.epoch_file.as_ref(), "--epoch-file")?;
    let objective = required_path(options.objective.as_ref(), "--objective")?;
    let prior = required_path(options.prior.as_ref(), "--prior")?;
    let policy = required_path(options.policy.as_ref(), "--policy")?;
    let check_kind = required_text(options.check_kind.as_ref(), "--check-kind")?;
    let observed_at = required_text(options.observed_at.as_ref(), "--observed-at")?;
    require_atom(check_kind, "check kind")?;
    crate::custody_ops::validate_utc_timestamp(observed_at)?;
    let (candidate, epoch) = crate::assurance::retained_epoch_digest(epoch_path)?;
    let prior_text = fs::read_to_string(prior).map_err(|error| {
        format!(
            "cannot read prior promotion state {}: {error}",
            prior.display()
        )
    })?;
    let prior_state = required_canonical_state(&prior_text)?;
    let objective_text = fs::read_to_string(objective)
        .map_err(|error| format!("cannot read objective surveillance input: {error}"))?;
    if quoted_field(&objective_text, "observedAt")? != observed_at {
        return Err("transition time differs from objective observation time".to_owned());
    }
    let surveillance_policy = SurveillancePolicy::load(policy)?;
    let cadence = surveillance_policy.deadline_days();
    if cadence == 0 || crate::custody_ops::utc_age_days(observed_at)? > cadence {
        return Err("surveillance observation is stale under committed cadence".to_owned());
    }
    let evaluation = objective_evaluation(
        &objective_text,
        &candidate,
        &epoch,
        check_kind,
        &surveillance_policy,
    )?;
    let objective_passed = evaluation.passed;
    let derived_state = if objective_passed {
        match prior_state {
            "promoted" => "promoted",
            "at-risk" => "at-risk",
            "revoked" => "revoked",
            _ => return Err("prior promotion state is unsupported".to_owned()),
        }
    } else if prior_state == "revoked" || evaluation.automatic_revocation {
        "revoked"
    } else {
        "at-risk"
    };
    let proposal = required_path(options.proposal.as_ref(), "--proposal")?;
    let approval = required_path(options.approval.as_ref(), "--approval")?;
    let gate = required_path(options.gate.as_ref(), "--gate")?;
    let report = required_path(options.report.as_ref(), "--report")?;
    let custody = required_path(options.custody.as_ref(), "--custody")?;
    for path in [
        proposal, approval, gate, report, custody, prior, policy, objective,
    ] {
        require_regular_file(path)?;
        if !path.starts_with(retained) && path != policy && path != objective && path != epoch_path
        {
            return Err(format!(
                "retained promotion input {} escaped active record",
                path.display()
            ));
        }
    }
    let transition_fields = TransitionFields {
        candidate: &candidate,
        epoch: &epoch,
        proposal: &file_digest(proposal)?,
        approval: &file_digest(approval)?,
        gate: &file_digest(gate)?,
        report: &file_digest(report)?,
        custody: &file_digest(custody)?,
        policy: &file_digest(policy)?,
        check_kind,
        observed_at,
        objective_path: path_text(objective)?,
        objective: &file_digest(objective)?,
        result: if objective_passed { "pass" } else { "fail" },
        prior_state,
        derived_state,
        incident_required: !objective_passed,
        supersedes: &file_digest(prior)?,
    };
    let record = transition_json(&transition_fields);
    write_atomic(output, record.as_bytes())?;
    verify_transition(output)?;
    Ok(format!(
        "derived promotion surveillance state {derived_state}"
    ))
}

struct TransitionFields<'a> {
    candidate: &'a str,
    epoch: &'a str,
    proposal: &'a str,
    approval: &'a str,
    gate: &'a str,
    report: &'a str,
    custody: &'a str,
    policy: &'a str,
    check_kind: &'a str,
    observed_at: &'a str,
    objective_path: String,
    objective: &'a str,
    result: &'a str,
    prior_state: &'a str,
    derived_state: &'a str,
    incident_required: bool,
    supersedes: &'a str,
}

fn transition_json(fields: &TransitionFields<'_>) -> String {
    let mut output = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in [
        ("candidateCommit", fields.candidate),
        ("assuranceEpochSha256", fields.epoch),
        ("promotionProposalSha256", fields.proposal),
        ("promotionApprovalSha256", fields.approval),
        ("promotionGateSha256", fields.gate),
        ("compatibilityReportSha256", fields.report),
        ("prePromotionCustodySha256", fields.custody),
        ("surveillancePolicySha256", fields.policy),
        ("checkKind", fields.check_kind),
        ("observedAt", fields.observed_at),
        ("objectiveInputPath", &fields.objective_path),
        ("objectiveInputSha256", fields.objective),
        ("result", fields.result),
        ("priorState", fields.prior_state),
        ("derivedState", fields.derived_state),
    ] {
        output.push_str(",\n  \"");
        output.push_str(field);
        output.push_str("\": ");
        push_json(&mut output, value);
    }
    write!(
        output,
        ",\n  \"incidentRequired\": {}",
        fields.incident_required
    )
    .expect("writing to String cannot fail");
    output.push_str(",\n  \"supersedesSha256\": ");
    push_json(&mut output, fields.supersedes);
    output.push_str("\n}\n");
    output
}

pub(crate) fn verify_transition(path: &Path) -> Result<String, String> {
    let document = fs::read_to_string(path).map_err(|error| {
        format!(
            "cannot read surveillance transition {}: {error}",
            path.display()
        )
    })?;
    if document.starts_with("{\n  \"schemaVersion\": 2,") {
        return verify_emergency_transition(&document);
    }
    if !document.starts_with("{\n  \"schemaVersion\": 1,") || !document.ends_with("\n}\n") {
        return Err("surveillance transition is not canonical schema v1 or v2 JSON".to_owned());
    }
    let candidate = quoted_field(&document, "candidateCommit")?;
    require_git_sha(&candidate, "transition candidate")?;
    for field in [
        "assuranceEpochSha256",
        "promotionProposalSha256",
        "promotionApprovalSha256",
        "promotionGateSha256",
        "compatibilityReportSha256",
        "prePromotionCustodySha256",
        "surveillancePolicySha256",
        "objectiveInputSha256",
        "supersedesSha256",
    ] {
        require_digest(&quoted_field(&document, field)?, field)?;
    }
    crate::custody_ops::validate_utc_timestamp(&quoted_field(&document, "observedAt")?)?;
    let result = quoted_field(&document, "result")?;
    let prior = quoted_field(&document, "priorState")?;
    let derived = quoted_field(&document, "derivedState")?;
    if !matches!(result.as_str(), "pass" | "fail")
        || !matches!(prior.as_str(), "promoted" | "at-risk" | "revoked")
        || !matches!(derived.as_str(), "promoted" | "at-risk" | "revoked")
        || (result == "fail" && derived == "promoted")
        || (prior == "revoked" && derived != "revoked")
    {
        return Err("surveillance transition contains an invalid state transition".to_owned());
    }
    let incident = boolean_field(&document, "incidentRequired")?;
    if incident != (result == "fail") {
        return Err("surveillance incident flag is not derived from result".to_owned());
    }
    Ok("verified canonical promotion surveillance transition".to_owned())
}

fn verify_emergency_transition(document: &str) -> Result<String, String> {
    if !document.ends_with("\n}\n")
        || quoted_field(document, "result")? != "fail"
        || quoted_field(document, "derivedState")? != "at-risk"
        || !boolean_field(document, "incidentRequired")?
    {
        return Err("emergency surveillance transition is not fail-closed".to_owned());
    }
    let subject_state = quoted_field(document, "subjectState")?;
    let candidate = quoted_field(document, "candidateCommit")?;
    let epoch = quoted_field(document, "assuranceEpochSha256")?;
    match subject_state.as_str() {
        "known" => {
            require_git_sha(&candidate, "emergency transition candidate")?;
            require_digest(&epoch, "emergency transition epoch")?;
            if !matches!(
                quoted_field(document, "priorState")?.as_str(),
                "promoted" | "at-risk" | "revoked"
            ) {
                return Err("known emergency transition lacks a canonical prior state".to_owned());
            }
        }
        "observer-source-only" => {
            require_git_sha(&candidate, "emergency observer source candidate")?;
            require_digest(&epoch, "emergency observer source epoch")?;
            if quoted_field(document, "priorState")? != "unknown" {
                return Err("observer-only emergency transition claims a prior state".to_owned());
            }
        }
        _ => return Err("emergency surveillance subject state is invalid".to_owned()),
    }
    for field in [
        "primaryObservationSha256",
        "secondaryObservationSha256",
        "surveillancePolicySha256",
        "failureSha256",
        "supersedesSha256",
    ] {
        require_digest(&quoted_field(document, field)?, field)?;
    }
    crate::custody_ops::validate_utc_timestamp(&quoted_field(document, "observedAt")?)?;
    Ok("verified canonical emergency at-risk surveillance transition".to_owned())
}

struct ObjectiveEvaluation {
    passed: bool,
    automatic_revocation: bool,
}

struct ObjectiveEvidencePaths {
    assurance: PathBuf,
    differential: PathBuf,
    impact: PathBuf,
    public_state: PathBuf,
    native_provenance_selection: PathBuf,
    active_subject_selection: PathBuf,
    divergence_issue_manifest: PathBuf,
    divergence_warnings: PathBuf,
    mutation: PathBuf,
    macos_provenance: PathBuf,
    windows_provenance: PathBuf,
    first_custody: PathBuf,
    second_custody: PathBuf,
    first_custody_dsse: PathBuf,
    second_custody_dsse: PathBuf,
    runner_baseline: PathBuf,
    runner_current: PathBuf,
    revocations: PathBuf,
    divergences: PathBuf,
    policy: PathBuf,
}

fn objective_evidence_paths(document: &str) -> Result<ObjectiveEvidencePaths, String> {
    Ok(ObjectiveEvidencePaths {
        assurance: objective_component(
            document,
            "repositoryAssurancePath",
            "repositoryAssuranceSha256",
        )?,
        differential: objective_component(
            document,
            "differentialPropertyPath",
            "differentialPropertySha256",
        )?,
        impact: objective_component(document, "regressionImpactPath", "regressionImpactSha256")?,
        public_state: objective_component(
            document,
            "publicCurrentStatePath",
            "publicCurrentStateSha256",
        )?,
        native_provenance_selection: objective_component(
            document,
            "nativeProvenanceSelectionPath",
            "nativeProvenanceSelectionSha256",
        )?,
        active_subject_selection: objective_component(
            document,
            "activeSubjectSelectionPath",
            "activeSubjectSelectionSha256",
        )?,
        divergence_issue_manifest: objective_component(
            document,
            "divergenceIssueManifestPath",
            "divergenceIssueManifestSha256",
        )?,
        divergence_warnings: objective_component(
            document,
            "divergenceWarningsPath",
            "divergenceWarningsSha256",
        )?,
        mutation: objective_component(document, "mutationPath", "mutationSha256")?,
        macos_provenance: objective_component(
            document,
            "macosNativeProvenancePath",
            "macosNativeProvenanceSha256",
        )?,
        windows_provenance: objective_component(
            document,
            "windowsNativeProvenancePath",
            "windowsNativeProvenanceSha256",
        )?,
        first_custody: objective_component(document, "firstCustodyPath", "firstCustodySha256")?,
        second_custody: objective_component(document, "secondCustodyPath", "secondCustodySha256")?,
        first_custody_dsse: objective_component(
            document,
            "firstCustodyDssePath",
            "firstCustodyDsseSha256",
        )?,
        second_custody_dsse: objective_component(
            document,
            "secondCustodyDssePath",
            "secondCustodyDsseSha256",
        )?,
        runner_baseline: objective_component(
            document,
            "runnerToolchainBaselinePath",
            "runnerToolchainBaselineSha256",
        )?,
        runner_current: objective_component(
            document,
            "runnerToolchainCurrentPath",
            "runnerToolchainCurrentSha256",
        )?,
        revocations: objective_component(
            document,
            "reviewRevocationsPath",
            "reviewRevocationsSha256",
        )?,
        divergences: objective_component(document, "divergencesPath", "divergencesSha256")?,
        policy: objective_component(
            document,
            "surveillancePolicyPath",
            "surveillancePolicySha256",
        )?,
    })
}

fn objective_evaluation(
    document: &str,
    candidate: &str,
    epoch: &str,
    check_kind: &str,
    policy: &SurveillancePolicy,
) -> Result<ObjectiveEvaluation, String> {
    if quoted_field(document, "candidateCommit")? != candidate
        || quoted_field(document, "assuranceEpochSha256")? != epoch
        || quoted_field(document, "checkKind")? != check_kind
    {
        return Err(
            "objective surveillance input does not bind current candidate, epoch, and check"
                .to_owned(),
        );
    }
    crate::custody_ops::validate_utc_timestamp(&quoted_field(document, "observedAt")?)?;
    objective_evidence_result(document, candidate, epoch, policy).or(Ok(ObjectiveEvaluation {
        passed: false,
        automatic_revocation: false,
    }))
}

fn objective_evidence_result(
    document: &str,
    candidate: &str,
    epoch: &str,
    policy: &SurveillancePolicy,
) -> Result<ObjectiveEvaluation, String> {
    let paths = objective_evidence_paths(document)?;
    verify_objective_policy_binding(document, &paths.policy, policy)?;
    let assurance_text = read_component(&paths.assurance)?;
    let differential_text = read_component(&paths.differential)?;
    let impact_text = read_component(&paths.impact)?;
    let public_state_text = read_component(&paths.public_state)?;
    let mutation_text = read_component(&paths.mutation)?;
    let first_custody_text = read_component(&paths.first_custody)?;
    let second_custody_text = read_component(&paths.second_custody)?;
    let assurance_passed = quoted_field(&assurance_text, "scope")? == "repository-structure"
        && boolean_field(&assurance_text, "passed")?;
    let differential_passed = quoted_field(&differential_text, "suite")? == "nightly"
        && boolean_field(&differential_text, "passed")?
        && verify_retained_active_subject(&paths, candidate, epoch)?;
    let impact_identity = quoted_field(&impact_text, "candidateCommit")? == candidate
        && quoted_field(&impact_text, "assuranceEpochSha256")? == epoch;
    let regression_passed = impact_identity
        && boolean_field(&impact_text, "promotedClaimRegressionPassed")?
        && unsigned_field(&impact_text, "mismatchCount")? == 0;
    let public_state_passed = quoted_field(&public_state_text, "candidateCommit")? == candidate
        && quoted_field(&public_state_text, "assuranceEpochSha256")? == epoch
        && quoted_field(&public_state_text, "state")? == "exact-public-and-dual-provider-agreement";
    let divergence_expiry_passed = impact_identity
        && boolean_field(&impact_text, "acceptedDivergenceExpiryPassed")?
        && unsigned_field(&impact_text, "expiredDivergenceCount")? == 0;
    let mutation_passed = quoted_field(&mutation_text, "candidateSourceCommit")? == candidate
        && quoted_field(&mutation_text, "assuranceEpochSha256")? == epoch
        && unsigned_field(&mutation_text, "undetectedCriticalMutants")? == 0
        && crate::custody_ops::utc_age_days(&quoted_field(&mutation_text, "issuedAt")?)?
            <= policy
                .warnings
                .mutation_report_maximum_age
                .min(policy.cadence.mutation_suite);
    let provenance_passed = verify_native_provenance_selection(&paths, candidate, epoch, policy)
        .unwrap_or(false)
        && surveillance_provenance_passed(&paths, policy);
    let custody_passed = surveillance_custody_passed(
        &paths,
        &first_custody_text,
        &second_custody_text,
        candidate,
        epoch,
        policy.warnings.custody_scrub_overdue,
    )?;
    verify_mutation_report(&paths.mutation, candidate, epoch)?;
    let runner_passed = fs::read(&paths.runner_baseline).map_err(|error| {
        format!(
            "cannot read runner baseline {}: {error}",
            paths.runner_baseline.display()
        )
    })? == fs::read(&paths.runner_current).map_err(|error| {
        format!(
            "cannot read current runner identity {}: {error}",
            paths.runner_current.display()
        )
    })?;
    let revocation_passed = validate_revocations(&read_component(&paths.revocations)?)?
        && verify_current_governance_revocations(&paths.revocations).unwrap_or(false);
    let divergence_passed = validate_divergences(&read_component(&paths.divergences)?)?;
    let divergence_issues_passed = crate::surveillance_impact::verify_divergence_issue_evidence(
        &component_path(["ci-out", "active-promotion-record"]),
        candidate,
        epoch,
        &paths.divergence_issue_manifest,
        &paths.divergence_warnings,
        &paths.policy,
    )
    .unwrap_or(false);
    let mut evaluation = evaluate_surveillance_events(
        policy,
        &[
            (
                "artifact_attestation_invalidated",
                assurance_passed && provenance_passed && public_state_passed,
            ),
            (
                "promoted_claim_regression",
                differential_passed && regression_passed,
            ),
            ("critical_mutant_undetected", mutation_passed),
            ("custody_retrieval_failure", custody_passed),
            ("platform_or_toolchain_support_expired", runner_passed),
            ("signing_identity_revoked", revocation_passed),
            (
                "accepted_divergence_expired",
                divergence_passed && divergence_expiry_passed && divergence_issues_passed,
            ),
        ],
    )?;
    if unsigned_field(&impact_text, "divergenceExpiryWarningCount")? != 0 {
        evaluation.passed = false;
    }
    Ok(evaluation)
}

fn verify_retained_active_subject(
    paths: &ObjectiveEvidencePaths,
    candidate: &str,
    epoch: &str,
) -> Result<bool, String> {
    let selection = read_component(&paths.active_subject_selection)?;
    let input = component_path(["ci-out", "surveillance", "active-subject"]);
    crate::suite::verify_retained_linux_surveillance_shard(
        input.as_path(),
        &component_path(["ci-out", "active-promotion-record"]),
        candidate,
        epoch,
    )?;
    let claim_index = input.join("evidence").join("claim-index.json");
    let claim_index_text = read_text(&claim_index)?;
    let mutation = input.join("mutation").join("mutation-score.pending.json");
    crate::assurance::verify_surveillance_mutation_report(
        &input.join("subject-policy"),
        &mutation,
        candidate,
        epoch,
    )?;
    Ok(
        quoted_field(&selection, "artifact")? == "ephemeralEvidence-active-subject-execution"
            && quoted_field(&selection, "workflowPath")?
                == ".github/workflows/promotion-surveillance.yml"
            && matches!(
                quoted_field(&selection, "event")?.as_str(),
                "push" | "schedule" | "workflow_dispatch"
            )
            && quoted_field(&selection, "candidateCommit")? == candidate
            && quoted_field(&selection, "directorySha256")?
                == crate::custody_ops::directory_digest(&input)?
            && quoted_field(&selection, "selectionState")? == "exact-provider-object"
            && quoted_field(&claim_index_text, "candidateSourceCommit")? == candidate,
    )
}

fn surveillance_provenance_passed(
    paths: &ObjectiveEvidencePaths,
    policy: &SurveillancePolicy,
) -> bool {
    let signer_policy = current_governance_path("reviews.allowed_signers");
    let macos = native_provenance_verification_root(&paths.macos_provenance).and_then(|root| {
        crate::assurance::verify_surveillance_oracle_provenance(
            root,
            &paths.macos_provenance,
            &signer_policy,
            policy.cadence.native_provenance_rebuild,
        )
    });
    let windows = native_provenance_verification_root(&paths.windows_provenance).and_then(|root| {
        crate::assurance::verify_surveillance_oracle_provenance(
            root,
            &paths.windows_provenance,
            &signer_policy,
            policy.cadence.native_provenance_rebuild,
        )
    });
    macos.as_deref() == Ok("macos-arm64") && windows.as_deref() == Ok("windows-amd64")
}

fn verify_native_provenance_selection(
    paths: &ObjectiveEvidencePaths,
    candidate: &str,
    epoch: &str,
    policy: &SurveillancePolicy,
) -> Result<bool, String> {
    let document = read_text(&paths.native_provenance_selection)?;
    if canonical_native_provenance_selection(&document)? != document {
        return Ok(false);
    }
    let provider_head = quoted_field(&document, "headSha")?;
    require_git_sha(&provider_head, "native provenance provider workflow head")?;
    if quoted_field(&document, "candidateCommit")? != candidate
        || quoted_field(&document, "assuranceEpochSha256")? != epoch
        || quoted_field(&document, "workflowPath")? != ".github/workflows/oracle-reproduce.yml"
        || crate::custody_ops::utc_age_days(&quoted_field(&document, "updatedAt")?)?
            > policy.cadence.native_provenance_rebuild
    {
        return Ok(false);
    }
    let run_id = unsigned_field(&document, "runId")?;
    let run_attempt = unsigned_field(&document, "runAttempt")?;
    let event = quoted_field(&document, "event")?;
    if !matches!(event.as_str(), "push" | "workflow_dispatch") {
        return Ok(false);
    }
    let root = component_path(["ci-out", "surveillance", "current-native-provenance"])
        .join(run_id.to_string())
        .join(run_attempt.to_string());
    let context = NativeSelectionVerification {
        document: &document,
        root: &root,
        run_id,
        run_attempt,
        event: &event,
        provider_head: &provider_head,
        candidate,
    };
    let macos =
        verify_selected_native_platform(&context, "macos", "macos-arm64", &paths.macos_provenance)?;
    let windows = verify_selected_native_platform(
        &context,
        "windows",
        "windows-amd64",
        &paths.windows_provenance,
    )?;
    Ok(macos && windows)
}

fn canonical_native_provenance_selection(document: &str) -> Result<String, String> {
    let text_fields = [
        "candidateCommit",
        "assuranceEpochSha256",
        "workflowPath",
        "event",
        "headSha",
        "updatedAt",
        "macosArtifactName",
        "macosDownloadedArchiveSha256",
        "macosExtractedTreeSha256",
        "macosProviderSelectionSha256",
        "macosProvenancePath",
        "macosProvenanceSha256",
        "windowsArtifactName",
        "windowsDownloadedArchiveSha256",
        "windowsExtractedTreeSha256",
        "windowsProviderSelectionSha256",
        "windowsProvenancePath",
        "windowsProvenanceSha256",
    ];
    let values = text_fields
        .iter()
        .map(|field| quoted_field(document, field))
        .collect::<Result<Vec<_>, _>>()?;
    require_git_sha(&values[0], "native provenance selection candidate")?;
    require_digest(&values[1], "native provenance selection epoch")?;
    require_git_sha(&values[4], "native provenance selection provider head")?;
    crate::custody_ops::validate_utc_timestamp(&values[5])?;
    for (index, label) in [
        (7, "macOS downloaded archive"),
        (8, "macOS extracted tree"),
        (9, "macOS provider selection"),
        (11, "macOS provenance"),
        (13, "Windows downloaded archive"),
        (14, "Windows extracted tree"),
        (15, "Windows provider selection"),
        (17, "Windows provenance"),
    ] {
        require_digest(&values[index], label)?;
    }
    let mut output = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in text_fields.iter().zip(values) {
        output.push_str(",\n  \"");
        output.push_str(field);
        output.push_str("\": ");
        push_json(&mut output, &value);
    }
    write!(
        output,
        ",\n  \"runId\": {},\n  \"runAttempt\": {},\n  \"macosArtifactId\": {},\n  \"windowsArtifactId\": {}\n}}\n",
        unsigned_field(document, "runId")?,
        unsigned_field(document, "runAttempt")?,
        unsigned_field(document, "macosArtifactId")?,
        unsigned_field(document, "windowsArtifactId")?,
    )
    .expect("writing to String cannot fail");
    Ok(output)
}

struct NativeSelectionVerification<'a> {
    document: &'a str,
    root: &'a Path,
    run_id: u64,
    run_attempt: u64,
    event: &'a str,
    provider_head: &'a str,
    candidate: &'a str,
}

fn verify_selected_native_platform(
    context: &NativeSelectionVerification<'_>,
    field_prefix: &str,
    platform: &str,
    provenance_path: &Path,
) -> Result<bool, String> {
    let capitalized = if field_prefix == "macos" {
        "macos"
    } else {
        "windows"
    };
    let path_field = format!("{capitalized}ProvenancePath");
    let sha_field = format!("{capitalized}ProvenanceSha256");
    let artifact_id_field = format!("{capitalized}ArtifactId");
    let artifact_name_field = format!("{capitalized}ArtifactName");
    let archive_field = format!("{capitalized}DownloadedArchiveSha256");
    let tree_field = format!("{capitalized}ExtractedTreeSha256");
    let selection_field = format!("{capitalized}ProviderSelectionSha256");
    let expected_root = context.root.join(platform);
    let extracted = expected_root.join("ci-out");
    let declared_path = portable_relative_path(&quoted_field(context.document, &path_field)?)?;
    if provenance_path != declared_path
        || !provenance_path.starts_with(&extracted)
        || file_digest(provenance_path)? != quoted_field(context.document, &sha_field)?
        || file_digest(&expected_root.join("artifact.zip"))?
            != quoted_field(context.document, &archive_field)?
        || crate::custody_ops::directory_digest(&extracted)?
            != quoted_field(context.document, &tree_field)?
    {
        return Ok(false);
    }
    let artifact_id = unsigned_field(context.document, &artifact_id_field)?;
    let artifact_name = quoted_field(context.document, &artifact_name_field)?;
    let token = workflow_github_token("native provenance source reverification")?;
    let workflow_source_root = context.root.join("provider-workflow-source");
    if !verify_native_provider_workflow_source(
        &token,
        context.provider_head,
        &workflow_source_root,
    )? {
        return Ok(false);
    }
    let output = context.root.join("provider-reverification").join(platform);
    let tree_sha256 = quoted_field(context.document, &tree_field)?;
    let selection = crate::assurance::verify_provider_artifact_selection_subject_to(
        &crate::assurance::ProviderArtifactSelectionSubject {
            root: &workflow_source_root,
            input_directory: &extracted,
            output_directory: &output,
            artifact_name: &artifact_name,
            workflow_path: ".github/workflows/oracle-reproduce.yml",
            event_name: context.event,
            run_id: context.run_id,
            run_attempt: context.run_attempt,
            artifact_id,
            provider_head: context.provider_head,
            candidate: context.candidate,
            expected_directory_sha256: &tree_sha256,
            expected_archive_sha256: &quoted_field(context.document, &archive_field)?,
        },
    )?;
    let archive = expected_root.join("artifact.zip");
    let archive_size = fs::metadata(&archive)
        .map_err(|error| format!("cannot inspect selected provider archive: {error}"))?
        .len();
    Ok(sha256_bytes(selection.as_bytes()).hex()
        == quoted_field(context.document, &selection_field)?
        && file_digest(&archive)? == quoted_field(&selection, "providerArchiveSha256")?
        && archive_size == unsigned_field(&selection, "providerArchiveSize")?)
}

fn portable_relative_path(value: &str) -> Result<PathBuf, String> {
    if value.is_empty() || value.starts_with('/') || value.contains('\\') {
        return Err("portable path is not a canonical relative path".to_owned());
    }
    let mut path = PathBuf::new();
    for component in value.split('/') {
        if component.is_empty() || matches!(component, "." | "..") {
            return Err("portable path contains an unsafe component".to_owned());
        }
        path = path.join(component);
    }
    Ok(path)
}

fn surveillance_custody_passed(
    paths: &ObjectiveEvidencePaths,
    first: &str,
    second: &str,
    candidate: &str,
    epoch: &str,
    maximum_age_days: u64,
) -> Result<bool, String> {
    let content_passed = custody_observation_passed(first, candidate, epoch, maximum_age_days)?
        && custody_observation_passed(second, candidate, epoch, maximum_age_days)?
        && quoted_field(first, "provider")? != quoted_field(second, "provider")?
        && quoted_field(first, "trustDomain")? != quoted_field(second, "trustDomain")?;
    let first_root = paths
        .first_custody
        .parent()
        .ok_or_else(|| "primary custody observation lacks a retained root".to_owned())?;
    let second_root = paths
        .second_custody
        .parent()
        .ok_or_else(|| "secondary custody observation lacks a retained root".to_owned())?;
    let first_signer = verify_provider_observation(first_root, first)?;
    let second_signer = verify_provider_observation(second_root, second)?;
    require_distinct_provider_signers(&first_signer, &second_signer)?;
    if paths.first_custody_dsse
        != paths
            .first_custody
            .with_file_name("provider-observation.dsse.json")
        || paths.second_custody_dsse
            != paths
                .second_custody
                .with_file_name("provider-observation.dsse.json")
    {
        return Err("objective custody DSSE paths differ from their raw observations".to_owned());
    }
    Ok(content_passed)
}

fn verify_objective_policy_binding(
    document: &str,
    retained_policy: &Path,
    policy: &SurveillancePolicy,
) -> Result<(), String> {
    let reparsed_policy = SurveillancePolicy::load(retained_policy)?;
    if file_digest(retained_policy)?
        != file_digest(&current_governance_path("surveillance-policy.toml"))?
        || boolean_field(document, "requireSignedGovernanceAction")?
            != policy.require_signed_governance_action
        || boolean_field(document, "publicReportExposesCurrentState")?
            != policy.public_report_exposes_current_state
        || &reparsed_policy != policy
    {
        return Err("objective surveillance policy binding was substituted".to_owned());
    }
    Ok(())
}

fn evaluate_surveillance_events(
    policy: &SurveillancePolicy,
    events: &[(&str, bool)],
) -> Result<ObjectiveEvaluation, String> {
    if events.len() != SURVEILLANCE_EVENTS.len()
        || events
            .iter()
            .map(|(event, _)| *event)
            .collect::<BTreeSet<_>>()
            != SURVEILLANCE_EVENTS.iter().copied().collect()
    {
        return Err("objective surveillance event set is incomplete".to_owned());
    }
    Ok(ObjectiveEvaluation {
        passed: events
            .iter()
            .all(|(event, passed)| policy.event_passes(event, *passed)),
        automatic_revocation: events
            .iter()
            .any(|(event, passed)| policy.automatic_revocation(event, *passed)),
    })
}

fn custody_observation_passed(
    document: &str,
    candidate: &str,
    epoch: &str,
    maximum_age_days: u64,
) -> Result<bool, String> {
    Ok(quoted_field(document, "candidateCommit")? == candidate
        && quoted_field(document, "assuranceEpochSha256")? == epoch
        && quoted_field(document, "result")? == "pass"
        && boolean_field(document, "subjectKnown")?
        && quoted_field(document, "failureCode")? == "none"
        && crate::custody_ops::utc_age_days(&quoted_field(document, "observedAt")?)?
            <= maximum_age_days)
}

fn verify_mutation_report(path: &Path, candidate: &str, epoch: &str) -> Result<(), String> {
    crate::assurance::verify_surveillance_mutation_report(
        &component_path(["ci-out", "surveillance", "active-subject", "subject-policy"]),
        path,
        candidate,
        epoch,
    )
}

fn objective_component(
    document: &str,
    path_field: &str,
    digest_field: &str,
) -> Result<PathBuf, String> {
    let path = PathBuf::from(quoted_field(document, path_field)?);
    if path_text(&path)? != path.to_string_lossy() {
        return Err(format!("objective component {path_field} is not canonical"));
    }
    require_regular_file(&path)?;
    let expected = quoted_field(document, digest_field)?;
    require_digest(&expected, digest_field)?;
    if file_digest(&path)? != expected {
        return Err(format!("objective component {path_field} digest mismatch"));
    }
    Ok(path)
}

fn read_component(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| {
        format!(
            "cannot read objective component {}: {error}",
            path.display()
        )
    })
}

fn validate_revocations(document: &str) -> Result<bool, String> {
    let mut values = crate::strict_toml::assignments(document)?;
    if crate::strict_toml::unsigned(&crate::strict_toml::take(&mut values, "schema_version")?)? != 1
        || crate::strict_toml::string(&crate::strict_toml::take(&mut values, "state")?)? != "active"
    {
        return Err("review revocation record schema or state is invalid".to_owned());
    }
    let revoked = crate::strict_toml::string_array(&crate::strict_toml::take(
        &mut values,
        "revoked_review_ids",
    )?)?;
    crate::strict_toml::finish(&values)?;
    Ok(revoked.is_empty())
}

fn verify_current_governance_revocations(revocations: &Path) -> Result<bool, String> {
    let record_path = component_path(["ci-out", "surveillance", "current-governance-source.json"]);
    let record = read_text(&record_path)?;
    let commit = quoted_field(&record, "providerCommit")?;
    let repository_id = quoted_field(&record, "repositoryId")?;
    let expected_commit = std::env::var("GITHUB_SHA")
        .map_err(|_| "current governance verification lacks GITHUB_SHA".to_owned())?;
    let expected_repository_id = std::env::var("GITHUB_REPOSITORY_ID")
        .map_err(|_| "current governance verification lacks GITHUB_REPOSITORY_ID".to_owned())?;
    let expected_path = component_path([
        "ci-out",
        "surveillance",
        "current-governance-source",
        "compat",
        "review-revocations.toml",
    ]);
    let revocations_sha256 = file_digest(revocations)?;
    let canonical = format!(
        "{{\n  \"schemaVersion\": 1,\n  \"repositoryId\": \"{repository_id}\",\n  \"providerCommit\": \"{commit}\",\n  \"revocationsPath\": \"ci-out/surveillance/current-governance-source/compat/review-revocations.toml\",\n  \"revocationsSha256\": \"{revocations_sha256}\",\n  \"state\": \"exact-current-provider-source\"\n}}\n"
    );
    if commit != expected_commit
        || repository_id != expected_repository_id
        || record != canonical
        || revocations != expected_path
        || quoted_field(&record, "revocationsPath")? != path_text(&expected_path)?
        || quoted_field(&record, "revocationsSha256")? != revocations_sha256
        || quoted_field(&record, "state")? != "exact-current-provider-source"
    {
        return Ok(false);
    }
    let token = workflow_github_token("current governance reverification")?;
    let queried_root = component_path([
        "ci-out",
        "surveillance",
        "current-governance-reverification",
    ]);
    let queried = provider_source_file(
        &token,
        &commit,
        &["compat", "review-revocations.toml"],
        &queried_root,
    )?;
    Ok(
        fs::read(queried).map_err(|error| format!("cannot read requeried revocations: {error}"))?
            == fs::read(revocations)
                .map_err(|error| format!("cannot read retained current revocations: {error}"))?,
    )
}

fn validate_divergences(document: &str) -> Result<bool, String> {
    let values = crate::strict_toml::assignments(document)?;
    let schema = values
        .get("schema_version")
        .ok_or_else(|| "divergence catalog lacks schema_version".to_owned())?;
    let state = values
        .get("state")
        .ok_or_else(|| "divergence catalog lacks state".to_owned())?;
    if crate::strict_toml::unsigned(schema)? != 2 {
        return Err("divergence catalog schema is invalid".to_owned());
    }
    Ok(crate::strict_toml::string(state)? == "none-accepted")
}

fn required_canonical_state(document: &str) -> Result<&str, String> {
    let state = if document.contains("\"state\": \"promoted\"") {
        "promoted"
    } else if document.contains("\"state\": \"at-risk\"")
        || document.contains("\"derivedState\": \"at-risk\"")
    {
        "at-risk"
    } else if document.contains("\"state\": \"revoked\"")
        || document.contains("\"derivedState\": \"revoked\"")
    {
        "revoked"
    } else {
        return Err("prior promotion record has no supported canonical state".to_owned());
    };
    Ok(state)
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), String> {
    let mut pending = vec![(source.to_path_buf(), destination.to_path_buf())];
    while let Some((current, target)) = pending.pop() {
        fs::create_dir_all(&target)
            .map_err(|error| format!("cannot create {}: {error}", target.display()))?;
        let mut entries = fs::read_dir(&current)
            .map_err(|error| format!("cannot read {}: {error}", current.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot list {}: {error}", current.display()))?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let file_type = entry
                .file_type()
                .map_err(|error| format!("cannot inspect {}: {error}", entry.path().display()))?;
            let next = target.join(entry.file_name());
            if file_type.is_dir() {
                pending.push((entry.path(), next));
            } else if file_type.is_file() {
                copy_file(&entry.path(), &next)?;
            } else {
                return Err(format!(
                    "promotion record rejects special file {}",
                    entry.path().display()
                ));
            }
        }
    }
    Ok(())
}

fn copy_file(source: &Path, destination: &Path) -> Result<(), String> {
    require_regular_file(source)?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    fs::copy(source, destination).map_err(|error| {
        format!(
            "cannot copy {} to {}: {error}",
            source.display(),
            destination.display()
        )
    })?;
    Ok(())
}

fn require_digest_sibling(path: &Path) -> Result<(), String> {
    let digest = file_digest(path)?;
    let sibling = path.with_extension("sha256");
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| "digested record name is not UTF-8".to_owned())?;
    let expected = format!("{digest}  {name}\n");
    let observed = fs::read_to_string(&sibling)
        .map_err(|error| format!("cannot read digest sibling {}: {error}", sibling.display()))?;
    if observed != expected {
        return Err(format!("digest sibling {} is stale", sibling.display()));
    }
    Ok(())
}

fn require_regular_file(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    Ok(())
}

fn file_digest(path: &Path) -> Result<String, String> {
    sha256_file(path)
        .map_err(|error| format!("cannot hash {}: {error}", path.display()))
        .map(hell_testkit::Digest::hex)
}

fn required_path<'a>(value: Option<&'a PathBuf>, flag: &str) -> Result<&'a Path, String> {
    value
        .map(PathBuf::as_path)
        .ok_or_else(|| format!("surveillance-ops requires {flag}"))
}

fn required_text<'a>(value: Option<&'a String>, flag: &str) -> Result<&'a str, String> {
    value
        .map(String::as_str)
        .ok_or_else(|| format!("surveillance-ops requires {flag}"))
}

fn set_path(target: &mut Option<PathBuf>, value: &OsString, flag: &str) -> Result<(), String> {
    if target.replace(PathBuf::from(value)).is_some() {
        return Err(format!("duplicate {flag}"));
    }
    Ok(())
}

fn set_text(target: &mut Option<String>, value: &OsString, flag: &str) -> Result<(), String> {
    let text = value
        .to_str()
        .ok_or_else(|| format!("{flag} must be UTF-8"))?;
    if target.replace(text.to_owned()).is_some() {
        return Err(format!("duplicate {flag}"));
    }
    Ok(())
}

fn require_git_sha(value: &str, label: &str) -> Result<(), String> {
    crate::promotion_policy::require_git_sha(value, label)
}

fn require_digest(value: &str, label: &str) -> Result<(), String> {
    crate::promotion_policy::require_digest(value, label)
}

fn require_atom(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!("{label} is not a typed atom"));
    }
    Ok(())
}

fn path_text(path: &Path) -> Result<String, String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(
                part.to_str()
                    .ok_or_else(|| "path is not UTF-8".to_owned())?,
            ),
            Component::CurDir => {}
            _ => return Err("path must be normalized and relative".to_owned()),
        }
    }
    if parts.is_empty() {
        return Err("path is empty".to_owned());
    }
    Ok(parts.join("/"))
}

fn quoted_field(document: &str, field: &str) -> Result<String, String> {
    let marker = format!("\"{field}\": \"");
    let start = document
        .find(&marker)
        .ok_or_else(|| format!("missing string field {field}"))?
        + marker.len();
    let remainder = &document[start..];
    let end = remainder
        .find('"')
        .ok_or_else(|| format!("unterminated string field {field}"))?;
    let value = &remainder[..end];
    if value.contains('\\') || document[start + end + 1..].contains(&marker) {
        return Err(format!("field {field} is escaped or duplicated"));
    }
    Ok(value.to_owned())
}

fn boolean_field(document: &str, field: &str) -> Result<bool, String> {
    let true_marker = format!("\"{field}\": true");
    let false_marker = format!("\"{field}\": false");
    let found_true = document.match_indices(&true_marker).count();
    let found_false = document.match_indices(&false_marker).count();
    match (found_true, found_false) {
        (1, 0) => Ok(true),
        (0, 1) => Ok(false),
        _ => Err(format!("boolean field {field} is missing or duplicated")),
    }
}

fn unsigned_field(document: &str, field: &str) -> Result<u64, String> {
    let marker = format!("\"{field}\": ");
    let start = document
        .find(&marker)
        .ok_or_else(|| format!("missing unsigned field {field}"))?
        + marker.len();
    let digits = document[start..]
        .bytes()
        .take_while(u8::is_ascii_digit)
        .collect::<Vec<_>>();
    if digits.is_empty() || document[start + digits.len()..].contains(&marker) {
        return Err(format!("unsigned field {field} is invalid or duplicated"));
    }
    std::str::from_utf8(&digits)
        .map_err(|_| format!("unsigned field {field} is not UTF-8"))?
        .parse()
        .map_err(|_| format!("unsigned field {field} is out of range"))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    let mut temporary = path.as_os_str().to_os_string();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    fs::write(&temporary, bytes)
        .map_err(|error| format!("cannot write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("cannot install {}: {error}", path.display()))
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
            character if character <= '\u{1f}' => {
                write!(output, "\\u{:04x}", u32::from(character))
                    .expect("writing to String cannot fail");
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn committed_surveillance_policy() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("compat")
            .join("surveillance-policy.toml")
    }

    #[test]
    fn surveillance_policy_is_exact_and_every_toggle_changes_semantics() {
        let path = committed_surveillance_policy();
        let policy = SurveillancePolicy::load(&path).unwrap();
        assert_eq!(policy.deadline_days(), 7);
        assert_eq!(policy.divergence_warning_windows(), [30, 14, 7]);
        assert!(!policy.event_passes("promoted_claim_regression", false));
        assert!(!policy.automatic_revocation("promoted_claim_regression", false));
        assert!(policy.require_signed_governance_action);
        assert!(policy.public_report_exposes_current_state);

        let directory =
            std::env::temp_dir().join(format!("hell-surveillance-policy-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let source = fs::read_to_string(path).unwrap();
        let relaxed_path = directory.join("relaxed.toml");
        fs::write(
            &relaxed_path,
            source.replace(
                "promoted_claim_regression = true",
                "promoted_claim_regression = false",
            ),
        )
        .unwrap();
        let relaxed = SurveillancePolicy::load(&relaxed_path).unwrap();
        assert!(relaxed.event_passes("promoted_claim_regression", false));

        let unknown_path = directory.join("unknown.toml");
        fs::write(&unknown_path, format!("{source}\nunknown = true\n")).unwrap();
        assert!(SurveillancePolicy::load(&unknown_path).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    fn native_selection_document() -> String {
        let head = "cccccccccccccccccccccccccccccccccccccccc";
        format!(
            "{{\n  \"schemaVersion\": 1,\n  \"candidateCommit\": \"{GIT}\",\n  \"assuranceEpochSha256\": \"{SHA}\",\n  \"workflowPath\": \".github/workflows/oracle-reproduce.yml\",\n  \"event\": \"workflow_dispatch\",\n  \"headSha\": \"{head}\",\n  \"updatedAt\": \"2026-08-09T12:00:00Z\",\n  \"macosArtifactName\": \"ephemeralEvidence-oracle-reviewed-macos-arm64\",\n  \"macosDownloadedArchiveSha256\": \"{SHA}\",\n  \"macosExtractedTreeSha256\": \"{SHA}\",\n  \"macosProviderSelectionSha256\": \"{SHA}\",\n  \"macosProvenancePath\": \"ci-out/surveillance/current-native-provenance/1/1/macos-arm64/ci-out/oracle-provenance.json\",\n  \"macosProvenanceSha256\": \"{SHA}\",\n  \"windowsArtifactName\": \"ephemeralEvidence-oracle-reviewed-windows-amd64\",\n  \"windowsDownloadedArchiveSha256\": \"{SHA}\",\n  \"windowsExtractedTreeSha256\": \"{SHA}\",\n  \"windowsProviderSelectionSha256\": \"{SHA}\",\n  \"windowsProvenancePath\": \"ci-out/surveillance/current-native-provenance/1/1/windows-amd64/ci-out/oracle-provenance.json\",\n  \"windowsProvenanceSha256\": \"{SHA}\",\n  \"runId\": 1,\n  \"runAttempt\": 1,\n  \"macosArtifactId\": 2,\n  \"windowsArtifactId\": 3\n}}\n"
        )
    }

    #[test]
    fn native_selection_schema_and_portable_paths_are_exact() {
        let document = native_selection_document();
        assert_eq!(
            canonical_native_provenance_selection(&document).unwrap(),
            document
        );
        assert!(
            canonical_native_provenance_selection(
                &document.replace("\n}\n", ",\n  \"unknown\": true\n}\n")
            )
            .is_ok_and(
                |canonical| canonical != document.replace("\n}\n", ",\n  \"unknown\": true\n}\n")
            )
        );
        assert!(portable_relative_path("ci-out/../escape").is_err());
        assert!(portable_relative_path("ci-out\\escape").is_err());
        assert_eq!(
            native_provider_ref_argument(GIT).unwrap(),
            OsString::from(format!("ref={GIT}"))
        );
        assert!(native_provider_ref_argument("main").is_err());
    }
    const GIT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn transition(result: &str, derived: &str, incident: bool) -> String {
        transition_json(&TransitionFields {
            candidate: GIT,
            epoch: SHA,
            proposal: SHA,
            approval: SHA,
            gate: SHA,
            report: SHA,
            custody: SHA,
            policy: SHA,
            check_kind: "weekly-composite",
            observed_at: "2026-08-09T12:00:00Z",
            objective_path: "ci-out/surveillance/objective-checks.json".to_owned(),
            objective: SHA,
            result,
            prior_state: "promoted",
            derived_state: derived,
            incident_required: incident,
            supersedes: SHA,
        })
    }

    #[test]
    fn forged_pass_cannot_retain_promoted_state() {
        let path = std::env::temp_dir().join(format!(
            "hell-surveillance-forged-pass-{}.json",
            std::process::id()
        ));
        fs::write(&path, transition("fail", "promoted", true)).unwrap();
        assert!(verify_transition(&path).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn failed_check_is_at_risk_and_requires_incident() {
        let path = std::env::temp_dir().join(format!(
            "hell-surveillance-failed-check-{}.json",
            std::process::id()
        ));
        fs::write(&path, transition("fail", "at-risk", true)).unwrap();
        assert!(verify_transition(&path).is_ok());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn objective_binding_rejects_stale_epoch_and_missing_checks() {
        let policy = SurveillancePolicy::load(&committed_surveillance_policy()).unwrap();
        let forged = format!(
            "{{\"candidateCommit\": \"{GIT}\", \"assuranceEpochSha256\": \"{SHA}\", \"checkKind\": \"weekly-composite\", \"observedAt\": \"2026-08-09T12:00:00Z\", \"repositoryAssurancePassed\": true}}"
        );
        assert!(
            !objective_evaluation(&forged, GIT, SHA, "weekly-composite", &policy)
                .unwrap()
                .passed
        );
        assert!(
            objective_evaluation(
                &forged,
                GIT,
                &"c".repeat(SHA.len()),
                "weekly-composite",
                &policy,
            )
            .is_err()
        );
    }

    #[test]
    fn missing_prior_state_fails_closed() {
        assert!(required_canonical_state("{\"state\":\"pending-durable-custody\"}").is_err());
        assert_eq!(
            required_canonical_state("{\"state\": \"revoked\"}").unwrap(),
            "revoked"
        );
    }

    fn current_transition(state: &str, digest: &str) -> VerifiedCurrentTransition {
        VerifiedCurrentTransition {
            path: PathBuf::from("promotion-transition.json"),
            record_sha256: digest.to_owned(),
            packet_sha256: SHA.to_owned(),
            dsse_sha256: SHA.to_owned(),
            derived_state: state.to_owned(),
            observed_at: "2026-08-09T12:00:00Z".to_owned(),
            supersedes_sha256: SHA.to_owned(),
        }
    }

    #[test]
    fn current_transition_requires_dual_provider_exact_agreement() {
        assert!(
            require_agreed_current_transition(None, None)
                .unwrap()
                .is_none()
        );
        let first = current_transition("at-risk", SHA);
        let same = current_transition("at-risk", SHA);
        assert_eq!(
            require_agreed_current_transition(Some(&first), Some(&same))
                .unwrap()
                .unwrap()
                .derived_state,
            "at-risk"
        );
        assert!(require_agreed_current_transition(Some(&first), None).is_err());
        let substituted_state = current_transition("revoked", SHA);
        assert!(require_agreed_current_transition(Some(&first), Some(&substituted_state)).is_err());
        let substituted_record = current_transition("at-risk", &"b".repeat(SHA.len()));
        assert!(
            require_agreed_current_transition(Some(&first), Some(&substituted_record)).is_err()
        );
    }

    #[test]
    fn emergency_transition_is_explicitly_observer_scoped_and_at_risk() {
        let path = std::env::temp_dir().join(format!(
            "hell-surveillance-emergency-{}.json",
            std::process::id()
        ));
        let record = format!(
            "{{\n  \"schemaVersion\": 2,\n  \"subjectState\": \"observer-source-only\",\n  \"candidateCommit\": \"{GIT}\",\n  \"assuranceEpochSha256\": \"{SHA}\",\n  \"primaryObservationSha256\": \"{SHA}\",\n  \"secondaryObservationSha256\": \"{SHA}\",\n  \"surveillancePolicySha256\": \"{SHA}\",\n  \"checkKind\": \"weekly-composite\",\n  \"observedAt\": \"2026-08-09T12:00:00Z\",\n  \"result\": \"fail\",\n  \"priorState\": \"unknown\",\n  \"derivedState\": \"at-risk\",\n  \"failureSha256\": \"{SHA}\",\n  \"supersedesSha256\": \"{SHA}\",\n  \"incidentRequired\": true\n}}\n"
        );
        fs::write(&path, record).unwrap();
        assert!(verify_transition(&path).is_ok());
        assert!(require_promoted(&path).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn scheduled_workflow_retains_and_alerts_on_fail_closed_observations() {
        let workflow = include_str!("../../../.github/workflows/promotion-surveillance.yml");
        for required in [
            "custody-ops workflow-surveillance-retrieve",
            "custody-ops workflow-surveillance-retrieval-packet-primary",
            "custody-ops workflow-surveillance-retrieval-packet-secondary",
            "provider-observation.dsse.json",
            "verify-and-transition:\n    if: ${{ always() && github.ref == 'refs/heads/main' }}",
            "Derive objective component-bound surveillance result\n        if: ${{ always() }}",
            "Derive exact regression impact from retained mismatch evidence\n        if: ${{ always() }}",
            "run: ./target/ci/hell-ci surveillance-ops workflow-impact",
            "Derive fail-closed promotion state transition\n        if: ${{ always() }}",
            "incident-alert:",
            "issues: write",
            "Upsert promotion surveillance incident",
            "GITHUB_TOKEN: ${{ github.token }}",
            "run: ./target/ci/hell-ci surveillance-ops workflow-alert",
            "Retain signed active Linux oracle bytes for subject execution",
            "Retain signed active Linux oracle acquisition attestation",
            "nightly-surveillance-subject --oracle ci-out/linux-release-oracle",
            "mutation run-surveillance --output ci-out/mutation/mutation-score.pending.json",
        ] {
            assert!(
                workflow.contains(required),
                "surveillance workflow lacks {required}"
            );
        }
        assert!(!workflow.contains("custody-ops workflow-scrub\n"));
        assert!(!workflow.contains("custody-maintenance-receipt.dsse.json"));
        assert!(!workflow.contains("script: |"));
        assert!(!workflow.contains("actions/github-script@"));
        assert!(!workflow.contains("curl --fail --location"));
        assert!(!workflow.contains("--role mutation-reviewer"));
        assert!(!workflow.contains("SURVEILLANCE_MUTATION_SSH_PRIVATE_KEY"));
        let acquire = workflow
            .find("Retain signed active Linux oracle bytes for subject execution")
            .unwrap();
        let attest = workflow
            .find("Retain signed active Linux oracle acquisition attestation")
            .unwrap();
        let nightly = workflow
            .find("nightly-surveillance-subject --oracle ci-out/linux-release-oracle")
            .unwrap();
        assert!(acquire < attest && attest < nightly);
        let build = workflow.find("Build surveillance driver").unwrap();
        let credentials = workflow
            .find("Configure protected read-only provider identity")
            .unwrap();
        assert!(build < credentials);
        assert!(workflow[credentials..].contains("continue-on-error: true"));
        assert!(workflow.contains(
            "Retrieve exact active immutable package or retain typed failure\n        if: ${{ always() }}"
        ));
        assert!(!workflow.contains("custody-provider:promotion-surveillance\""));
    }

    #[test]
    fn custody_observation_signers_must_have_distinct_subjects_and_keys() {
        let first = (
            "provider-primary".to_owned(),
            "fingerprint-primary".to_owned(),
        );
        let second = (
            "provider-secondary".to_owned(),
            "fingerprint-secondary".to_owned(),
        );
        assert!(require_distinct_provider_signers(&first, &second).is_ok());
        assert!(require_distinct_provider_signers(&first, &first).is_err());
        assert!(
            require_distinct_provider_signers(
                &first,
                &("provider-secondary".to_owned(), first.1.clone())
            )
            .is_err()
        );
    }

    #[test]
    fn watchdog_run_parser_is_typed_and_workflow_retains_signed_at_risk_evidence() {
        let run = parse_watchdog_run("123\t2\t2026-08-01T00:00:00Z\t2026-08-01T01:00:00Z\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\t.github/workflows/promotion-surveillance.yml\tschedule\tcompleted\tsuccess").unwrap();
        assert_eq!(run.run_id, 123);
        assert_eq!(run.run_attempt, 2);
        assert!(parse_watchdog_run("0\t2\t2026-08-01T00:00:00Z\t2026-08-01T01:00:00Z\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\t.github/workflows/promotion-surveillance.yml\tschedule\tcompleted\tsuccess").is_err());
        assert!(parse_watchdog_run("123\t2\tnot-a-time\t2026-08-01T01:00:00Z\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\t.github/workflows/promotion-surveillance.yml\tschedule\tcompleted\tsuccess").is_err());
        assert!(parse_watchdog_run("123\t2\t2026-08-01T00:00:00Z\t2026-08-01T01:00:00Z\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\t.github/workflows/other.yml\tschedule\tcompleted\tsuccess").is_err());
        assert!(!deadline_reached(604_799, 604_800));
        assert!(deadline_reached(604_800, 604_800));
        assert!(watchdog_head_matches(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ));
        assert!(!watchdog_head_matches(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "cccccccccccccccccccccccccccccccccccccccc"
        ));
        let artifact = parse_watchdog_artifact("55\tpromotion-surveillance-123-2\tsha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\tfalse\t2026-08-01T01:00:00Z\t2026-08-31T01:00:00Z").unwrap();
        assert_eq!(artifact.artifact_id, 55);
        assert!(parse_watchdog_artifact("55\twrong\tsha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\ttrue\t2026-08-01T01:00:00Z\t2026-08-31T01:00:00Z").is_err());
        let workflow =
            include_str!("../../../.github/workflows/promotion-surveillance-watchdog.yml");
        for required in [
            "schedule:",
            "actions: read",
            "surveillance-ops workflow-deadline",
            "Sign missed-deadline at-risk transition",
            "promotion-transition.dsse.json",
            "Upsert missed surveillance deadline incident",
            "surveillance-ops workflow-alert",
            "Publish exact signed watchdog state immutably",
            "artifact-ids: ${{ needs.deadline.outputs.transition_artifact_id }}",
        ] {
            assert!(workflow.contains(required), "watchdog lacks {required}");
        }
        assert!(!workflow.contains("script: |"));
    }

    #[test]
    fn push_surveillance_requires_exact_main_workflow_and_checkout_head() {
        let head = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let workflow =
            "Portfoligno/hell-rs/.github/workflows/promotion-surveillance.yml@refs/heads/main";
        assert!(trusted_push_surveillance_trigger(
            "refs/heads/main",
            workflow,
            head,
            head,
        ));
        assert!(!trusted_push_surveillance_trigger(
            "refs/heads/feature",
            workflow,
            head,
            head,
        ));
        assert!(!trusted_push_surveillance_trigger(
            "refs/heads/main",
            workflow,
            head,
            "cccccccccccccccccccccccccccccccccccccccc",
        ));
        assert!(!trusted_push_surveillance_trigger(
            "refs/heads/main",
            "Portfoligno/hell-rs/.github/workflows/promotion-surveillance.yml@refs/tags/main",
            head,
            head,
        ));
    }
}
