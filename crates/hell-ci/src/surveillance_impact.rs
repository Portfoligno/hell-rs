use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use hell_testkit::{Digest, sha256_bytes, sha256_file, verify_observation_bundle};

const OUTPUT: &str = "ci-out/surveillance/regression-impact.json";

fn component_path<const N: usize>(components: [&str; N]) -> PathBuf {
    components.iter().collect()
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ClaimCell {
    builtin: String,
    dimension: String,
    platform: String,
    status: String,
    reference: String,
}

struct MismatchImpact {
    case_id: String,
    bundle_path: String,
    bundle_sha256: Digest,
    cells: BTreeSet<ClaimCell>,
    raw_observation_sha256: String,
    normalized_observation_sha256: String,
    disposition: ImpactDisposition,
    divergence_id: Option<String>,
    divergence_review: Option<String>,
    review_groups: BTreeSet<String>,
    public_statements: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ImpactDisposition {
    ApprovedUnchanged,
    NewOrChanged,
    Expired,
}

struct ApprovedDivergence {
    divergence_id: String,
    builtin: String,
    dimension: String,
    platform: String,
    profile: String,
    fingerprint: String,
    expires_at: String,
    review_ref: String,
    issue_number: u64,
}

struct DivergenceWarning {
    divergence_id: String,
    issue_number: u64,
    expires_at: String,
    days_remaining: u64,
    warning_window_days: u64,
    state: &'static str,
}

pub(crate) fn workflow_impact() -> Result<String, String> {
    let epoch_path = component_path(["ci-out", "assurance-epoch.json"]);
    let (candidate, epoch) = crate::assurance::retained_epoch_digest(&epoch_path)?;
    let observed_at = crate::custody_ops::current_utc_timestamp()?;
    let nightly = component_path(["ci-out", "surveillance", "nightly.json"]);
    let nightly_text = fs::read_to_string(&nightly).ok();
    let nightly_sha256 = file_digest_or_absent(&nightly)?;
    let claim_indexes = named_files(
        &component_path(["ci-out", "active-promotion-record"]),
        "claim-index.json",
    )?;
    let policy_path = component_path(["compat", "surveillance-policy.toml"]);
    let policy = crate::surveillance_ops::SurveillancePolicy::load(&policy_path)?;
    let automatic_critical_events = policy.automatic_critical_events();
    let claims = claim_cells(&claim_indexes)?;
    let public_mappings = verified_claim_public_mappings(
        &component_path(["ci-out", "active-promotion-record"]),
        &component_path(["ci-out", "active-promotion-record"]),
        &candidate,
        &epoch,
    )?;
    let divergences = approved_divergences(
        &component_path(["ci-out", "active-promotion-record"]),
        &candidate,
        &epoch,
    )?;
    let warnings = divergence_warnings(
        &divergences,
        &observed_at,
        policy.divergence_warning_windows(),
    )?;
    let impacts = mismatch_impacts(
        &component_path(["ci-out", "surveillance", "mismatches"]),
        &claims,
        &divergences,
        &public_mappings,
        &observed_at,
    )?;
    let source_passed = nightly_text
        .as_deref()
        .and_then(|document| json_boolean(document, "passed").ok())
        .unwrap_or(false);
    let actionable = impacts
        .iter()
        .filter(|impact| impact.disposition != ImpactDisposition::ApprovedUnchanged)
        .count();
    let state = derive_impact_state(
        source_passed,
        actionable,
        !claim_indexes.is_empty(),
        &warnings,
        automatic_critical_events,
    );
    let output = impact_json(&ImpactReport {
        candidate: &candidate,
        epoch: &epoch,
        observed_at: &observed_at,
        nightly_path: "ci-out/surveillance/nightly.json",
        nightly_sha256: &nightly_sha256,
        nightly_present: nightly_text.is_some(),
        source_passed,
        policy_path: "compat/surveillance-policy.toml",
        policy_sha256: &file_digest(&policy_path)?,
        claim_indexes: &claim_indexes,
        impacts: &impacts,
        warnings: &warnings,
        state,
    })?;
    write_atomic(Path::new(OUTPUT), output.as_bytes())?;
    write_atomic(
        &component_path(["ci-out", "surveillance", "divergence-expiry-warnings.json"]),
        divergence_warning_json(
            &candidate,
            &epoch,
            &observed_at,
            &file_digest(&policy_path)?,
            &warnings,
        )
        .as_bytes(),
    )?;
    Ok(format!(
        "derived regression impact for {} mismatch bundles with result {}",
        impacts.len(),
        state.result()
    ))
}

pub(crate) fn workflow_divergence_issues() -> Result<String, String> {
    const REPOSITORY: &str = "Portfoligno/hell-rs";
    let repository = std::env::var("GITHUB_REPOSITORY")
        .map_err(|_| "divergence issue sync lacks GITHUB_REPOSITORY".to_owned())?;
    let server = std::env::var("GITHUB_SERVER_URL")
        .map_err(|_| "divergence issue sync lacks GITHUB_SERVER_URL".to_owned())?;
    let token = std::env::var("GITHUB_TOKEN")
        .map_err(|_| "divergence issue sync lacks GITHUB_TOKEN".to_owned())?;
    if repository != REPOSITORY
        || server != "https://github.com"
        || token.is_empty()
        || token.chars().any(char::is_control)
    {
        return Err("divergence issue sync identity or token is invalid".to_owned());
    }
    let (candidate, epoch) = crate::assurance::retained_epoch_digest(&component_path([
        "ci-out",
        "assurance-epoch.json",
    ]))?;
    let active = component_path(["ci-out", "active-promotion-record"]);
    let divergences = approved_divergences(&active, &candidate, &epoch)?;
    let impact_path = component_path(["ci-out", "surveillance", "regression-impact.json"]);
    let warnings_path =
        component_path(["ci-out", "surveillance", "divergence-expiry-warnings.json"]);
    let impact_sha256 = file_digest(&impact_path)?;
    let warnings_sha256 = file_digest(&warnings_path)?;
    let warning_text = fs::read_to_string(&warnings_path)
        .map_err(|error| format!("cannot read divergence warning set: {error}"))?;
    let policy_path = component_path(["compat", "surveillance-policy.toml"]);
    let policy = crate::surveillance_ops::SurveillancePolicy::load(&policy_path)?;
    let observed_at = quoted_field(&warning_text, "observedAt")?;
    let warnings = divergence_warnings(
        &divergences,
        &observed_at,
        policy.divergence_warning_windows(),
    )?;
    if divergence_warning_json(
        &candidate,
        &epoch,
        &observed_at,
        &file_digest(&policy_path)?,
        &warnings,
    ) != warning_text
    {
        return Err("retained divergence warning set does not replay exactly".to_owned());
    }
    let run_id = std::env::var("GITHUB_RUN_ID")
        .map_err(|_| "divergence issue sync lacks GITHUB_RUN_ID".to_owned())?;
    require_nonzero_text(&run_id, "divergence issue sync run ID")?;
    let mut by_issue = BTreeMap::<u64, Vec<&ApprovedDivergence>>::new();
    for divergence in &divergences {
        by_issue
            .entry(divergence.issue_number)
            .or_default()
            .push(divergence);
    }
    let mut warnings_by_issue = BTreeMap::<u64, Vec<&DivergenceWarning>>::new();
    for warning in &warnings {
        warnings_by_issue
            .entry(warning.issue_number)
            .or_default()
            .push(warning);
    }
    let output_root = component_path(["ci-out", "surveillance", "divergence-issue-comments"]);
    let mut records = Vec::new();
    for (issue_number, issue_divergences) in by_issue {
        let issue_warnings = warnings_by_issue.remove(&issue_number).unwrap_or_default();
        records.push(sync_divergence_issue(&DivergenceIssueSync {
            token: &token,
            repository: REPOSITORY,
            server: &server,
            run_id: &run_id,
            candidate: &candidate,
            epoch: &epoch,
            issue_number,
            divergences: &issue_divergences,
            warnings: &issue_warnings,
            impact_sha256: &impact_sha256,
            warnings_sha256: &warnings_sha256,
            output_root: &output_root,
        })?);
    }
    write_atomic(
        &output_root.join("manifest.json"),
        divergence_issue_manifest(&candidate, &epoch, &records).as_bytes(),
    )?;
    Ok(format!(
        "synchronized {} linked divergence issue summaries",
        records.len()
    ))
}

struct DivergenceIssueSync<'a> {
    token: &'a str,
    repository: &'a str,
    server: &'a str,
    run_id: &'a str,
    candidate: &'a str,
    epoch: &'a str,
    issue_number: u64,
    divergences: &'a [&'a ApprovedDivergence],
    warnings: &'a [&'a DivergenceWarning],
    impact_sha256: &'a str,
    warnings_sha256: &'a str,
    output_root: &'a Path,
}

struct DivergenceIssueSyncRecord {
    issue_number: u64,
    state_response_sha256: String,
    body_sha256: String,
    comment_response_sha256: String,
}

fn sync_divergence_issue(
    sync: &DivergenceIssueSync<'_>,
) -> Result<DivergenceIssueSyncRecord, String> {
    let issue = sync.issue_number.to_string();
    let state = crate::surveillance_ops::github_request(
        sync.token,
        &[
            OsString::from("issue"),
            OsString::from("view"),
            OsString::from(&issue),
            OsString::from("--repo"),
            OsString::from(sync.repository),
            OsString::from("--json"),
            OsString::from("number,state,url,updatedAt"),
            OsString::from("--jq"),
            OsString::from("[.number,.state,.url,.updatedAt] | @tsv"),
        ],
    )?;
    let state = String::from_utf8(state.stdout)
        .map_err(|_| "divergence issue state response is not UTF-8".to_owned())?;
    verify_linked_issue_state(sync.issue_number, &state)?;
    let state_path = sync.output_root.join(&issue).with_extension("state.tsv");
    write_atomic(&state_path, state.as_bytes())?;
    let body_path = sync.output_root.join(&issue).with_extension("md");
    let (body_sha256, comment_response_sha256) = if sync.warnings.is_empty() {
        (empty_digest(), empty_digest())
    } else {
        let body = divergence_issue_body(sync);
        write_atomic(&body_path, body.as_bytes())?;
        let response = crate::surveillance_ops::github_request(
            sync.token,
            &[
                OsString::from("issue"),
                OsString::from("comment"),
                OsString::from(&issue),
                OsString::from("--repo"),
                OsString::from(sync.repository),
                OsString::from("--body-file"),
                body_path.as_os_str().to_owned(),
                OsString::from("--edit-last"),
                OsString::from("--create-if-none"),
            ],
        )?;
        let response_path = sync.output_root.join(&issue).with_extension("response.txt");
        write_atomic(&response_path, &response.stdout)?;
        (file_digest(&body_path)?, file_digest(&response_path)?)
    };
    Ok(DivergenceIssueSyncRecord {
        issue_number: sync.issue_number,
        state_response_sha256: file_digest(&state_path)?,
        body_sha256,
        comment_response_sha256,
    })
}

fn empty_digest() -> String {
    sha256_bytes(b"").hex()
}

fn verify_linked_issue_state(issue_number: u64, response: &str) -> Result<(), String> {
    let fields = response.trim().split('\t').collect::<Vec<_>>();
    if fields.len() != 4
        || fields[0] != issue_number.to_string()
        || fields[1] != "OPEN"
        || fields[2] != format!("https://github.com/Portfoligno/hell-rs/issues/{issue_number}")
    {
        return Err("linked divergence issue is not the exact current open issue".to_owned());
    }
    crate::custody_ops::validate_utc_timestamp(fields[3])
}

fn divergence_issue_body(sync: &DivergenceIssueSync<'_>) -> String {
    let mut body = format!(
        "<!-- hell-surveillance-divergence-issue:{} -->\nCurrent signed-evidence surveillance summary for candidate `{}` and assurance epoch `{}`.\n\nRun: {}/Portfoligno/hell-rs/actions/runs/{}\n\nRegression impact SHA-256: `{}`\nExpiry warning set SHA-256: `{}`\n",
        sync.issue_number,
        sync.candidate,
        sync.epoch,
        sync.server,
        sync.run_id,
        sync.impact_sha256,
        sync.warnings_sha256,
    );
    for divergence in sync.divergences {
        writeln!(
            body,
            "\n- Divergence `{}`: fingerprint `{}`, expires `{}`.",
            divergence.divergence_id, divergence.fingerprint, divergence.expires_at
        )
        .expect("writing to String cannot fail");
    }
    for warning in sync.warnings {
        writeln!(
            body,
            "- Expiry event for `{}`: state `{}`, {} days remaining, policy window {} days.",
            warning.divergence_id,
            warning.state,
            warning.days_remaining,
            warning.warning_window_days,
        )
        .expect("writing to String cannot fail");
    }
    body
}

fn divergence_issue_manifest(
    candidate: &str,
    epoch: &str,
    records: &[DivergenceIssueSyncRecord],
) -> String {
    let mut output = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in [
        ("candidateCommit", candidate),
        ("assuranceEpochSha256", epoch),
    ] {
        output.push_str(",\n  \"");
        output.push_str(field);
        output.push_str("\": ");
        push_json(&mut output, value);
    }
    output.push_str(",\n  \"records\": [");
    for (index, record) in records.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write!(
            output,
            "\n    {{\"issueNumber\": {}, \"stateResponseSha256\": ",
            record.issue_number
        )
        .expect("writing to String cannot fail");
        push_json(&mut output, &record.state_response_sha256);
        output.push_str(", \"bodySha256\": ");
        push_json(&mut output, &record.body_sha256);
        output.push_str(", \"commentResponseSha256\": ");
        push_json(&mut output, &record.comment_response_sha256);
        output.push('}');
    }
    output.push_str("\n  ]\n}\n");
    output
}

pub(crate) fn verify_divergence_issue_evidence(
    active: &Path,
    candidate: &str,
    epoch: &str,
    manifest_path: &Path,
    warnings_path: &Path,
    policy_path: &Path,
) -> Result<bool, String> {
    let divergences = approved_divergences(active, candidate, epoch)?;
    let warning_text = fs::read_to_string(warnings_path)
        .map_err(|error| format!("cannot read retained divergence warnings: {error}"))?;
    let observed_at = quoted_field(&warning_text, "observedAt")?;
    let policy = crate::surveillance_ops::SurveillancePolicy::load(policy_path)?;
    let warnings = divergence_warnings(
        &divergences,
        &observed_at,
        policy.divergence_warning_windows(),
    )?;
    if divergence_warning_json(
        candidate,
        epoch,
        &observed_at,
        &file_digest(policy_path)?,
        &warnings,
    ) != warning_text
    {
        return Err("objective divergence warning evidence does not replay".to_owned());
    }
    let warning_issues = warnings
        .iter()
        .map(|warning| warning.issue_number)
        .collect::<BTreeSet<_>>();
    let issue_numbers = divergences
        .iter()
        .map(|divergence| divergence.issue_number)
        .collect::<BTreeSet<_>>();
    let output_root = manifest_path
        .parent()
        .ok_or_else(|| "divergence issue manifest has no parent".to_owned())?;
    let mut records = Vec::new();
    for issue_number in issue_numbers {
        let issue = issue_number.to_string();
        let state_path = output_root.join(&issue).with_extension("state.tsv");
        let state = fs::read_to_string(&state_path)
            .map_err(|error| format!("cannot read retained divergence issue state: {error}"))?;
        verify_linked_issue_state(issue_number, &state)?;
        let body_path = output_root.join(&issue).with_extension("md");
        let response_path = output_root.join(&issue).with_extension("response.txt");
        let warned = warning_issues.contains(&issue_number);
        if body_path.is_file() != warned || response_path.is_file() != warned {
            return Err("divergence issue comment set differs from warning set".to_owned());
        }
        records.push(DivergenceIssueSyncRecord {
            issue_number,
            state_response_sha256: file_digest(&state_path)?,
            body_sha256: if warned {
                file_digest(&body_path)?
            } else {
                empty_digest()
            },
            comment_response_sha256: if warned {
                file_digest(&response_path)?
            } else {
                empty_digest()
            },
        });
    }
    let manifest = fs::read_to_string(manifest_path)
        .map_err(|error| format!("cannot read divergence issue manifest: {error}"))?;
    if divergence_issue_manifest(candidate, epoch, &records) != manifest {
        return Err(
            "divergence issue manifest does not exactly bind current issue states".to_owned(),
        );
    }
    Ok(true)
}

fn require_nonzero_text(value: &str, label: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| format!("{label} must be nonzero"))
}

fn approved_divergences(
    root: &Path,
    candidate: &str,
    epoch: &str,
) -> Result<Vec<ApprovedDivergence>, String> {
    let paths = named_files(root, "divergence-report.details.json")?;
    if paths.len() > 1 {
        return Err("active promotion contains multiple divergence reports".to_owned());
    }
    let Some(path) = paths.first() else {
        return Ok(Vec::new());
    };
    let document = fs::read_to_string(path)
        .map_err(|error| format!("cannot read active divergence report: {error}"))?;
    let mut divergences = Vec::new();
    for record in record_objects(&document)? {
        let divergence = ApprovedDivergence {
            divergence_id: quoted_field(record, "divergenceId")?,
            builtin: quoted_field(record, "builtin")?,
            dimension: quoted_field(record, "dimension")?,
            platform: quoted_field(record, "platform")?,
            profile: quoted_field(record, "profile")?,
            fingerprint: quoted_field(record, "fingerprint")?,
            expires_at: quoted_field(record, "expiresAt")?,
            review_ref: quoted_field(record, "reviewRef")?,
            issue_number: unsigned_field(record, "issueNumber")?,
        };
        crate::custody_ops::validate_utc_timestamp(&divergence.expires_at)?;
        require_digest(&divergence.fingerprint, "divergence fingerprint")?;
        require_digest(&divergence.review_ref, "divergence review")?;
        verify_divergence_review(root, path, &divergence.review_ref, candidate, epoch)?;
        divergences.push(divergence);
    }
    Ok(divergences)
}

fn divergence_warnings(
    divergences: &[ApprovedDivergence],
    observed_at: &str,
    windows: &[u64],
) -> Result<Vec<DivergenceWarning>, String> {
    let observed = crate::assurance::utc_timestamp_seconds(observed_at)?;
    let mut warnings = Vec::new();
    for divergence in divergences {
        let expiry = crate::assurance::utc_timestamp_seconds(&divergence.expires_at)?;
        let (days_remaining, warning_window_days, state) = if expiry <= observed {
            (0, 0, "expired")
        } else {
            let seconds = expiry.saturating_sub(observed);
            let days = seconds.div_ceil(86_400);
            let Some(window) = windows.iter().rev().copied().find(|window| days <= *window) else {
                continue;
            };
            (days, window, "warning")
        };
        warnings.push(DivergenceWarning {
            divergence_id: divergence.divergence_id.clone(),
            issue_number: divergence.issue_number,
            expires_at: divergence.expires_at.clone(),
            days_remaining,
            warning_window_days,
            state,
        });
    }
    warnings.sort_by(|left, right| {
        left.issue_number
            .cmp(&right.issue_number)
            .then_with(|| left.divergence_id.cmp(&right.divergence_id))
    });
    Ok(warnings)
}

fn verify_divergence_review(
    root: &Path,
    details: &Path,
    review_ref: &str,
    candidate: &str,
    epoch: &str,
) -> Result<(), String> {
    let reviews = named_files(root, "review.dsse.json")?
        .into_iter()
        .filter(|path| file_digest(path).is_ok_and(|digest| digest == review_ref))
        .collect::<Vec<_>>();
    if reviews.len() != 1 {
        return Err(
            "approved divergence reviewRef does not resolve to one retained envelope".to_owned(),
        );
    }
    let review = &reviews[0];
    let directory = review
        .parent()
        .ok_or_else(|| "divergence review has no authorization directory".to_owned())?;
    let authorization = directory.join("authorization.json");
    let policy = directory.join("reviewer.allowed_signers");
    let required = BTreeSet::from([file_digest(details)?, file_digest(&authorization)?]);
    crate::assurance::verify_review_binding(
        review,
        &policy,
        "divergence-reviewer",
        candidate,
        epoch,
        &required,
    )
    .map(|_| ())
    .map_err(|_| "approved divergence reviewRef is not an authorized exact review".to_owned())
}

pub(crate) struct VerifiedClaimPublicMapping {
    pub(crate) review_group_id: String,
    pub(crate) statement_id: String,
    pub(crate) mapping_sha256: String,
    pub(crate) packet_sha256: String,
    pub(crate) public_report_sha256: String,
}

pub(crate) fn verified_claim_public_mappings(
    mapping_root: &Path,
    public_root: &Path,
    candidate: &str,
    epoch: &str,
) -> Result<BTreeMap<String, VerifiedClaimPublicMapping>, String> {
    let maps = named_files(mapping_root, "claim-group-map.json")?;
    let subjects = named_files(mapping_root, "graph-review-subject.json")?;
    let packet_manifests = named_files(mapping_root, "packet.sha256")?;
    if maps.len() != 1 || subjects.len() != 1 || packet_manifests.len() != 1 {
        return Err("active promotion lacks one signed claim/public mapping packet".to_owned());
    }
    let map = &maps[0];
    let subject = fs::read_to_string(&subjects[0])
        .map_err(|error| format!("cannot read graph review subject: {error}"))?;
    let map_text = fs::read_to_string(map)
        .map_err(|error| format!("cannot read claim/public mapping: {error}"))?;
    if quoted_field(&map_text, "candidateSourceCommit")? != candidate
        || quoted_field(&map_text, "assuranceEpochSha256")? != epoch
        || quoted_field(&subject, "candidateSourceCommit")? != candidate
        || quoted_field(&subject, "assuranceEpochSha256")? != epoch
        || quoted_field(&subject, "packetSha256")? != file_digest(&packet_manifests[0])?
    {
        return Err("claim/public mapping packet identity is stale".to_owned());
    }
    let manifest = fs::read_to_string(&packet_manifests[0])
        .map_err(|error| format!("cannot read offline packet manifest: {error}"))?;
    let expected_line = format!(
        "{}  attachments/claim-groups/claim-group-map.json\n",
        file_digest(map)?
    );
    if !manifest
        .lines()
        .any(|line| format!("{line}\n") == expected_line)
    {
        return Err("offline packet manifest does not bind the claim/public mapping".to_owned());
    }
    let mut reports = named_files(public_root, "compatibility-report.md")?;
    reports.extend(named_files(public_root, "public-compatibility-report.md")?);
    if reports.len() != 1 {
        return Err("active promotion lacks one current public compatibility report".to_owned());
    }
    let subject_directory = subjects[0]
        .parent()
        .ok_or_else(|| "graph review subject has no retained directory".to_owned())?;
    let auth = subject_directory.join("auth").join("role-graph");
    let reviewed_groups = crate::assurance::verify_reviewed_claim_groups(
        &auth.join("review.dsse.json"),
        &auth.join("reviewer.allowed_signers"),
        candidate,
        epoch,
    )?;
    let group_ids = reviewed_groups
        .iter()
        .filter_map(|binding| binding.lines().next().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    let parsed = parse_claim_public_mappings(&map_text, &group_ids)?;
    let mapping_sha256 = file_digest(map)?;
    let packet_sha256 = file_digest(&packet_manifests[0])?;
    let public_report_sha256 = file_digest(&reports[0])?;
    Ok(parsed
        .into_iter()
        .map(|(cell, (review_group_id, statement_id))| {
            (
                cell,
                VerifiedClaimPublicMapping {
                    review_group_id,
                    statement_id,
                    mapping_sha256: mapping_sha256.clone(),
                    packet_sha256: packet_sha256.clone(),
                    public_report_sha256: public_report_sha256.clone(),
                },
            )
        })
        .collect())
}

fn parse_claim_public_mappings(
    document: &str,
    signed_group_ids: &BTreeSet<String>,
) -> Result<BTreeMap<String, (String, String)>, String> {
    let mut mappings = BTreeMap::new();
    for record in array_objects(document, "mappings")? {
        let cell = quoted_field(record, "claimCellId")?;
        let group = quoted_field(record, "reviewGroupId")?;
        let statement = quoted_field(record, "publicStatementId")?;
        let status = cell
            .rsplit_once(':')
            .map(|(_, status)| status)
            .ok_or_else(|| "claim/public mapping has an invalid claim cell ID".to_owned())?;
        let expected_statement = format!("bounded-compatibility-report/claim-scope-cells/{status}");
        if !signed_group_ids.contains(&group)
            || statement != expected_statement
            || mappings.insert(cell, (group, statement)).is_some()
        {
            return Err(
                "claim/public mapping is duplicated, unsigned, or names a nonexistent report section"
                    .to_owned(),
            );
        }
    }
    if mappings.is_empty() {
        return Err("claim/public mapping packet is empty".to_owned());
    }
    Ok(mappings)
}

fn record_objects(document: &str) -> Result<Vec<&str>, String> {
    array_objects(document, "records")
}

fn array_objects<'a>(document: &'a str, field: &str) -> Result<Vec<&'a str>, String> {
    let marker = format!("\"{field}\": [");
    let start = document
        .find(&marker)
        .ok_or_else(|| format!("document lacks {field} object array"))?
        + marker.len();
    if document[start..].contains(&marker) {
        return Err(format!("document repeats {field} object array"));
    }
    let mut objects = Vec::new();
    let mut depth = 0_u32;
    let mut object_start = None;
    let mut quoted = false;
    let mut escaped = false;
    for (offset, character) in document[start..].char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                quoted = false;
            }
            continue;
        }
        match character {
            '"' => quoted = true,
            '{' => {
                if depth == 0 {
                    object_start = Some(start + offset);
                }
                depth = depth
                    .checked_add(1)
                    .ok_or_else(|| "divergence record nesting overflows".to_owned())?;
            }
            '}' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| "divergence record closes before opening".to_owned())?;
                if depth == 0 {
                    let begin = object_start
                        .take()
                        .ok_or_else(|| "divergence record lacks a start".to_owned())?;
                    objects.push(&document[begin..=start + offset]);
                }
            }
            ']' if depth == 0 => return Ok(objects),
            value if depth == 0 && !matches!(value, ' ' | '\n' | '\r' | '\t' | ',') => {
                return Err("divergence records array contains a non-object value".to_owned());
            }
            _ => {}
        }
    }
    Err("divergence records array is unterminated".to_owned())
}

fn claim_cells(paths: &[PathBuf]) -> Result<BTreeMap<String, BTreeSet<ClaimCell>>, String> {
    let mut claims = BTreeMap::<String, BTreeSet<ClaimCell>>::new();
    for path in paths {
        let document = fs::read_to_string(path)
            .map_err(|error| format!("cannot read claim index {}: {error}", path.display()))?;
        for line in document.lines().map(str::trim) {
            if !line.starts_with("{ \"builtin\": ") || !line.contains("\"reference\": ") {
                continue;
            }
            let reference = quoted_field(line, "reference")?;
            let case_id = hell_builtins::parse_differential_reference(&reference)
                .map_err(|_| format!("claim index {} has an invalid reference", path.display()))?
                .case_id
                .to_owned();
            let cell = ClaimCell {
                builtin: quoted_field(line, "builtin")?,
                dimension: quoted_field(line, "dimension")?,
                platform: quoted_field(line, "platform")?,
                status: quoted_field(line, "status")?,
                reference,
            };
            claims.entry(case_id).or_default().insert(cell);
        }
    }
    Ok(claims)
}

fn mismatch_impacts(
    root: &Path,
    claims: &BTreeMap<String, BTreeSet<ClaimCell>>,
    divergences: &[ApprovedDivergence],
    public_mappings: &BTreeMap<String, VerifiedClaimPublicMapping>,
    observed_at: &str,
) -> Result<Vec<MismatchImpact>, String> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect mismatch root: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("surveillance mismatch root is not a real directory".to_owned());
    }
    let mut directories = fs::read_dir(root)
        .map_err(|error| format!("cannot read mismatch root: {error}"))?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot read mismatch entry: {error}"))?;
    directories.sort();
    let mut impacts = Vec::with_capacity(directories.len());
    for directory in directories {
        let metadata = fs::symlink_metadata(&directory)
            .map_err(|error| format!("cannot inspect {}: {error}", directory.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "mismatch entry {} is not a real directory",
                directory.display()
            ));
        }
        let case_id = directory
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "mismatch case ID is not UTF-8".to_owned())?
            .to_owned();
        require_atom(&case_id, "mismatch case ID")?;
        let bundle_sha256 = verify_observation_bundle(&directory)
            .map_err(|error| format!("invalid mismatch bundle {case_id}: {error}"))?;
        let oracle_sha256 = file_digest(&directory.join("oracle").join("observation.json"))?;
        let candidate_sha256 = file_digest(&directory.join("candidate").join("observation.json"))?;
        let raw_observation_sha256 = sha256_bytes(
            [
                oracle_sha256.as_bytes(),
                b"\n",
                candidate_sha256.as_bytes(),
                b"\n",
            ]
            .concat()
            .as_slice(),
        )
        .hex();
        let normalized_observation_sha256 = file_digest(&directory.join("normalized.diff"))?;
        let cells = claims.get(&case_id).cloned().unwrap_or_default();
        let (disposition, divergence_id, divergence_review) = classify_impact(
            &cells,
            bundle_sha256,
            &raw_observation_sha256,
            &normalized_observation_sha256,
            divergences,
            observed_at,
        );
        let mapped = cells
            .iter()
            .filter_map(|cell| public_mappings.get(&claim_cell_id(cell)))
            .collect::<Vec<_>>();
        if mapped.len() != cells.len() {
            return Err("regression impact lacks a verified review/public mapping".to_owned());
        }
        impacts.push(MismatchImpact {
            bundle_path: path_text(&directory)?,
            bundle_sha256,
            cells,
            raw_observation_sha256,
            normalized_observation_sha256,
            disposition,
            divergence_id,
            divergence_review,
            review_groups: mapped
                .iter()
                .map(|mapping| mapping.review_group_id.clone())
                .collect(),
            public_statements: mapped
                .iter()
                .map(|mapping| mapping.statement_id.clone())
                .collect(),
            case_id,
        });
    }
    Ok(impacts)
}

fn classify_impact(
    cells: &BTreeSet<ClaimCell>,
    bundle_sha256: Digest,
    raw_observation_sha256: &str,
    normalized_observation_sha256: &str,
    divergences: &[ApprovedDivergence],
    observed_at: &str,
) -> (ImpactDisposition, Option<String>, Option<String>) {
    for cell in cells {
        let fingerprint = divergence_fingerprint(
            cell,
            bundle_sha256,
            raw_observation_sha256,
            normalized_observation_sha256,
        );
        if let Some(divergence) = divergences.iter().find(|divergence| {
            divergence.builtin == cell.builtin
                && divergence.dimension == cell.dimension
                && divergence.platform == cell.platform
                && divergence.profile == "upstream"
                && divergence.fingerprint == fingerprint
        }) {
            let disposition = if divergence.expires_at.as_str() > observed_at {
                ImpactDisposition::ApprovedUnchanged
            } else {
                ImpactDisposition::Expired
            };
            return (
                disposition,
                Some(divergence.divergence_id.clone()),
                Some(divergence.review_ref.clone()),
            );
        }
    }
    (ImpactDisposition::NewOrChanged, None, None)
}

fn divergence_fingerprint(
    cell: &ClaimCell,
    bundle_sha256: Digest,
    raw_observation_sha256: &str,
    normalized_observation_sha256: &str,
) -> String {
    let mut subject = String::new();
    let evidence_ref = bundle_sha256.hex();
    for field in [
        cell.builtin.as_str(),
        cell.dimension.as_str(),
        "upstream",
        cell.platform.as_str(),
        evidence_ref.as_str(),
        raw_observation_sha256,
        normalized_observation_sha256,
    ] {
        subject.push_str(field);
        subject.push('\n');
    }
    sha256_bytes(subject.as_bytes()).hex()
}

struct ImpactReport<'a> {
    candidate: &'a str,
    epoch: &'a str,
    observed_at: &'a str,
    nightly_path: &'a str,
    nightly_sha256: &'a str,
    nightly_present: bool,
    source_passed: bool,
    policy_path: &'a str,
    policy_sha256: &'a str,
    claim_indexes: &'a [PathBuf],
    impacts: &'a [MismatchImpact],
    warnings: &'a [DivergenceWarning],
    state: ImpactState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ImpactState {
    Pass,
    AtRisk,
    Revoke,
}

fn derive_impact_state(
    source_passed: bool,
    actionable: usize,
    has_claim_indexes: bool,
    warnings: &[DivergenceWarning],
    automatic_critical_events: &BTreeSet<String>,
) -> ImpactState {
    let expired = warnings.iter().any(|warning| warning.state == "expired");
    if (actionable != 0 && automatic_critical_events.contains("promoted_claim_regression"))
        || (expired && automatic_critical_events.contains("accepted_divergence_expired"))
    {
        ImpactState::Revoke
    } else if source_passed && actionable == 0 && warnings.is_empty() && has_claim_indexes {
        ImpactState::Pass
    } else {
        ImpactState::AtRisk
    }
}

impl ImpactState {
    const fn result(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::AtRisk | Self::Revoke => "fail",
        }
    }

    const fn immediate_revocation(self) -> bool {
        matches!(self, Self::Revoke)
    }
}

fn impact_json(report: &ImpactReport<'_>) -> Result<String, String> {
    let actionable = report
        .impacts
        .iter()
        .filter(|impact| impact.disposition != ImpactDisposition::ApprovedUnchanged)
        .count();
    let approved_unchanged = report.impacts.len().saturating_sub(actionable);
    let expired = report
        .warnings
        .iter()
        .filter(|warning| warning.state == "expired")
        .count();
    let mut output = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in [
        ("candidateCommit", report.candidate),
        ("assuranceEpochSha256", report.epoch),
        ("observedAt", report.observed_at),
        ("nightlyPath", report.nightly_path),
        ("nightlySha256", report.nightly_sha256),
        ("surveillancePolicyPath", report.policy_path),
        ("surveillancePolicySha256", report.policy_sha256),
    ] {
        output.push_str(",\n  \"");
        output.push_str(field);
        output.push_str("\": ");
        push_json(&mut output, value);
    }
    write!(
        output,
        ",\n  \"nightlyPresent\": {},\n  \"nightlyPassed\": {},\n  \"mismatchCount\": {actionable},\n  \"approvedUnchangedDivergenceCount\": {approved_unchanged},\n  \"retainedMismatchBundleCount\": {}",
        report.nightly_present,
        report.source_passed,
        report.impacts.len()
    )
    .expect("writing to String cannot fail");
    output.push_str(",\n  \"claimIndexes\": [");
    for (index, path) in report.claim_indexes.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("\n    {\"path\": ");
        push_json(&mut output, &path_text(path)?);
        output.push_str(", \"sha256\": ");
        push_json(&mut output, &file_digest(path)?);
        output.push('}');
    }
    output.push_str("\n  ],\n  \"mismatches\": [");
    for (index, impact) in report.impacts.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        mismatch_json(&mut output, impact);
    }
    output.push_str("\n  ],\n  \"reviewRequired\": ");
    output.push_str(if matches!(report.state, ImpactState::Pass) {
        "false"
    } else {
        "true"
    });
    output.push_str(",\n  \"immediateRevocationRequired\": ");
    output.push_str(if report.state.immediate_revocation() {
        "true"
    } else {
        "false"
    });
    write!(
        output,
        ",\n  \"promotedClaimRegressionPassed\": {},\n  \"acceptedDivergenceExpiryPassed\": {},\n  \"expiredDivergenceCount\": {expired}",
        report.source_passed && actionable == 0,
        expired == 0,
    )
    .expect("writing to String cannot fail");
    output.push_str(",\n  \"revocationDecision\": \"");
    output.push_str(if report.state.immediate_revocation() {
        "automatic-revocation-required"
    } else {
        "at-risk-pending-independent-impact-review"
    });
    output.push_str("\",\n  \"result\": \"");
    output.push_str(report.state.result());
    output.push_str("\",\n  \"divergenceExpiryWarningCount\": ");
    output.push_str(&report.warnings.len().to_string());
    output.push_str("\n}\n");
    Ok(output)
}

fn divergence_warning_json(
    candidate: &str,
    epoch: &str,
    observed_at: &str,
    policy_sha256: &str,
    warnings: &[DivergenceWarning],
) -> String {
    let mut output = String::from("{\n  \"schemaVersion\": 1");
    for (field, value) in [
        ("candidateCommit", candidate),
        ("assuranceEpochSha256", epoch),
        ("observedAt", observed_at),
        ("surveillancePolicySha256", policy_sha256),
    ] {
        output.push_str(",\n  \"");
        output.push_str(field);
        output.push_str("\": ");
        push_json(&mut output, value);
    }
    output.push_str(",\n  \"records\": [");
    for (index, warning) in warnings.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("\n    {\"divergenceId\": ");
        push_json(&mut output, &warning.divergence_id);
        write!(
            output,
            ", \"issueNumber\": {}, \"expiresAt\": ",
            warning.issue_number
        )
        .expect("writing to String cannot fail");
        push_json(&mut output, &warning.expires_at);
        write!(
            output,
            ", \"daysRemaining\": {}, \"warningWindowDays\": {}, \"state\": ",
            warning.days_remaining, warning.warning_window_days
        )
        .expect("writing to String cannot fail");
        push_json(&mut output, warning.state);
        output.push('}');
    }
    output.push_str("\n  ]\n}\n");
    output
}

fn mismatch_json(output: &mut String, impact: &MismatchImpact) {
    output.push_str("\n    {\"caseId\": ");
    push_json(output, &impact.case_id);
    output.push_str(", \"bundlePath\": ");
    push_json(output, &impact.bundle_path);
    output.push_str(", \"bundleSha256\": ");
    push_json(output, &impact.bundle_sha256.hex());
    output.push_str(", \"rawObservationSha256\": ");
    push_json(output, &impact.raw_observation_sha256);
    output.push_str(", \"normalizedObservationSha256\": ");
    push_json(output, &impact.normalized_observation_sha256);
    output.push_str(", \"disposition\": \"");
    output.push_str(match impact.disposition {
        ImpactDisposition::ApprovedUnchanged => "approved-unchanged",
        ImpactDisposition::NewOrChanged => "new-or-changed",
        ImpactDisposition::Expired => "expired",
    });
    output.push_str("\", \"divergenceId\": ");
    push_optional_json(output, impact.divergence_id.as_deref());
    output.push_str(", \"divergenceReviewSha256\": ");
    push_optional_json(output, impact.divergence_review.as_deref());
    output.push_str(", \"mappingState\": \"");
    output.push_str(if impact.cells.is_empty() {
        "unmapped-generated-or-uncataloged"
    } else {
        "exact-claim-reference"
    });
    output.push_str("\", \"affectedClaimCells\": [");
    for (index, cell) in impact.cells.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        let id = claim_cell_id(cell);
        push_json(output, &id);
    }
    output.push_str("], \"affectedEvidenceReferences\": [");
    if impact.cells.is_empty() {
        let mut reference = String::from("mismatch-bundle:");
        reference.push_str(&impact.bundle_path);
        reference.push('#');
        reference.push_str(&impact.bundle_sha256.hex());
        push_json(output, &reference);
    } else {
        for (index, cell) in impact.cells.iter().enumerate() {
            if index != 0 {
                output.push_str(", ");
            }
            push_json(output, &cell.reference);
        }
    }
    output.push_str("], \"affectedReviewGroups\": [");
    if impact.review_groups.is_empty() {
        let mut group = String::from("regression-review:unmapped:");
        group.push_str(&impact.case_id);
        push_json(output, &group);
    } else {
        for (index, group) in impact.review_groups.iter().enumerate() {
            if index != 0 {
                output.push_str(", ");
            }
            push_json(output, group);
        }
    }
    output.push_str("], \"affectedPublicStatements\": [");
    if impact.public_statements.is_empty() {
        let mut statement = String::from("compatibility-report:unmapped-regression:");
        statement.push_str(&impact.case_id);
        push_json(output, &statement);
    } else {
        for (index, statement) in impact.public_statements.iter().enumerate() {
            if index != 0 {
                output.push_str(", ");
            }
            push_json(output, statement);
        }
    }
    output.push_str("]}");
}

fn push_optional_json(output: &mut String, value: Option<&str>) {
    if let Some(value) = value {
        push_json(output, value);
    } else {
        output.push_str("null");
    }
}

fn claim_cell_id(cell: &ClaimCell) -> String {
    [
        cell.builtin.as_str(),
        cell.dimension.as_str(),
        cell.platform.as_str(),
        cell.status.as_str(),
    ]
    .join(":")
}

fn named_files(root: &Path, name: &str) -> Result<Vec<PathBuf>, String> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut pending = vec![root.to_path_buf()];
    let mut matches = Vec::new();
    while let Some(directory) = pending.pop() {
        let mut entries = fs::read_dir(&directory)
            .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
            .map(|entry| entry.map(|value| value.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot read directory entry: {error}"))?;
        entries.sort();
        for path in entries {
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "retained evidence contains symlink {}",
                    path.display()
                ));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() && path.file_name().is_some_and(|value| value == name) {
                matches.push(path);
            }
        }
    }
    matches.sort();
    Ok(matches)
}

fn quoted_field(document: &str, field: &str) -> Result<String, String> {
    let needle = format!("\"{field}\": \"");
    let mut matches = document.match_indices(&needle);
    let (offset, _) = matches
        .next()
        .ok_or_else(|| format!("document lacks {field}"))?;
    if matches.next().is_some() {
        return Err(format!("document repeats {field}"));
    }
    let value = &document[offset + needle.len()..];
    let end = value
        .find('"')
        .ok_or_else(|| format!("document has an unterminated {field}"))?;
    let value = &value[..end];
    require_atom(value, field)?;
    Ok(value.to_owned())
}

fn json_boolean(document: &str, field: &str) -> Result<bool, String> {
    let needle = format!("\"{field}\": ");
    let mut matches = document.match_indices(&needle);
    let (offset, _) = matches
        .next()
        .ok_or_else(|| format!("document lacks {field}"))?;
    if matches.next().is_some() {
        return Err(format!("document repeats {field}"));
    }
    let value = &document[offset + needle.len()..];
    if value
        .strip_prefix("true")
        .is_some_and(boolean_value_has_canonical_suffix)
    {
        Ok(true)
    } else if value
        .strip_prefix("false")
        .is_some_and(boolean_value_has_canonical_suffix)
    {
        Ok(false)
    } else {
        Err(format!("document {field} is not boolean"))
    }
}

fn unsigned_field(document: &str, field: &str) -> Result<u64, String> {
    let needle = format!("\"{field}\": ");
    let mut matches = document.match_indices(&needle);
    let (offset, _) = matches
        .next()
        .ok_or_else(|| format!("document lacks {field}"))?;
    if matches.next().is_some() {
        return Err(format!("document repeats {field}"));
    }
    let value = &document[offset + needle.len()..];
    let end = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    value[..end]
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| format!("document {field} is not a nonzero unsigned integer"))
}

fn boolean_value_has_canonical_suffix(value: &str) -> bool {
    matches!(value.as_bytes().first(), Some(b',' | b'}' | b'\n'))
}

fn file_digest(path: &Path) -> Result<String, String> {
    sha256_file(path)
        .map(Digest::hex)
        .map_err(|error| format!("cannot hash {}: {error}", path.display()))
}

fn file_digest_or_absent(path: &Path) -> Result<String, String> {
    if path.exists() {
        file_digest(path)
    } else {
        Ok(hell_testkit::sha256_bytes(b"absent-surveillance-component").hex())
    }
}

fn path_text(path: &Path) -> Result<String, String> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "path {} is not portable and relative",
            path.display()
        ));
    }
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("path {} is not UTF-8", path.display()))
}

fn require_atom(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'+' | b'=')
        })
    {
        Err(format!("{label} is not a safe canonical atom"))
    } else {
        Ok(())
    }
}

fn require_digest(value: &str, label: &str) -> Result<(), String> {
    Digest::from_hex(value)
        .map(|_| ())
        .map_err(|_| format!("{label} is not a SHA-256 digest"))
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
    fn claim_index_mapping_is_exact_and_unmapped_regressions_remain_visible() {
        let reference = "differential:case-one";
        let document = format!(
            "{{ \"builtin\": \"echo\", \"dimension\": \"stdout\", \"status\": \"exact\", \"profile\": \"upstream\", \"platform\": \"linux-amd64\", \"reference\": \"{reference}\" }}\n"
        );
        let directory =
            std::env::temp_dir().join(format!("hell-surveillance-impact-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let index = directory.join("claim-index.json");
        fs::write(&index, document).unwrap();
        let claims = claim_cells(&[index]).unwrap();
        assert_eq!(claims.get("case-one").unwrap().len(), 1);
        assert!(!claims.contains_key("generated-unmapped"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn boolean_parser_rejects_duplicate_or_wrong_typed_results() {
        assert_eq!(json_boolean("{\"passed\": true}", "passed"), Ok(true));
        assert!(json_boolean("{\"passed\": \"true\"}", "passed").is_err());
        assert!(json_boolean("{\"passed\": true, \"passed\": false}", "passed").is_err());
    }

    #[test]
    fn claim_public_mappings_require_exact_signed_groups() {
        let groups = BTreeSet::from(["group-one".to_owned()]);
        let mapping = "{\"mappings\": [{\"claimCellId\": \"echo:stdout:linux-amd64:exact\", \"reviewGroupId\": \"group-one\", \"publicStatementId\": \"bounded-compatibility-report/claim-scope-cells/exact\"}]}";
        assert_eq!(
            parse_claim_public_mappings(mapping, &groups).unwrap().len(),
            1
        );
        let unsigned = mapping.replace("group-one", "group-two");
        assert!(parse_claim_public_mappings(&unsigned, &groups).is_err());
        let duplicate = mapping.replace("]}", ",{\"claimCellId\": \"echo:stdout:linux-amd64:exact\", \"reviewGroupId\": \"group-one\", \"publicStatementId\": \"other\"}]}");
        assert!(parse_claim_public_mappings(&duplicate, &groups).is_err());
    }

    #[test]
    fn divergence_classification_distinguishes_unchanged_changed_and_expired() {
        let cell = ClaimCell {
            builtin: "echo".to_owned(),
            dimension: "stdout".to_owned(),
            platform: "linux-amd64".to_owned(),
            status: "deliberate-divergence".to_owned(),
            reference: "differential:case-one".to_owned(),
        };
        let cells = BTreeSet::from([cell.clone()]);
        let bundle = sha256_bytes(b"bundle");
        let raw = sha256_bytes(b"raw").hex();
        let normalized = sha256_bytes(b"normalized").hex();
        let fingerprint = divergence_fingerprint(&cell, bundle, &raw, &normalized);
        let approved = ApprovedDivergence {
            divergence_id: "divergence-one".to_owned(),
            builtin: cell.builtin.clone(),
            dimension: cell.dimension.clone(),
            platform: cell.platform.clone(),
            profile: "upstream".to_owned(),
            fingerprint,
            expires_at: "2030-01-01T00:00:00Z".to_owned(),
            review_ref: sha256_bytes(b"review").hex(),
            issue_number: 17,
        };
        assert_eq!(
            classify_impact(
                &cells,
                bundle,
                &raw,
                &normalized,
                std::slice::from_ref(&approved),
                "2029-01-01T00:00:00Z"
            )
            .0,
            ImpactDisposition::ApprovedUnchanged
        );
        assert_eq!(
            classify_impact(
                &cells,
                bundle,
                &raw,
                &sha256_bytes(b"changed").hex(),
                std::slice::from_ref(&approved),
                "2029-01-01T00:00:00Z"
            )
            .0,
            ImpactDisposition::NewOrChanged
        );
        assert_eq!(
            classify_impact(
                &cells,
                bundle,
                &raw,
                &normalized,
                &[approved],
                "2030-01-01T00:00:00Z"
            )
            .0,
            ImpactDisposition::Expired
        );
    }

    #[test]
    fn divergence_warning_windows_are_exact_at_thirty_fourteen_and_seven_days() {
        let divergence = ApprovedDivergence {
            divergence_id: "divergence-one".to_owned(),
            builtin: "Bool.bool".to_owned(),
            dimension: "pure-runtime".to_owned(),
            platform: "linux-amd64".to_owned(),
            profile: "upstream".to_owned(),
            fingerprint: sha256_bytes(b"fingerprint").hex(),
            expires_at: "2030-01-01T00:00:00Z".to_owned(),
            review_ref: sha256_bytes(b"review").hex(),
            issue_number: 17,
        };
        let windows = [30, 14, 7];
        for (observed_at, expected_window) in [
            ("2029-12-02T00:00:00Z", 30),
            ("2029-12-18T00:00:00Z", 14),
            ("2029-12-25T00:00:00Z", 7),
            ("2029-12-26T00:00:00Z", 7),
        ] {
            let warnings =
                divergence_warnings(std::slice::from_ref(&divergence), observed_at, &windows)
                    .unwrap();
            assert_eq!(warnings.len(), 1);
            assert_eq!(warnings[0].warning_window_days, expected_window);
            assert_eq!(warnings[0].state, "warning");
        }
        assert!(
            divergence_warnings(
                std::slice::from_ref(&divergence),
                "2029-11-30T00:00:00Z",
                &windows,
            )
            .unwrap()
            .is_empty()
        );
        let expired = divergence_warnings(&[divergence], "2030-01-01T00:00:00Z", &windows).unwrap();
        assert_eq!(expired[0].state, "expired");
        let no_automatic_events = BTreeSet::new();
        assert_eq!(
            derive_impact_state(true, 0, true, &[], &no_automatic_events),
            ImpactState::Pass
        );
        assert_eq!(
            derive_impact_state(true, 0, true, &expired, &no_automatic_events),
            ImpactState::AtRisk
        );
        assert_eq!(
            derive_impact_state(
                true,
                0,
                true,
                &expired,
                &BTreeSet::from(["accepted_divergence_expired".to_owned()]),
            ),
            ImpactState::Revoke
        );
    }

    #[test]
    fn every_linked_divergence_issue_must_remain_open() {
        assert!(
            verify_linked_issue_state(
                17,
                "17\tOPEN\thttps://github.com/Portfoligno/hell-rs/issues/17\t2029-01-01T00:00:00Z\n",
            )
            .is_ok()
        );
        assert!(
            verify_linked_issue_state(
                17,
                "17\tCLOSED\thttps://github.com/Portfoligno/hell-rs/issues/17\t2029-01-01T00:00:00Z\n",
            )
            .is_err()
        );
        assert!(
            verify_linked_issue_state(
                17,
                "18\tOPEN\thttps://github.com/Portfoligno/hell-rs/issues/18\t2029-01-01T00:00:00Z\n",
            )
            .is_err()
        );
    }

    #[test]
    fn divergence_review_reference_must_resolve_to_retained_signed_evidence() {
        let directory = std::env::temp_dir().join(format!(
            "hell-surveillance-divergence-review-{}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let details = directory.join("divergence-report.details.json");
        fs::write(&details, "{}\n").unwrap();
        assert!(
            verify_divergence_review(
                &directory,
                &details,
                &sha256_bytes(b"missing-review").hex(),
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                &sha256_bytes(b"epoch").hex(),
            )
            .is_err()
        );
        fs::remove_dir_all(directory).unwrap();
    }
}
