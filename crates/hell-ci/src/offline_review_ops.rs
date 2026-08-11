use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use hell_testkit::{sha256_bytes, sha256_file};

fn component_path<const N: usize>(components: [&str; N]) -> PathBuf {
    components.iter().collect()
}

const COVERAGE: &str = "ci-out/evidence/coverage/claim-coverage.finalized.json";
const SUBJECT: &str = "ci-out/evidence/review/graph-review-subject.json";
const ROLE_GRAPH: &str = "ci-out/evidence/review/role-graph.details.json";
const PACKET_ROOT: &str = "ci-out/evidence/promotion-review-packet";
const GROUP_REVIEW: &str = "ci-out/evidence/review/auth/role-graph/review.dsse.json";
const GROUP_POLICY: &str = "ci-out/evidence/review/auth/role-graph/reviewer.allowed_signers";
const OUTPUT: &str = "ci-out/evidence/review/offline-review-packet.json";
const COMPONENT_SET: &str = "ci-out/evidence/review/semantic-review-set.json";
const PROVIDER_ARTIFACTS: &str = "ci-out/evidence/review/provider-review-artifacts.json";

const REVIEWS: [ReviewInput; 4] = [
    ReviewInput {
        kind: "claim-coverage",
        role: "claim-reviewer",
        details: "ci-out/evidence/coverage/claim-coverage.finalized.json",
        bound: "ci-out/evidence/coverage/claim-coverage.json",
        authorization: "ci-out/evidence/review/auth/claim/authorization.json",
        review: "ci-out/evidence/review/auth/claim/review.dsse.json",
        policy: "ci-out/evidence/review/auth/claim/reviewer.allowed_signers",
    },
    ReviewInput {
        kind: "normalizer-audit",
        role: "normalizer-reviewer",
        details: "ci-out/evidence/coverage/normalizer-audit.details.json",
        bound: "ci-out/evidence/coverage/normalizer-audit.json",
        authorization: "ci-out/evidence/review/auth/normalizer/authorization.json",
        review: "ci-out/evidence/review/auth/normalizer/review.dsse.json",
        policy: "ci-out/evidence/review/auth/normalizer/reviewer.allowed_signers",
    },
    ReviewInput {
        kind: "divergence",
        role: "divergence-reviewer",
        details: "ci-out/evidence/review/divergence-report.details.json",
        bound: "ci-out/evidence/review/divergence-report.json",
        authorization: "ci-out/evidence/review/auth/divergence/authorization.json",
        review: "ci-out/evidence/review/auth/divergence/review.dsse.json",
        policy: "ci-out/evidence/review/auth/divergence/reviewer.allowed_signers",
    },
    ReviewInput {
        kind: "residual-risk",
        role: "residual-risk-reviewer",
        details: "ci-out/evidence/coverage/residual-risk.details.json",
        bound: "ci-out/evidence/coverage/residual-risk.json",
        authorization: "ci-out/evidence/review/auth/residual-risk/authorization.json",
        review: "ci-out/evidence/review/auth/residual-risk/review.dsse.json",
        policy: "ci-out/evidence/review/auth/residual-risk/reviewer.allowed_signers",
    },
];

struct ReviewInput {
    kind: &'static str,
    role: &'static str,
    details: &'static str,
    bound: &'static str,
    authorization: &'static str,
    review: &'static str,
    policy: &'static str,
}

struct GroupBinding {
    identity: String,
    cells: Vec<String>,
    evidence: Vec<String>,
}

struct VerifiedComponent {
    kind: &'static str,
    bound: &'static str,
    bound_digest: String,
    review_digest: String,
    subject: String,
    fingerprint: String,
}

struct ExceptionQueue {
    id: &'static str,
    sources: Vec<QueueSource>,
    records: Vec<QueueRecord>,
}

#[derive(Clone)]
struct QueueSource {
    path: String,
    sha256: String,
}

struct QueueRecord {
    id: String,
    retained_refs: Vec<String>,
}

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments
        .first()
        .is_some_and(|argument| argument == "offline-review-ops")
}

pub(crate) fn run(arguments: &[OsString]) -> Result<String, String> {
    match arguments.get(1).and_then(|argument| argument.to_str()) {
        Some("workflow-verify-components") if arguments.len() == 2 => {
            workflow_verify_components()
        }
        Some("workflow-manifest") if arguments.len() == 2 => workflow_manifest(),
        Some("workflow-package") if arguments.len() == 2 => workflow_package(),
        _ => Err(
            "offline-review-ops requires workflow-verify-components, workflow-manifest, or workflow-package"
                .to_owned(),
        ),
    }
}

fn workflow_verify_components() -> Result<String, String> {
    let coverage = read(Path::new(COVERAGE))?;
    let candidate = quoted_field(&coverage, "candidateSourceCommit")?;
    let epoch = quoted_field(&coverage, "assuranceEpochSha256")?;
    require_git_sha(&candidate)?;
    require_digest(&epoch)?;
    retain_review_provider_artifacts()?;
    let components = verify_components(&candidate, &epoch)?;
    let output = render_component_set(&candidate, &epoch, &components)?;
    write_atomic(Path::new(COMPONENT_SET), output.as_bytes())?;
    Ok(format!(
        "verified and retained {} semantic review components",
        components.len()
    ))
}

fn workflow_manifest() -> Result<String, String> {
    crate::assurance::verify_offline_packet_sources(
        Path::new("ci-out"),
        &component_path(["compat", "reviews.allowed_signers"]),
    )?;
    let coverage = read(Path::new(COVERAGE))?;
    let candidate = quoted_field(&coverage, "candidateSourceCommit")?;
    let epoch = quoted_field(&coverage, "assuranceEpochSha256")?;
    require_git_sha(&candidate)?;
    require_digest(&epoch)?;
    let components = verify_components(&candidate, &epoch)?;
    let retained_components = read(Path::new(COMPONENT_SET))?;
    if retained_components != render_component_set(&candidate, &epoch, &components)? {
        return Err("retained semantic review component set is stale".to_owned());
    }
    let cells = crate::assurance::finalized_claim_cells(Path::new(COVERAGE))?;
    let groups = claim_groups(&cells)?;
    if groups.is_empty() {
        return Err("claim-group manifest cannot be empty".to_owned());
    }
    let review_set = component_review_set_digest(&components)?;
    file_digest(Path::new(ROLE_GRAPH))?;
    let queues = exception_queues(&cells, &groups)?;
    let packet_sha256 =
        build_offline_packet(&candidate, &epoch, &cells, &groups, &components, &queues)?;
    let subject = render_subject(&candidate, &epoch, &groups, &review_set, &packet_sha256)?;
    write_atomic(Path::new(SUBJECT), subject.as_bytes())?;
    Ok(format!(
        "wrote deterministic offline manifest for {} exact claim groups",
        groups.len()
    ))
}

fn render_component_set(
    candidate: &str,
    epoch: &str,
    components: &[VerifiedComponent],
) -> Result<String, String> {
    let mut output = String::from("{\n  \"schemaVersion\": 1,\n  \"candidateSourceCommit\": ");
    push_json(&mut output, candidate);
    output.push_str(",\n  \"assuranceEpochSha256\": ");
    push_json(&mut output, epoch);
    output.push_str(",\n  \"reviewSetSha256\": ");
    push_json(&mut output, &component_review_set_digest(components)?);
    output.push_str(",\n  \"components\": [");
    for (index, component) in components.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("\n    {\"kind\": ");
        push_json(&mut output, component.kind);
        output.push_str(", \"boundPath\": ");
        push_json(&mut output, component.bound);
        output.push_str(", \"boundSha256\": ");
        push_json(&mut output, &component.bound_digest);
        output.push_str(", \"reviewSha256\": ");
        push_json(&mut output, &component.review_digest);
        output.push_str(", \"reviewerSubject\": ");
        push_json(&mut output, &component.subject);
        output.push_str(", \"signerFingerprint\": ");
        push_json(&mut output, &component.fingerprint);
        output.push('}');
    }
    output.push_str("\n  ]\n}\n");
    Ok(output)
}

fn workflow_package() -> Result<String, String> {
    let coverage = read(Path::new(COVERAGE))?;
    let candidate = quoted_field(&coverage, "candidateSourceCommit")?;
    let epoch = quoted_field(&coverage, "assuranceEpochSha256")?;
    let components = verify_components(&candidate, &epoch)?;
    let cells = crate::assurance::finalized_claim_cells(Path::new(COVERAGE))?;
    let groups = claim_groups(&cells)?;
    let packet_sha256 = verify_packet_manifest()?;
    let expected = render_subject(
        &candidate,
        &epoch,
        &groups,
        &component_review_set_digest(&components)?,
        &packet_sha256,
    )?;
    if read(Path::new(SUBJECT))? != expected {
        return Err("signed graph-review subject differs from retained exact evidence".to_owned());
    }
    let reviewed = crate::assurance::verify_reviewed_claim_groups(
        Path::new(GROUP_REVIEW),
        Path::new(GROUP_POLICY),
        &candidate,
        &epoch,
    )?;
    let expected_groups =
        group_review_bindings(&groups, &component_review_set_digest(&components)?);
    if reviewed != expected_groups {
        return Err("claim-group signature omits or substitutes an exact group binding".to_owned());
    }
    let required_artifacts = BTreeSet::from([
        file_digest(Path::new(SUBJECT))?,
        file_digest(Path::new(ROLE_GRAPH))?,
        packet_sha256,
        file_digest(Path::new(
            "ci-out/evidence/review/auth/role-graph/authorization.json",
        ))?,
    ]);
    crate::assurance::verify_review_binding(
        Path::new(GROUP_REVIEW),
        Path::new(GROUP_POLICY),
        "review-graph-reviewer",
        &candidate,
        &epoch,
        &required_artifacts,
    )?;
    verify_bound_record(
        &ReviewInput {
            kind: "review-role-graph",
            role: "review-graph-reviewer",
            details: ROLE_GRAPH,
            bound: "ci-out/evidence/review/role-graph.json",
            authorization: "ci-out/evidence/review/auth/role-graph/authorization.json",
            review: GROUP_REVIEW,
            policy: GROUP_POLICY,
        },
        &candidate,
        &epoch,
    )?;
    let packet = render_packet(&candidate, &epoch, &components, groups.len())?;
    write_atomic(Path::new(OUTPUT), packet.as_bytes())?;
    Ok(format!(
        "verified and retained exact offline review packet for {} claim groups",
        groups.len()
    ))
}

fn verify_components(candidate: &str, epoch: &str) -> Result<Vec<VerifiedComponent>, String> {
    let mut components = Vec::with_capacity(REVIEWS.len());
    let mut subjects = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    for review in REVIEWS {
        verify_bound_record(&review, candidate, epoch)?;
        let details_digest = file_digest(Path::new(review.details))?;
        let authorization_digest = file_digest(Path::new(review.authorization))?;
        let required = BTreeSet::from([details_digest, authorization_digest]);
        let (subject, fingerprint) = crate::assurance::verify_review_binding(
            Path::new(review.review),
            Path::new(review.policy),
            review.role,
            candidate,
            epoch,
            &required,
        )?;
        if !subjects.insert(subject.clone()) || !fingerprints.insert(fingerprint.clone()) {
            return Err(
                "offline evidence roles reuse a reviewer subject or signing key".to_owned(),
            );
        }
        components.push(VerifiedComponent {
            kind: review.kind,
            bound: review.bound,
            bound_digest: file_digest(Path::new(review.bound))?,
            review_digest: file_digest(Path::new(review.review))?,
            subject,
            fingerprint,
        });
    }
    Ok(components)
}

fn retain_review_provider_artifacts() -> Result<(), String> {
    let repository = std::env::var("GITHUB_REPOSITORY")
        .map_err(|_| "review artifact verification lacks GITHUB_REPOSITORY".to_owned())?;
    if repository != "Portfoligno/hell-rs" {
        return Err("review artifact verification selected an unauthorized repository".to_owned());
    }
    let run_id = environment_nonzero("GITHUB_RUN_ID")?;
    let run_attempt = environment_nonzero("GITHUB_RUN_ATTEMPT")?;
    let token = std::env::var("GITHUB_TOKEN")
        .map_err(|_| "review artifact verification lacks GITHUB_TOKEN".to_owned())?;
    if token.is_empty() || token.chars().any(char::is_control) {
        return Err("review artifact verification token is malformed".to_owned());
    }
    let endpoint = component_path(["repos", "Portfoligno", "hell-rs", "actions", "runs"])
        .join(run_id.to_string())
        .join("artifacts");
    let output = Command::new("gh")
        .args([
            OsString::from("api"),
            OsString::from("--method"),
            OsString::from("GET"),
            endpoint.as_os_str().to_owned(),
            OsString::from("--paginate"),
            OsString::from("--jq"),
            OsString::from(
                ".artifacts[] | [.id,.name,.digest,.expired,.created_at,.expires_at] | @tsv",
            ),
        ])
        .env("GH_TOKEN", token)
        .env_remove("GITHUB_TOKEN")
        .output()
        .map_err(|error| format!("cannot query typed review artifacts: {error}"))?;
    if !output.status.success() {
        return Err("typed review artifact query failed with redacted output".to_owned());
    }
    let response = String::from_utf8(output.stdout)
        .map_err(|_| "review artifact response is not UTF-8".to_owned())?;
    let expected = [
        "promotion-review-claim",
        "promotion-review-divergence",
        "promotion-review-normalizer",
        "promotion-review-residual-risk",
    ];
    let mut artifacts = BTreeMap::new();
    for line in response.lines() {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 6 || !expected.contains(&fields[1]) {
            continue;
        }
        if fields[3] != "false" {
            return Err("review provider artifact is expired".to_owned());
        }
        let id = parse_nonzero(fields[0], "review provider artifact ID")?;
        let digest = fields[2]
            .strip_prefix("sha256:")
            .ok_or_else(|| "review provider artifact lacks SHA-256 digest".to_owned())?;
        require_digest(digest)?;
        crate::custody_ops::validate_utc_timestamp(fields[4])?;
        crate::custody_ops::validate_utc_timestamp(fields[5])?;
        if artifacts
            .insert(
                fields[1].to_owned(),
                (
                    id,
                    digest.to_owned(),
                    fields[4].to_owned(),
                    fields[5].to_owned(),
                ),
            )
            .is_some()
        {
            return Err("review provider artifact name is duplicated".to_owned());
        }
    }
    if artifacts.len() != expected.len() {
        return Err("review provider artifact set is incomplete".to_owned());
    }
    let mut json = format!(
        "{{\n  \"schemaVersion\": 1,\n  \"repository\": \"Portfoligno/hell-rs\",\n  \"runId\": {run_id},\n  \"runAttempt\": {run_attempt},\n  \"artifacts\": ["
    );
    for (index, (name, (id, digest, created, expires))) in artifacts.iter().enumerate() {
        if index != 0 {
            json.push(',');
        }
        json.push_str("\n    {\"name\": ");
        push_json(&mut json, name);
        write!(json, ", \"artifactId\": {id}, \"providerSha256\": ")
            .expect("writing to String cannot fail");
        push_json(&mut json, digest);
        json.push_str(", \"createdAt\": ");
        push_json(&mut json, created);
        json.push_str(", \"expiresAt\": ");
        push_json(&mut json, expires);
        json.push('}');
    }
    json.push_str("\n  ]\n}\n");
    write_atomic(Path::new(PROVIDER_ARTIFACTS), json.as_bytes())
}

fn environment_nonzero(name: &str) -> Result<u64, String> {
    let value = std::env::var(name).map_err(|_| format!("review artifacts lack {name}"))?;
    parse_nonzero(&value, name)
}

fn parse_nonzero(value: &str, label: &str) -> Result<u64, String> {
    let value = value
        .parse::<u64>()
        .map_err(|_| format!("{label} is not an integer"))?;
    if value == 0 {
        return Err(format!("{label} must be nonzero"));
    }
    Ok(value)
}

fn verify_bound_record(review: &ReviewInput, candidate: &str, epoch: &str) -> Result<(), String> {
    let document = read(Path::new(review.bound))?;
    for (field, expected) in [
        ("kind", review.kind),
        ("candidateSourceCommit", candidate),
        ("assuranceEpochSha256", epoch),
        ("detailsPath", strip_evidence_prefix(review.details)?),
        ("reviewPath", strip_evidence_prefix(review.review)?),
        (
            "authorizationPath",
            strip_evidence_prefix(review.authorization)?,
        ),
        ("signerPolicyPath", strip_evidence_prefix(review.policy)?),
    ] {
        if quoted_field(&document, field)? != expected {
            return Err(format!("{} bound review has stale {field}", review.kind));
        }
    }
    if number_field(&document, "blockerCount")? != 0 {
        return Err(format!(
            "{} review retains unresolved blockers",
            review.kind
        ));
    }
    for (field, path) in [
        ("detailsSha256", review.details),
        ("reviewSha256", review.review),
        ("authorizationSha256", review.authorization),
        ("signerPolicySha256", review.policy),
    ] {
        if quoted_field(&document, field)? != file_digest(Path::new(path))? {
            return Err(format!("{} bound review has stale {field}", review.kind));
        }
    }
    Ok(())
}

fn claim_groups(
    cells: &[crate::assurance::FinalizedClaimCell],
) -> Result<BTreeMap<String, GroupBinding>, String> {
    let mut groups = BTreeMap::new();
    for cell in cells {
        let evidence = canonical_array(
            cell.evidence_refs
                .iter()
                .map(|reference| reference.canonical_json.as_str()),
        );
        let normalizers = canonical_string_array(&cell.normalizer_ids);
        let obligations = canonical_string_array(&cell.obligations);
        let equivalence = claim_group_equivalence(cell, &evidence, &normalizers, &obligations)?;
        let group_id = format!(
            "assurance-equivalence/{}",
            sha256_bytes(equivalence.as_bytes()).hex()
        );
        let identity = format!(
            "{}\n{}\n{}\n{}\n{equivalence}",
            cell.builtin, cell.dimension, cell.profile, cell.platform
        );
        let group = groups.entry(group_id).or_insert_with(|| GroupBinding {
            identity: String::new(),
            cells: Vec::new(),
            evidence: Vec::new(),
        });
        group.identity.push_str(&identity);
        group.cells.push(format!("{}\n", cell.canonical_json));
        group
            .evidence
            .push(format!("{evidence}\n{normalizers}\n{obligations}\n"));
    }
    Ok(groups)
}

fn canonical_array<'a>(values: impl Iterator<Item = &'a str>) -> String {
    format!("[{}]", values.collect::<Vec<_>>().join(","))
}

fn claim_group_id(cell: &crate::assurance::FinalizedClaimCell) -> Result<String, String> {
    let evidence = canonical_array(
        cell.evidence_refs
            .iter()
            .map(|reference| reference.canonical_json.as_str()),
    );
    let normalizers = canonical_string_array(&cell.normalizer_ids);
    let obligations = canonical_string_array(&cell.obligations);
    let equivalence = claim_group_equivalence(cell, &evidence, &normalizers, &obligations)?;
    Ok(format!(
        "assurance-equivalence/{}",
        sha256_bytes(equivalence.as_bytes()).hex()
    ))
}

fn claim_group_equivalence(
    cell: &crate::assurance::FinalizedClaimCell,
    evidence: &str,
    normalizers: &str,
    obligations: &str,
) -> Result<String, String> {
    for atom in [
        &cell.dimension,
        &cell.profile,
        &cell.platform,
        &cell.proposed_status,
    ] {
        require_group_atom(atom)?;
    }
    let spec = hell_builtins::registry()
        .iter()
        .find(|spec| spec.name == cell.builtin)
        .ok_or_else(|| format!("claim-group references unknown builtin {:?}", cell.builtin))?;
    let metadata = spec.assurance_metadata();
    Ok(format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        spec.implementation.unwrap_or_default(),
        spec.scheme.unwrap_or_default(),
        metadata.semantic_family,
        cell.applicability,
        evidence,
        normalizers,
        obligations,
        cell.profile,
        cell.platform,
        cell.proposed_status,
    ))
}

fn canonical_string_array(values: &[String]) -> String {
    let mut output = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        push_json(&mut output, value);
    }
    output.push(']');
    output
}

fn exception_queues(
    cells: &[crate::assurance::FinalizedClaimCell],
    groups: &BTreeMap<String, GroupBinding>,
) -> Result<Vec<ExceptionQueue>, String> {
    let coverage_source = queue_source(COVERAGE)?;
    let ambiguous = cell_queue(
        "ambiguous-applicability",
        &coverage_source,
        cells
            .iter()
            .filter(|cell| cell.applicability_decision_sha256.is_some()),
    );
    let normalizers = cell_queue(
        "normalizer-applications",
        &coverage_source,
        cells.iter().filter(|cell| !cell.normalizer_ids.is_empty()),
    );
    let divergences = cell_queue(
        "accepted-divergences",
        &coverage_source,
        cells
            .iter()
            .filter(|cell| cell.proposed_status == "deliberate-divergence"),
    );
    let platform_differences = cell_queue(
        "platform-raw-differences",
        &coverage_source,
        cells
            .iter()
            .filter(|cell| cell.proposed_status == "platform-dependent"),
    );
    let heuristic = cell_queue(
        "heuristically-grouped-rows",
        &coverage_source,
        cells
            .iter()
            .filter(|cell| cell.applicability.contains("heuristic")),
    );
    let high_risk_families = high_risk_family_queue(cells, groups, &coverage_source)?;
    let mut one_case_records = Vec::new();
    for (group, binding) in groups {
        let case_ids = claim_group_case_ids(cells, group)?;
        if case_ids.len() == 1 {
            one_case_records.push(QueueRecord {
                id: group.clone(),
                retained_refs: case_ids
                    .into_iter()
                    .chain([cell_set_digest(binding), evidence_set_digest(binding)])
                    .collect(),
            });
        }
    }
    let one_case = ExceptionQueue {
        id: "one-case-claim-groups",
        sources: vec![coverage_source.clone()],
        records: one_case_records,
    };
    Ok(vec![
        ambiguous,
        normalizers,
        divergences,
        high_risk_families,
        ExceptionQueue {
            id: "weak-mutation-families",
            sources: vec![queue_source(
                "ci-out/evidence/coverage/mutation-score.json",
            )?],
            records: Vec::new(),
        },
        platform_differences,
        ExceptionQueue {
            id: "source-build-warnings",
            sources: vec![
                queue_source("ci-out/evidence/provenance/macos-arm64/oracle-provenance.json")?,
                queue_source("ci-out/evidence/provenance/windows-amd64/oracle-provenance.json")?,
            ],
            records: Vec::new(),
        },
        ExceptionQueue {
            id: "custody-identity-warnings",
            sources: vec![
                queue_source("ci-out/evidence/custody/custody-receipt.json")?,
                queue_source(ROLE_GRAPH)?,
            ],
            records: Vec::new(),
        },
        one_case,
        heuristic,
    ])
}

fn high_risk_family_queue(
    cells: &[crate::assurance::FinalizedClaimCell],
    groups: &BTreeMap<String, GroupBinding>,
    source: &QueueSource,
) -> Result<ExceptionQueue, String> {
    let mut families = BTreeMap::<String, BTreeSet<String>>::new();
    for cell in cells {
        let spec = hell_builtins::registry()
            .iter()
            .find(|spec| spec.name == cell.builtin)
            .ok_or_else(|| {
                format!(
                    "high-risk queue references unknown builtin {:?}",
                    cell.builtin
                )
            })?;
        let metadata = spec.assurance_metadata();
        if metadata.capabilities.is_empty()
            && metadata.sensitivities.is_empty()
            && metadata.source_reachability != hell_builtins::SourceReachability::GeneratedOnly
        {
            continue;
        }
        let group = claim_group_id(cell)?;
        if !groups.contains_key(&group) {
            return Err("high-risk queue lost a finalized claim group".to_owned());
        }
        families
            .entry(metadata.semantic_family.to_owned())
            .or_default()
            .extend([
                format!(
                    "{}:{}:{}:{}:{}",
                    cell.builtin, cell.dimension, cell.profile, cell.platform, cell.proposed_status
                ),
                sha256_bytes(cell.canonical_json.as_bytes()).hex(),
                group,
            ]);
    }
    Ok(ExceptionQueue {
        id: "high-risk-semantic-families",
        sources: vec![source.clone()],
        records: families
            .into_iter()
            .map(|(id, retained_refs)| QueueRecord {
                id,
                retained_refs: retained_refs.into_iter().collect(),
            })
            .collect(),
    })
}

fn claim_group_case_ids(
    cells: &[crate::assurance::FinalizedClaimCell],
    group_id: &str,
) -> Result<BTreeSet<String>, String> {
    let mut case_ids = BTreeSet::new();
    for cell in cells {
        if claim_group_id(cell)? == group_id {
            case_ids.extend(
                cell.evidence_refs
                    .iter()
                    .map(|reference| reference.case_id.clone()),
            );
        }
    }
    Ok(case_ids)
}

fn queue_source(path: &str) -> Result<QueueSource, String> {
    Ok(QueueSource {
        path: strip_evidence_prefix(path)?.to_owned(),
        sha256: file_digest(Path::new(path))?,
    })
}

fn cell_queue<'a>(
    id: &'static str,
    source: &QueueSource,
    cells: impl Iterator<Item = &'a crate::assurance::FinalizedClaimCell>,
) -> ExceptionQueue {
    ExceptionQueue {
        id,
        sources: vec![source.clone()],
        records: cells.map(cell_queue_record).collect(),
    }
}

fn cell_queue_record(cell: &crate::assurance::FinalizedClaimCell) -> QueueRecord {
    let mut retained_refs = Vec::new();
    for reference in &cell.evidence_refs {
        retained_refs.extend([
            reference.sha256.clone(),
            reference.bundle_path.clone(),
            reference.bundle_sha256.clone(),
            reference.case_id.clone(),
            canonical_string_array(&reference.obligations),
        ]);
    }
    retained_refs.extend(cell.normalizer_ids.iter().cloned());
    retained_refs.extend(cell.normalizer_application_refs.iter().cloned());
    if let Some(digest) = &cell.applicability_decision_sha256 {
        retained_refs.push(digest.clone());
    }
    if let Some(reference) = &cell.divergence_record_ref {
        retained_refs.push(reference.clone());
    }
    QueueRecord {
        id: format!(
            "{}:{}:{}:{}:{}",
            cell.builtin, cell.dimension, cell.profile, cell.platform, cell.proposed_status
        ),
        retained_refs,
    }
}

fn component_review_set_digest(components: &[VerifiedComponent]) -> Result<String, String> {
    let mut framed = String::new();
    for component in components {
        for value in [
            component.kind,
            component.bound,
            &component.bound_digest,
            &component.review_digest,
            &component.subject,
            &component.fingerprint,
        ] {
            framed.push_str(value);
            framed.push('\n');
        }
    }
    framed.push_str(&file_digest(Path::new(PROVIDER_ARTIFACTS))?);
    framed.push('\n');
    Ok(sha256_bytes(framed.as_bytes()).hex())
}

fn group_review_bindings(
    groups: &BTreeMap<String, GroupBinding>,
    review_set: &str,
) -> BTreeSet<String> {
    if crate::assurance_control_mutant_active("post-collection-obligation-removal") {
        return groups.keys().cloned().collect();
    }
    groups
        .iter()
        .map(|(group, binding)| {
            format!(
                "{group}\n{}\n{}\n{review_set}",
                cell_set_digest(binding),
                evidence_set_digest(binding)
            )
        })
        .collect()
}

fn render_subject(
    candidate: &str,
    epoch: &str,
    groups: &BTreeMap<String, GroupBinding>,
    review_set: &str,
    packet_sha256: &str,
) -> Result<String, String> {
    let mut output = String::from("{\n  \"schemaVersion\": 1,\n  \"candidateSourceCommit\": ");
    push_json(&mut output, candidate);
    output.push_str(",\n  \"assuranceEpochSha256\": ");
    push_json(&mut output, epoch);
    output.push_str(",\n  \"claimGroups\": [");
    for (index, (group, binding)) in groups.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("\n    {\"groupId\": ");
        push_json(&mut output, group);
        output.push_str(", \"cellSetSha256\": ");
        push_json(&mut output, &cell_set_digest(binding));
        output.push_str(", \"evidenceSetSha256\": ");
        push_json(&mut output, &evidence_set_digest(binding));
        output.push_str(", \"reviewSetSha256\": ");
        push_json(&mut output, review_set);
        output.push('}');
    }
    output.push_str(
        "\n  ],\n  \"roleGraphPath\": \"review/role-graph.details.json\",\n  \"roleGraphSha256\": ",
    );
    push_json(&mut output, &file_digest(Path::new(ROLE_GRAPH))?);
    output.push_str(
        ",\n  \"packetPath\": \"promotion-review-packet/packet.sha256\",\n  \"packetSha256\": ",
    );
    push_json(&mut output, packet_sha256);
    output.push_str("\n}\n");
    Ok(output)
}

fn build_offline_packet(
    candidate: &str,
    epoch: &str,
    cells: &[crate::assurance::FinalizedClaimCell],
    groups: &BTreeMap<String, GroupBinding>,
    components: &[VerifiedComponent],
    queues: &[ExceptionQueue],
) -> Result<String, String> {
    let root = Path::new(PACKET_ROOT);
    if root.exists() {
        return Err("offline review packet output already exists".to_owned());
    }
    let claim_group_attachments = root.join("attachments").join("claim-groups");
    fs::create_dir_all(&claim_group_attachments)
        .map_err(|error| format!("cannot create offline packet: {error}"))?;
    let summary = render_prepacket(candidate, epoch, groups, components);
    write_atomic(&root.join("packet.json"), summary.as_bytes())?;
    let group_map = render_claim_group_map(candidate, epoch, cells, groups)?;
    write_atomic(
        &claim_group_attachments.join("claim-group-map.json"),
        group_map.as_bytes(),
    )?;
    let exception_queue = render_exception_queues(candidate, epoch, queues);
    write_atomic(
        &claim_group_attachments.join("exception-queues.json"),
        exception_queue.as_bytes(),
    )?;
    copy_attachment(
        Path::new(ROLE_GRAPH),
        &claim_group_attachments.join("role-graph.details.json"),
    )?;
    for review in REVIEWS {
        let attachment = match review.kind {
            "claim-coverage" => "claim-groups",
            "normalizer-audit" => "normalizer-audits",
            "divergence" => "divergence-packets",
            "residual-risk" => "residual-risk",
            _ => unreachable!("review inputs are fixed"),
        };
        let directory = root.join("attachments").join(attachment);
        fs::create_dir_all(&directory)
            .map_err(|error| format!("cannot create {}: {error}", directory.display()))?;
        copy_attachment(Path::new(review.details), &directory.join("details.json"))?;
        copy_attachment(
            Path::new(review.bound),
            &directory.join("bound-review.json"),
        )?;
        copy_attachment(
            Path::new(review.review),
            &directory.join("review.dsse.json"),
        )?;
        copy_attachment(
            Path::new(review.authorization),
            &directory.join("authorization.json"),
        )?;
    }
    for (source, destination) in [
        (
            "ci-out/evidence/acquisition",
            "attachments/acquisition-reports",
        ),
        (
            "ci-out/evidence/provenance",
            "attachments/provenance-reports",
        ),
        ("ci-out/evidence/native", "attachments/case-observations"),
        ("ci-out/evidence/custody", "attachments/custody-receipts"),
        ("ci-out/evidence/coverage", "attachments/semantic-coverage"),
        ("ci-out/evidence/review", "attachments/review-records"),
    ] {
        copy_tree(Path::new(source), &root.join(destination))?;
    }
    for attachment in [
        "acquisition-reports",
        "provenance-reports",
        "case-observations",
        "custody-receipts",
        "semantic-coverage",
        "review-records",
    ] {
        write_attachment_index(&root.join("attachments").join(attachment))?;
    }
    let pages = [
        ("01-scope-summary.html", "Scope summary"),
        ("02-artifact-authenticity.html", "Artifact authenticity"),
        ("03-oracle-provenance.html", "Oracle provenance"),
        ("04-claim-worklist.html", "Claim worklist"),
        ("05-semantic-coverage.html", "Semantic coverage"),
        ("06-normalizers.html", "Normalizers"),
        ("07-divergences.html", "Divergences"),
        ("08-custody.html", "Custody"),
        ("09-role-independence.html", "Role independence"),
        ("10-residual-risk.html", "Residual risk"),
    ];
    for (name, title) in pages {
        let page = static_page(title, candidate, groups.len(), queues);
        write_atomic(&root.join(name), page.as_bytes())?;
    }
    let index = render_index(candidate, epoch, &pages);
    write_atomic(&root.join("index.html"), index.as_bytes())?;
    let manifest = packet_file_manifest(root)?;
    write_atomic(&root.join("packet.sha256"), manifest.as_bytes())?;
    verify_offline_links(root)?;
    file_digest(&root.join("packet.sha256"))
}

fn verify_packet_manifest() -> Result<String, String> {
    let root = Path::new(PACKET_ROOT);
    let expected = packet_file_manifest(root)?;
    let retained = read(&root.join("packet.sha256"))?;
    if retained != expected {
        return Err("offline packet manifest is stale or has extra payload bytes".to_owned());
    }
    file_digest(&root.join("packet.sha256"))
}

fn render_prepacket(
    candidate: &str,
    epoch: &str,
    groups: &BTreeMap<String, GroupBinding>,
    components: &[VerifiedComponent],
) -> String {
    let mut output = String::from("{\n  \"schemaVersion\": 1,\n  \"candidateSourceCommit\": ");
    push_json(&mut output, candidate);
    output.push_str(",\n  \"assuranceEpochSha256\": ");
    push_json(&mut output, epoch);
    write!(
        output,
        ",\n  \"claimGroupCount\": {},\n  \"reviewComponentCount\": {},\n  \"state\": \"ready-for-review-graph-signature\"\n}}\n",
        groups.len(),
        components.len()
    )
    .expect("writing to String cannot fail");
    output
}

fn render_claim_group_map(
    candidate: &str,
    epoch: &str,
    cells: &[crate::assurance::FinalizedClaimCell],
    groups: &BTreeMap<String, GroupBinding>,
) -> Result<String, String> {
    let mut output = String::from("{\n  \"schemaVersion\": 1,\n  \"candidateSourceCommit\": ");
    push_json(&mut output, candidate);
    output.push_str(",\n  \"assuranceEpochSha256\": ");
    push_json(&mut output, epoch);
    output.push_str(",\n  \"mappings\": [");
    let mut mappings = Vec::new();
    for cell in cells {
        let group_id = claim_group_id(cell)?;
        if !groups.contains_key(&group_id) {
            return Err("claim-group map lost a finalized cell".to_owned());
        }
        let cell_id = [
            cell.builtin.as_str(),
            cell.dimension.as_str(),
            cell.platform.as_str(),
            cell.proposed_status.as_str(),
        ]
        .join(":");
        mappings.push((cell_id, group_id, cell.proposed_status.clone()));
    }
    mappings.sort();
    for (index, (cell_id, group_id, status)) in mappings.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("\n    {\"claimCellId\": ");
        push_json(&mut output, cell_id);
        output.push_str(", \"reviewGroupId\": ");
        push_json(&mut output, group_id);
        output.push_str(", \"publicStatementId\": ");
        push_json(
            &mut output,
            &format!("bounded-compatibility-report/claim-scope-cells/{status}"),
        );
        output.push('}');
    }
    output.push_str("\n  ]\n}\n");
    Ok(output)
}

fn render_exception_queues(candidate: &str, epoch: &str, queues: &[ExceptionQueue]) -> String {
    let mut output = String::from("{\n  \"schemaVersion\": 1,\n  \"candidateSourceCommit\": ");
    push_json(&mut output, candidate);
    output.push_str(",\n  \"assuranceEpochSha256\": ");
    push_json(&mut output, epoch);
    output.push_str(",\n  \"queues\": [");
    for (queue_index, queue) in queues.iter().enumerate() {
        if queue_index != 0 {
            output.push(',');
        }
        output.push_str("\n    {\"queueId\": ");
        push_json(&mut output, queue.id);
        write!(
            output,
            ", \"recordCount\": {}, \"sources\": [",
            queue.records.len()
        )
        .expect("writing to String cannot fail");
        for (source_index, source) in queue.sources.iter().enumerate() {
            if source_index != 0 {
                output.push(',');
            }
            output.push_str("{\"path\": ");
            push_json(&mut output, &source.path);
            output.push_str(", \"sha256\": ");
            push_json(&mut output, &source.sha256);
            output.push('}');
        }
        output.push_str("], \"records\": [");
        for (record_index, record) in queue.records.iter().enumerate() {
            if record_index != 0 {
                output.push(',');
            }
            output.push_str("{\"recordId\": ");
            push_json(&mut output, &record.id);
            output.push_str(", \"retainedRefs\": ");
            output.push_str(&canonical_string_array(&record.retained_refs));
            output.push('}');
        }
        output.push_str("]}");
    }
    output.push_str("\n  ]\n}\n");
    output
}

fn static_page(
    title: &str,
    candidate: &str,
    group_count: usize,
    queues: &[ExceptionQueue],
) -> String {
    let (question, evidence, queue) = match title {
        "Scope summary" => (
            "Are repository, workflow, release, profile, and platform scopes exact?",
            "attachments/semantic-coverage/claim-coverage.finalized.json",
            "Inspect ambiguous applicability, missing obligations, and one-case-only groups.",
        ),
        "Artifact authenticity" => (
            "Do both acquisition channels bind the same provider bytes and identities?",
            "attachments/acquisition-reports/_packet-index.html",
            "Inspect absent attestations, provider substitutions, and trust-domain overlap.",
        ),
        "Oracle provenance" => (
            "Do independent macOS and Windows plans rebuild the selected upstream source?",
            "attachments/provenance-reports/_packet-index.html",
            "Inspect source-acquisition, network, SBOM, warning, and binary-binding failures.",
        ),
        "Claim worklist" => (
            "Is every assurance-equivalence group applicable and fully represented?",
            "attachments/claim-groups/details.json",
            "Inspect heuristic groups, group exceptions, platform differences, and low evidence diversity.",
        ),
        "Semantic coverage" => (
            "Does every promoted cell have causal evidence for every required obligation?",
            "attachments/case-observations/_packet-index.html",
            "Inspect missing targets, negative/boundary gaps, and generated-only cases.",
        ),
        "Normalizers" => (
            "Does each normalizer remove only reviewed nondeterminism?",
            "attachments/normalizer-audits",
            "Inspect protected-field changes, failed mutants, and unaudited applications.",
        ),
        "Divergences" => (
            "Is every retained mismatch narrowly fingerprinted, unexpired, and approved?",
            "attachments/divergence-packets",
            "Inspect changed fingerprints, expiring records, wildcard scopes, and impact approvals.",
        ),
        "Custody" => (
            "Are both immutable copies independently retrievable for the policy duration?",
            "attachments/custody-receipts/_packet-index.html",
            "Inspect missing versions, retention gaps, corrupt objects, and identity reuse.",
        ),
        "Role independence" => (
            "Do provider facts prove the required roles and separation of duties?",
            "attachments/claim-groups/role-graph.details.json",
            "Inspect policy violations, duplicate stable accounts, reused keys, and stale authorization.",
        ),
        "Residual risk" => (
            "Is the retained residual risk compatible with the bounded public statement?",
            "attachments/residual-risk",
            "Inspect unverified/out-of-scope cells, weak mutation families, and unresolved findings.",
        ),
        _ => unreachable!("packet page titles are fixed"),
    };
    let relevant = page_queue_ids(title);
    let mut generated = String::from("<ul>");
    for queue_id in relevant {
        let retained = queues
            .iter()
            .find(|candidate| candidate.id == *queue_id)
            .expect("page queue IDs are fixed");
        write!(
            generated,
            "<li><code>{}</code>: {} exact record(s)<ul>",
            retained.id,
            retained.records.len()
        )
        .expect("writing to String cannot fail");
        if retained.records.is_empty() {
            generated.push_str("<li>none</li>");
        } else {
            for record in &retained.records {
                write!(generated, "<li><code>{}</code></li>", html_atom(&record.id))
                    .expect("writing to String cannot fail");
            }
        }
        generated.push_str("</ul></li>");
    }
    generated.push_str("</ul>");
    format!(
        "<!doctype html>\n<html lang=\"en\"><meta charset=\"utf-8\"><title>{title}</title><body><h1>{title}</h1><p>Candidate <code>{candidate}</code>.</p><p>Exact assurance-equivalence claim groups: {group_count}.</p><h2>Required decision</h2><p>{question}</p><h2>Generated exception queues</h2><p>{queue}</p>{generated}<p><a href=\"attachments/claim-groups/exception-queues.json\">Open the exact queue records and source digests</a></p><h2>Retained evidence</h2><p><a href=\"{evidence}\">Open exact evidence</a></p><p><a href=\"index.html\">Packet index</a> · <a href=\"attachments/claim-groups/role-graph.details.json\">Role graph</a></p></body></html>\n"
    )
}

fn html_atom(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            character => output.push(character),
        }
    }
    output
}

fn page_queue_ids(title: &str) -> &'static [&'static str] {
    match title {
        "Scope summary" => &["ambiguous-applicability", "heuristically-grouped-rows"],
        "Artifact authenticity" | "Custody" | "Role independence" => &["custody-identity-warnings"],
        "Oracle provenance" => &["source-build-warnings"],
        "Claim worklist" => &[
            "ambiguous-applicability",
            "high-risk-semantic-families",
            "one-case-claim-groups",
            "heuristically-grouped-rows",
        ],
        "Semantic coverage" => &["one-case-claim-groups", "platform-raw-differences"],
        "Normalizers" => &["normalizer-applications"],
        "Divergences" => &["accepted-divergences", "platform-raw-differences"],
        "Residual risk" => &["high-risk-semantic-families", "weak-mutation-families"],
        _ => unreachable!("packet page titles are fixed"),
    }
}

fn render_index(candidate: &str, epoch: &str, pages: &[(&str, &str)]) -> String {
    let mut output = format!(
        "<!doctype html>\n<html lang=\"en\"><meta charset=\"utf-8\"><title>Promotion review packet</title><body><h1>Promotion review packet</h1><p>Candidate <code>{candidate}</code>; assurance epoch <code>{epoch}</code>.</p><ol>"
    );
    for (name, title) in pages {
        write!(output, "<li><a href=\"{name}\">{title}</a></li>")
            .expect("writing to String cannot fail");
    }
    output.push_str("</ol><h2>Explicit reviewer decisions</h2><ol>");
    for question in packet_summary_questions() {
        write!(output, "<li>{question}</li>").expect("writing to String cannot fail");
    }
    output.push_str("</ol><p>Each decision must be made from the exact digested attachments and generated exception queues; workflow success is not an answer.</p><p><a href=\"packet.json\">Machine-readable packet</a> · <a href=\"packet.sha256\">Integrity manifest</a></p></body></html>\n");
    output
}

fn packet_summary_questions() -> &'static [&'static str] {
    &[
        "Are the repository, workflow, run, release, and upstream identities trusted for this promotion?",
        "Do native macOS and Windows build plans faithfully represent the selected upstream baseline?",
        "Are all claim applicability decisions correct for the declared profile and platform scope?",
        "Does each exact or normalized claim have a representative obligation set?",
        "Does each normalizer remove only irrelevant nondeterminism?",
        "Is each deliberate divergence acceptable and narrowly scoped?",
        "Are durable evidence copies independently retrievable under the required retention policy?",
        "Does the reviewer role graph satisfy authorization and independence policy?",
        "Is the residual risk acceptable under the bounded public statement?",
    ]
}

fn write_attachment_index(directory: &Path) -> Result<(), String> {
    let mut files = Vec::new();
    collect_attachment_files(directory, directory, &mut files)?;
    files.sort();
    if files.is_empty() {
        return Err(format!(
            "offline packet attachment directory is empty: {}",
            directory.display()
        ));
    }
    let mut output = String::from(
        "<!doctype html>\n<html lang=\"en\"><meta charset=\"utf-8\"><title>Retained attachment files</title><body><h1>Retained attachment files</h1><ul>",
    );
    for relative in files {
        require_safe_html_path(&relative)?;
        write!(output, "<li><a href=\"{relative}\">{relative}</a></li>")
            .expect("writing to String cannot fail");
    }
    output.push_str("</ul></body></html>\n");
    write_atomic(&directory.join("_packet-index.html"), output.as_bytes())
}

fn collect_attachment_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<String>,
) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read attachment entry: {error}"))?;
        let kind = entry
            .file_type()
            .map_err(|error| format!("cannot inspect attachment entry: {error}"))?;
        if kind.is_symlink() {
            return Err("offline packet attachment cannot contain symlinks".to_owned());
        }
        let path = entry.path();
        if kind.is_dir() {
            collect_attachment_files(root, &path, files)?;
        } else if kind.is_file()
            && path
                .file_name()
                .is_none_or(|name| name != "_packet-index.html")
        {
            files.push(
                path.strip_prefix(root)
                    .map_err(|_| "attachment path escaped its root".to_owned())?
                    .to_str()
                    .ok_or_else(|| "attachment path is not UTF-8".to_owned())?
                    .replace('\\', "/"),
            );
        }
    }
    Ok(())
}

fn require_safe_html_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.starts_with('/')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || path.chars().any(|character| {
            character.is_control() || matches!(character, '<' | '>' | '&' | '"' | '\'')
        })
    {
        return Err("attachment path is unsafe for deterministic offline HTML".to_owned());
    }
    Ok(())
}

fn copy_attachment(source: &Path, destination: &Path) -> Result<(), String> {
    fs::copy(source, destination)
        .map(|_| ())
        .map_err(|error| format!("cannot copy {}: {error}", source.display()))
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source).map_err(|error| {
        format!(
            "cannot inspect required packet source {}: {error}",
            source.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err("offline packet source cannot be a symlink".to_owned());
    }
    if metadata.is_file() {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        return copy_attachment(source, destination);
    }
    if !metadata.is_dir() {
        return Err("offline packet source is not a file or directory".to_owned());
    }
    fs::create_dir_all(destination)
        .map_err(|error| format!("cannot create {}: {error}", destination.display()))?;
    let mut entries = fs::read_dir(source)
        .map_err(|error| format!("cannot read {}: {error}", source.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot enumerate {}: {error}", source.display()))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        copy_tree(&entry.path(), &destination.join(entry.file_name()))?;
    }
    Ok(())
}

fn packet_file_manifest(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    collect_packet_files(root, root, &mut files)?;
    files.sort();
    let mut output = String::new();
    for relative in files {
        let path = root.join(&relative);
        writeln!(output, "{}  {}", file_digest(&path)?, relative)
            .expect("writing to String cannot fail");
    }
    Ok(output)
}

fn collect_packet_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<String>,
) -> Result<(), String> {
    let entries = fs::read_dir(directory).map_err(|error| {
        format!(
            "cannot read packet directory {}: {error}",
            directory.display()
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read packet entry: {error}"))?;
        let metadata = entry
            .file_type()
            .map_err(|error| format!("cannot inspect packet entry: {error}"))?;
        if metadata.is_symlink() {
            return Err("offline packet cannot contain symlinks".to_owned());
        }
        let path = entry.path();
        if metadata.is_dir() {
            collect_packet_files(root, &path, files)?;
        } else if metadata.is_file() && path.file_name().is_none_or(|name| name != "packet.sha256")
        {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "packet file escaped its root".to_owned())?;
            let relative = relative
                .to_str()
                .ok_or_else(|| "packet path is not UTF-8".to_owned())?;
            if relative
                .split('/')
                .any(|component| component.is_empty() || component == "..")
            {
                return Err("packet path is not an offline-safe relative path".to_owned());
            }
            files.push(relative.to_owned());
        }
    }
    Ok(())
}

fn verify_offline_links(root: &Path) -> Result<(), String> {
    let mut files = Vec::new();
    collect_packet_files(root, root, &mut files)?;
    for relative in files.iter().filter(|path| {
        Path::new(path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("html"))
    }) {
        let page = read(&root.join(relative))?;
        let mut rest = page.as_str();
        while let Some(start) = rest.find("href=\"") {
            rest = &rest[start.saturating_add("href=\"".len())..];
            let end = rest
                .find('"')
                .ok_or_else(|| "offline packet contains an unterminated link".to_owned())?;
            let link = &rest[..end];
            if link.is_empty()
                || link.contains("://")
                || Path::new(link).is_absolute()
                || link.split('/').any(|component| component == "..")
                || !root.join(link).exists()
            {
                return Err(format!(
                    "offline packet link {link:?} is not locally resolvable"
                ));
            }
            rest = &rest[end.saturating_add(1)..];
        }
    }
    Ok(())
}

fn render_packet(
    candidate: &str,
    epoch: &str,
    components: &[VerifiedComponent],
    group_count: usize,
) -> Result<String, String> {
    let mut output = String::from("{\n  \"schemaVersion\": 1,\n  \"candidateSourceCommit\": ");
    push_json(&mut output, candidate);
    output.push_str(",\n  \"assuranceEpochSha256\": ");
    push_json(&mut output, epoch);
    output.push_str(",\n  \"graphReviewSubjectPath\": \"review/graph-review-subject.json\",\n  \"graphReviewSubjectSha256\": ");
    push_json(&mut output, &file_digest(Path::new(SUBJECT))?);
    output.push_str(",\n  \"claimGroupReviewPath\": \"review/auth/role-graph/review.dsse.json\",\n  \"claimGroupReviewSha256\": ");
    push_json(&mut output, &file_digest(Path::new(GROUP_REVIEW))?);
    write!(
        output,
        ",\n  \"claimGroupCount\": {group_count},\n  \"reviewComponents\": ["
    )
    .expect("writing to String cannot fail");
    for (index, component) in components.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("\n    {\"kind\": ");
        push_json(&mut output, component.kind);
        output.push_str(", \"boundPath\": ");
        push_json(&mut output, strip_evidence_prefix(component.bound)?);
        output.push_str(", \"boundSha256\": ");
        push_json(&mut output, &component.bound_digest);
        output.push_str(", \"reviewSha256\": ");
        push_json(&mut output, &component.review_digest);
        output.push_str(", \"reviewerSubject\": ");
        push_json(&mut output, &component.subject);
        output.push_str(", \"signerFingerprint\": ");
        push_json(&mut output, &component.fingerprint);
        output.push('}');
    }
    output.push_str("\n  ],\n  \"verificationState\": \"exact-groups-dual-signed\"\n}\n");
    Ok(output)
}

fn cell_set_digest(group: &GroupBinding) -> String {
    let mut framed = group.identity.clone();
    for cell in &group.cells {
        framed.push_str(cell);
    }
    sha256_bytes(framed.as_bytes()).hex()
}

fn evidence_set_digest(group: &GroupBinding) -> String {
    let mut framed = group.identity.clone();
    for evidence in &group.evidence {
        framed.push_str(evidence);
    }
    sha256_bytes(framed.as_bytes()).hex()
}

fn quoted_field(document: &str, field: &str) -> Result<String, String> {
    let marker = format!("\"{field}\": \"");
    let start = document
        .find(&marker)
        .ok_or_else(|| format!("missing exact field {field}"))?
        .saturating_add(marker.len());
    let tail = &document[start..];
    let end = tail
        .find('"')
        .ok_or_else(|| format!("unterminated exact field {field}"))?;
    let value = &tail[..end];
    if value.contains('\\') || value.chars().any(char::is_control) {
        return Err(format!("exact field {field} is not a plain canonical atom"));
    }
    Ok(value.to_owned())
}

fn number_field(document: &str, field: &str) -> Result<u64, String> {
    let marker = format!("\"{field}\": ");
    let start = document
        .find(&marker)
        .ok_or_else(|| format!("missing exact number {field}"))?
        .saturating_add(marker.len());
    let digits = document[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>();
    if digits.is_empty() {
        return Err(format!("exact number {field} is malformed"));
    }
    digits
        .parse::<u64>()
        .map_err(|_| format!("exact number {field} exceeds u64"))
}

fn require_group_atom(value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err("claim-group identity contains an unsafe component".to_owned());
    }
    Ok(())
}

fn require_git_sha(value: &str) -> Result<(), String> {
    let exemplar = git_output(&["rev-parse", "HEAD"])?;
    if value.len() != exemplar.trim().len()
        || !value.chars().all(|character| character.is_ascii_hexdigit())
    {
        return Err("claim-group candidate is not a full Git object identity".to_owned());
    }
    Ok(())
}

fn require_digest(value: &str) -> Result<(), String> {
    let exemplar = sha256_bytes(b"digest-length-exemplar").hex();
    if value.len() != exemplar.len()
        || !value
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        return Err("claim-group binding is not a lowercase SHA-256 digest".to_owned());
    }
    Ok(())
}

fn strip_evidence_prefix(path: &str) -> Result<&str, String> {
    path.strip_prefix("ci-out/evidence/")
        .ok_or_else(|| "offline review path is outside the retained evidence root".to_owned())
}

fn file_digest(path: &Path) -> Result<String, String> {
    sha256_file(path)
        .map(hell_testkit::Digest::hex)
        .map_err(|error| format!("cannot digest {}: {error}", path.display()))
}

fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn git_output(arguments: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new("git")
        .args(arguments)
        .output()
        .map_err(|error| format!("cannot run git: {error}"))?;
    output.status.success().then_some(()).ok_or_else(|| {
        format!(
            "git command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    })?;
    String::from_utf8(output.stdout).map_err(|_| "git output is not UTF-8".to_owned())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    let mut temporary = PathBuf::from(path);
    temporary.set_extension("tmp");
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

    fn finalized_cell(builtin: &str, dimension: &str) -> crate::assurance::FinalizedClaimCell {
        crate::assurance::FinalizedClaimCell {
            builtin: builtin.to_owned(),
            dimension: dimension.to_owned(),
            profile: "upstream".to_owned(),
            platform: "linux-amd64".to_owned(),
            applicability: "applicable".to_owned(),
            applicability_decision_sha256: None,
            proposed_status: "exact".to_owned(),
            canonical_json: "{\"cell\":\"exact\"}".to_owned(),
            evidence_refs: vec![crate::assurance::FinalizedClaimEvidenceRef {
                canonical_json: "{\"bundlePath\":\"one\"}".to_owned(),
                sha256: sha256_bytes(b"reference").hex(),
                bundle_path: "native/one".to_owned(),
                bundle_sha256: sha256_bytes(b"bundle").hex(),
                case_id: "case-one".to_owned(),
                obligations: vec!["evaluation".to_owned()],
            }],
            normalizer_ids: Vec::new(),
            normalizer_application_refs: Vec::new(),
            obligations: vec!["evaluation".to_owned()],
            divergence_record_ref: None,
        }
    }

    #[test]
    fn claim_cells_are_partitioned_into_exact_platform_dimension_groups() {
        let builtin = hell_builtins::registry()[0].name;
        let groups = claim_groups(&[finalized_cell(builtin, "effects")]).unwrap();
        assert_eq!(groups.len(), 1);
        let binding = groups.values().next().unwrap();
        assert_eq!(binding.cells.len(), 1);
        assert_ne!(cell_set_digest(binding), evidence_set_digest(binding));
    }

    #[test]
    fn malformed_or_injected_group_fields_fail_closed() {
        let builtin = hell_builtins::registry()[0].name;
        assert!(claim_groups(&[finalized_cell(builtin, "effects/forged")]).is_err());
        assert!(claim_groups(&[finalized_cell("forged", "effects")]).is_err());
    }

    #[test]
    fn manifest_changes_when_any_cell_evidence_or_review_changes() {
        let mut groups = BTreeMap::new();
        groups.insert(
            "effects/upstream/linux-amd64".to_owned(),
            GroupBinding {
                identity: "echo\neffects\nupstream\nlinux-amd64\n".to_owned(),
                cells: vec!["cell-one\n".to_owned()],
                evidence: vec!["[]\n".to_owned()],
            },
        );
        let first = group_review_bindings(&groups, "review-one");
        groups
            .get_mut("effects/upstream/linux-amd64")
            .unwrap()
            .evidence[0] = "[evidence]\n".to_owned();
        let second = group_review_bindings(&groups, "review-one");
        let third = group_review_bindings(&groups, "review-two");
        assert_ne!(first, second);
        assert_ne!(second, third);
    }

    #[test]
    fn attachment_index_paths_are_offline_safe() {
        assert!(require_safe_html_path("provider/receipt.json").is_ok());
        assert!(require_safe_html_path("../receipt.json").is_err());
        assert!(require_safe_html_path("provider/<receipt>.json").is_err());
        assert!(require_safe_html_path("provider/receipt\n.json").is_err());
    }

    #[test]
    fn appendix_exception_classifiers_enumerate_exact_cells() {
        let builtin = hell_builtins::registry()[0].name;
        let mut cell = finalized_cell(builtin, "effects");
        cell.applicability = "ambiguous-needs-review".to_owned();
        cell.applicability_decision_sha256 = Some(sha256_bytes(b"applicability").hex());
        cell.proposed_status = "deliberate-divergence".to_owned();
        cell.normalizer_ids = vec!["diagnostic-path-v1".to_owned()];
        cell.normalizer_application_refs = vec![sha256_bytes(b"application").hex()];
        cell.divergence_record_ref = Some(sha256_bytes(b"divergence").hex());
        let source = QueueSource {
            path: "coverage/claim-coverage.finalized.json".to_owned(),
            sha256: sha256_bytes(b"coverage").hex(),
        };
        for (id, matched) in [
            (
                "ambiguous-applicability",
                cell_queue(
                    "ambiguous-applicability",
                    &source,
                    [&cell]
                        .into_iter()
                        .filter(|cell| cell.applicability_decision_sha256.is_some()),
                ),
            ),
            (
                "normalizer-applications",
                cell_queue(
                    "normalizer-applications",
                    &source,
                    [&cell]
                        .into_iter()
                        .filter(|cell| !cell.normalizer_ids.is_empty()),
                ),
            ),
            (
                "accepted-divergences",
                cell_queue(
                    "accepted-divergences",
                    &source,
                    [&cell]
                        .into_iter()
                        .filter(|cell| cell.proposed_status == "deliberate-divergence"),
                ),
            ),
        ] {
            assert_eq!(matched.id, id);
            assert_eq!(matched.records.len(), 1);
            assert!(!matched.records[0].retained_refs.is_empty());
        }
    }

    #[test]
    fn every_required_exception_queue_is_rendered_on_a_packet_page() {
        let pages = [
            "Scope summary",
            "Artifact authenticity",
            "Oracle provenance",
            "Claim worklist",
            "Semantic coverage",
            "Normalizers",
            "Divergences",
            "Custody",
            "Role independence",
            "Residual risk",
        ];
        let observed = pages
            .into_iter()
            .flat_map(page_queue_ids)
            .copied()
            .collect::<BTreeSet<_>>();
        let expected = [
            "ambiguous-applicability",
            "normalizer-applications",
            "accepted-divergences",
            "high-risk-semantic-families",
            "weak-mutation-families",
            "platform-raw-differences",
            "source-build-warnings",
            "custody-identity-warnings",
            "one-case-claim-groups",
            "heuristically-grouped-rows",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(observed, expected);
        assert_eq!(html_atom("Ord.<&"), "Ord.&lt;&amp;");
    }

    #[test]
    fn packet_index_requires_every_explicit_summary_decision() {
        let pages = [("01-scope-summary.html", "Scope summary")];
        let index = render_index("candidate", "epoch", &pages);
        assert_eq!(packet_summary_questions().len(), 9);
        for question in packet_summary_questions() {
            assert!(
                index.contains(question),
                "packet index omitted {question:?}"
            );
        }
        assert!(index.contains("workflow success is not an answer"));
    }

    #[test]
    fn high_risk_family_queue_binds_finalized_cells_and_exact_groups() {
        let builtin = hell_builtins::registry()
            .iter()
            .find(|spec| {
                let metadata = spec.assurance_metadata();
                !metadata.capabilities.is_empty()
                    || !metadata.sensitivities.is_empty()
                    || metadata.source_reachability
                        == hell_builtins::SourceReachability::GeneratedOnly
            })
            .expect("catalog includes an environment-sensitive builtin")
            .name;
        let cell = finalized_cell(builtin, "effects");
        let groups = claim_groups(std::slice::from_ref(&cell)).unwrap();
        let source = QueueSource {
            path: "coverage/claim-coverage.finalized.json".to_owned(),
            sha256: sha256_bytes(b"coverage").hex(),
        };
        let queue = high_risk_family_queue(&[cell], &groups, &source).unwrap();
        assert_eq!(queue.id, "high-risk-semantic-families");
        assert_eq!(queue.records.len(), 1);
        assert!(queue.records[0].retained_refs.len() >= 3);
    }

    #[test]
    fn one_case_queue_counts_distinct_retained_case_identities() {
        let builtin = hell_builtins::registry()[0].name;
        let mut cell = finalized_cell(builtin, "effects");
        let group = claim_group_id(&cell).unwrap();
        assert_eq!(claim_group_case_ids(&[cell], &group).unwrap().len(), 1);

        cell = finalized_cell(builtin, "effects");
        cell.evidence_refs
            .push(crate::assurance::FinalizedClaimEvidenceRef {
                canonical_json: "{\"bundlePath\":\"two\"}".to_owned(),
                sha256: sha256_bytes(b"reference-two").hex(),
                bundle_path: "native/two".to_owned(),
                bundle_sha256: sha256_bytes(b"bundle-two").hex(),
                case_id: "case-two".to_owned(),
                obligations: vec!["evaluation".to_owned()],
            });
        let group = claim_group_id(&cell).unwrap();
        assert_eq!(claim_group_case_ids(&[cell], &group).unwrap().len(), 2);
    }
}
