use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::github_runtime::{GithubCredential, GithubRuntime};
use crate::json::{JsonValue, canonical_json_bytes, json_member, parse_json};

use super::manifest::{read_json, read_regular, write_json_new};
use super::schema::{ReleasePlan, number, object, require_digest, string};

const MAX_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_API_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 4096;
const PROFILE_DOMAIN: &[u8] = b"hell-rs:governance-profile:1";
const RESIDUAL_SET_DOMAIN: &[u8] = b"hell-rs:residual-assumption-set:1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeclaredGovernanceBindings {
    pub(crate) declaration_sha256: String,
    pub(crate) profile_sha256: String,
    pub(crate) residual_set_digest: String,
}

struct SnapshotTransaction(SnapshotOptions);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Phase {
    Resolve,
    PostAssembly,
    PreAttestation,
    PrePublish,
}

#[derive(Clone, Debug)]
pub(crate) struct SnapshotOptions {
    pub(crate) policy: PathBuf,
    pub(crate) api_policy: PathBuf,
    pub(crate) plan: PathBuf,
    pub(crate) baseline: Option<PathBuf>,
    pub(crate) predecessor: Option<PathBuf>,
    pub(crate) phase: Phase,
    pub(crate) output: PathBuf,
    pub(crate) report: PathBuf,
}

#[derive(Clone, Debug)]
struct GovernancePolicy {
    profile_id: String,
    repository_owner: String,
    repository_name: String,
    default_branch: String,
    merge_queue: bool,
    immutable_releases: String,
    full_sha_actions: String,
    default_workflow_token: String,
    workflows_may_approve_pull_requests: bool,
    candidate_head_stability: String,
    tag_absence_before_publication: String,
    controls: Vec<ControlPolicy>,
    residuals: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
struct ControlPolicy {
    id: String,
    endpoint: String,
    treatment: String,
    phases: Vec<Phase>,
    residual_assumption: Option<String>,
}

#[derive(Clone, Debug)]
struct ApiPolicy {
    api_version: String,
    accept: String,
    user_agent: String,
    connect_timeout: Duration,
    request_timeout: Duration,
    maximum_retries: u64,
    endpoints: BTreeMap<String, EndpointPolicy>,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct EndpointPolicy {
    method: String,
    path_segments: Vec<String>,
    maximum_response_bytes: u64,
    not_found: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ObservationStatus {
    Observed,
    Unavailable,
    NotApplicable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Evaluation {
    Matched,
    Mismatched,
    ResidualAssumption,
    NotApplicable,
}

#[derive(Clone, Debug)]
struct Observation {
    control_id: String,
    status: ObservationStatus,
    normalized_value: Option<JsonValue>,
    endpoint_id: Option<String>,
    http_status: Option<u16>,
    residual_assumption_id: Option<String>,
    evaluation: Evaluation,
}

struct Snapshot {
    value: JsonValue,
    observations: BTreeMap<String, Observation>,
}

#[derive(Clone, Copy)]
struct SnapshotMaterials<'a> {
    phase: Phase,
    plan: &'a ReleasePlan,
    runtime: &'a GithubRuntime,
    api: &'a ApiPolicy,
    bindings: &'a DeclaredGovernanceBindings,
    baseline_sha256: Option<&'a str>,
    predecessor_sha256: Option<&'a str>,
}

struct SnapshotChain {
    baseline_sha256: Option<String>,
    predecessor_sha256: Option<String>,
}

#[derive(Clone, Debug)]
struct Failure {
    code: &'static str,
    message: String,
}

impl Failure {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        let mut message = message.into();
        if message.len() > MAX_DIAGNOSTIC_BYTES {
            message.truncate(MAX_DIAGNOSTIC_BYTES);
        }
        Self { code, message }
    }
}

impl Phase {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "resolve" => Ok(Self::Resolve),
            "post-assembly" => Ok(Self::PostAssembly),
            "pre-attestation" => Ok(Self::PreAttestation),
            "pre-publish" => Ok(Self::PrePublish),
            _ => Err(format!("unsupported governance phase {value:?}")),
        }
    }

    const fn id(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::PostAssembly => "post-assembly",
            Self::PreAttestation => "pre-attestation",
            Self::PrePublish => "pre-publish",
        }
    }

    const fn predecessor(self) -> Option<&'static str> {
        match self {
            Self::Resolve => None,
            Self::PostAssembly => Some("resolve"),
            Self::PreAttestation => Some("post-assembly"),
            Self::PrePublish => Some("pre-attestation"),
        }
    }
}

pub(crate) fn declared_bindings(path: &Path) -> Result<DeclaredGovernanceBindings, String> {
    let bytes = read_bounded_regular(path, MAX_POLICY_BYTES, "governance policy")?;
    let policy = GovernancePolicy::parse(&bytes)?;
    let declaration_sha256 = hell_testkit::sha256_bytes(&bytes).hex();
    let profile = policy.declared_profile_json();
    let residuals = policy.declared_residuals_json();
    Ok(DeclaredGovernanceBindings {
        declaration_sha256,
        profile_sha256: domain_digest(PROFILE_DOMAIN, &profile)?,
        residual_set_digest: domain_digest(RESIDUAL_SET_DOMAIN, &residuals)?,
    })
}

pub(crate) fn snapshot(options: SnapshotOptions) -> Result<String, String> {
    let transaction = SnapshotTransaction(options);
    let options = &transaction.0;
    let outcome = snapshot_inner(options);
    let report = match &outcome {
        Ok((snapshot, digest)) => object([
            ("admitted", JsonValue::Bool(true)),
            ("diagnostic", JsonValue::Null),
            ("phase", string(options.phase.id())),
            ("planSha256", snapshot_plan_sha(&snapshot.value)?),
            ("schemaVersion", number(1)),
            ("snapshotSha256", string(digest)),
            ("state", string("observed")),
        ]),
        Err(failure) => object([
            ("admitted", JsonValue::Bool(false)),
            (
                "diagnostic",
                object([
                    ("code", string(failure.code)),
                    ("message", string(&failure.message)),
                ]),
            ),
            ("phase", string(options.phase.id())),
            ("planSha256", JsonValue::Null),
            ("schemaVersion", number(1)),
            ("snapshotSha256", JsonValue::Null),
            ("state", string("rejected")),
        ]),
    };
    if let Err(report_error) = write_json_new(&options.report, &report) {
        if outcome.is_ok() && options.output.exists() {
            std::fs::remove_file(&options.output).map_err(|cleanup_error| {
                format!(
                    "cannot write governance report: {report_error}; cannot remove unreported snapshot: {cleanup_error}"
                )
            })?;
        }
        return Err(format!("cannot write governance report: {report_error}"));
    }
    let (snapshot, _) =
        outcome.map_err(|failure| format!("{}: {}", failure.code, failure.message))?;
    Ok(format!(
        "recorded {} governance controls for {}",
        snapshot.observations.len(),
        options.phase.id()
    ))
}

fn snapshot_inner(options: &SnapshotOptions) -> Result<(Snapshot, String), Failure> {
    let policy_bytes = read_bounded_regular(&options.policy, MAX_POLICY_BYTES, "governance policy")
        .map_err(|error| Failure::new("governance.policy.input", error))?;
    let policy = GovernancePolicy::parse(&policy_bytes)
        .map_err(|error| Failure::new("governance.policy.schema", error))?;
    let api = ApiPolicy::read(&options.api_policy)
        .map_err(|error| Failure::new("governance.api-policy.schema", error))?;
    let plan = ReleasePlan::parse(
        &read_json(&options.plan).map_err(|error| Failure::new("governance.plan.input", error))?,
    )
    .map_err(|error| Failure::new("governance.plan.schema", error))?;
    let runtime = GithubRuntime::from_process()
        .map_err(|error| Failure::new("governance.runtime.identity", error))?;
    require_runtime_plan_identity(&runtime, &plan)?;
    let bindings = declared_bindings(&options.policy)
        .map_err(|error| Failure::new("governance.policy.binding", error))?;
    require_plan_bindings(&plan, &bindings)?;
    let credential = GithubCredential::from_process()
        .map_err(|error| Failure::new("governance.credential.unavailable", error))?;
    let deadline = Instant::now()
        .checked_add(Duration::from_mins(5))
        .ok_or_else(|| Failure::new("governance.deadline.overflow", "deadline overflowed"))?;
    let client = Client::new(&runtime, credential, &api, deadline)?;
    let observations = observe(&policy, &plan, &runtime, options.phase, &client)?;
    if observations
        .values()
        .any(|observation| observation.evaluation == Evaluation::Mismatched)
    {
        return Err(Failure::new(
            "governance.control.mismatched",
            "at least one governance control mismatched its declaration",
        ));
    }
    for control in &policy.controls {
        if control.treatment == "block-on-unavailable-or-mismatch"
            && observations
                .get(&control.id)
                .is_some_and(|observation| observation.evaluation == Evaluation::ResidualAssumption)
        {
            return Err(Failure::new(
                "governance.control.unavailable",
                format!("required control {} was unavailable", control.id),
            ));
        }
    }
    let chain = snapshot_chain(options, &plan, &runtime, &bindings, &observations)?;
    let snapshot = build_snapshot(
        &SnapshotMaterials {
            phase: options.phase,
            plan: &plan,
            runtime: &runtime,
            api: &api,
            bindings: &bindings,
            baseline_sha256: chain.baseline_sha256.as_deref(),
            predecessor_sha256: chain.predecessor_sha256.as_deref(),
        },
        observations,
    )?;
    let digest = persist_snapshot(options, &plan, &snapshot, &chain)?;
    Ok((snapshot, digest))
}

fn snapshot_chain(
    options: &SnapshotOptions,
    plan: &ReleasePlan,
    runtime: &GithubRuntime,
    bindings: &DeclaredGovernanceBindings,
    observations: &BTreeMap<String, Observation>,
) -> Result<SnapshotChain, Failure> {
    if options.phase == Phase::Resolve && options.baseline.is_some() {
        return Err(Failure::new(
            "governance.baseline.unexpected",
            "resolve phase must not accept a baseline",
        ));
    }
    let (baseline_sha256, predecessor_sha256) = if options.phase == Phase::Resolve {
        if options.predecessor.is_some() {
            return Err(Failure::new(
                "governance.predecessor.unexpected",
                "resolve phase must not accept a predecessor",
            ));
        }
        (None, None)
    } else {
        let baseline_path = options.baseline.as_deref().ok_or_else(|| {
            Failure::new(
                "governance.baseline.missing",
                "post-resolve governance phase requires --baseline",
            )
        })?;
        let baseline_sha256 =
            compare_baseline(baseline_path, plan, runtime, bindings, observations)?;
        let predecessor_sha256 = match options.phase {
            Phase::PostAssembly => {
                if options.predecessor.is_some() {
                    return Err(Failure::new(
                        "governance.predecessor.unexpected",
                        "post-assembly predecessor is the resolve baseline",
                    ));
                }
                baseline_sha256.clone()
            }
            Phase::PreAttestation | Phase::PrePublish => {
                let predecessor = options.predecessor.as_deref().ok_or_else(|| {
                    Failure::new(
                        "governance.predecessor.missing",
                        "governance phase requires its immediate predecessor receipt",
                    )
                })?;
                require_predecessor(
                    predecessor,
                    options
                        .phase
                        .predecessor()
                        .expect("non-resolve predecessor"),
                    &baseline_sha256,
                    plan,
                    runtime,
                    bindings,
                )?
            }
            Phase::Resolve => unreachable!("resolve handled above"),
        };
        (Some(baseline_sha256), Some(predecessor_sha256))
    };
    Ok(SnapshotChain {
        baseline_sha256,
        predecessor_sha256,
    })
}

fn persist_snapshot(
    options: &SnapshotOptions,
    plan: &ReleasePlan,
    snapshot: &Snapshot,
    chain: &SnapshotChain,
) -> Result<String, Failure> {
    let bytes = write_json_new(&options.output, &snapshot.value)
        .map_err(|error| Failure::new("governance.snapshot.write", error))?;
    let digest = hell_testkit::sha256_bytes(&bytes).hex();
    let verified_digest = match verify_snapshot(
        &options.output,
        plan,
        options.phase,
        chain.baseline_sha256.as_deref(),
        chain.predecessor_sha256.as_deref(),
    ) {
        Ok(digest) => digest,
        Err(primary) => {
            return match std::fs::remove_file(&options.output) {
                Ok(()) => Err(Failure::new(
                    "governance.snapshot.self-verification",
                    primary,
                )),
                Err(cleanup) => Err(Failure::new(
                    "governance.snapshot.self-verification",
                    format!("{primary}; cannot remove rejected snapshot: {cleanup}"),
                )),
            };
        }
    };
    if verified_digest != digest {
        let primary = "written governance snapshot digest differs after verification";
        return match std::fs::remove_file(&options.output) {
            Ok(()) => Err(Failure::new(
                "governance.snapshot.self-verification",
                primary,
            )),
            Err(cleanup) => Err(Failure::new(
                "governance.snapshot.self-verification",
                format!("{primary}; cannot remove rejected snapshot: {cleanup}"),
            )),
        };
    }
    Ok(digest)
}

fn require_runtime_plan_identity(
    runtime: &GithubRuntime,
    plan: &ReleasePlan,
) -> Result<(), Failure> {
    if runtime.repository.numeric_id != plan.resolution.repository_id
        || runtime.repository.full_name != plan.resolution.repository
        || runtime.run_id != plan.resolution.run_id
        || runtime.run_attempt != plan.resolution.run_attempt
        || runtime.workflow_ref != plan.resolution.workflow_ref
        || runtime.workflow_sha != plan.resolution.workflow_sha
    {
        return Err(Failure::new(
            "governance.runtime.plan-mismatch",
            "trusted GitHub runtime identity differs from the release plan",
        ));
    }
    Ok(())
}

fn require_plan_bindings(
    plan: &ReleasePlan,
    bindings: &DeclaredGovernanceBindings,
) -> Result<(), Failure> {
    if plan.governance_declaration_sha256 != bindings.declaration_sha256
        || plan.governance_profile_sha256 != bindings.profile_sha256
        || plan.residual_assumption_set_sha256 != bindings.residual_set_digest
    {
        return Err(Failure::new(
            "governance.plan.policy-binding",
            "release plan governance policy bindings differ from the trusted declaration",
        ));
    }
    Ok(())
}

fn build_snapshot(
    materials: &SnapshotMaterials<'_>,
    observations: BTreeMap<String, Observation>,
) -> Result<Snapshot, Failure> {
    let SnapshotMaterials {
        phase,
        plan,
        runtime,
        api,
        bindings,
        baseline_sha256,
        predecessor_sha256,
    } = *materials;
    let active_residuals = observations
        .values()
        .filter_map(|observation| observation.residual_assumption_id.as_ref())
        .cloned()
        .collect::<BTreeSet<_>>();
    let residual_json =
        JsonValue::Array(active_residuals.iter().map(|value| string(value)).collect());
    let residual_digest = domain_digest(RESIDUAL_SET_DOMAIN, &residual_json)
        .map_err(|error| Failure::new("governance.residual.digest", error))?;
    let observation_json = JsonValue::Array(
        observations
            .values()
            .map(Observation::json)
            .collect::<Vec<_>>(),
    );
    let profile = object([
        (
            "governanceDeclarationSha256",
            string(&bindings.declaration_sha256),
        ),
        ("observations", observation_json.clone()),
        ("phase", string(phase.id())),
        ("planSha256", string(&plan.plan_sha256)),
        ("repositoryId", number(runtime.repository.numeric_id)),
        ("residualAssumptions", residual_json.clone()),
        ("schemaVersion", number(1)),
    ]);
    let profile_digest = domain_digest(PROFILE_DOMAIN, &profile)
        .map_err(|error| Failure::new("governance.profile.digest", error))?;
    let api_policy_digest = hell_testkit::sha256_bytes(&api.bytes).hex();
    let value = object([
        ("apiPolicySha256", string(&api_policy_digest)),
        (
            "baselineSha256",
            baseline_sha256.map_or(JsonValue::Null, string),
        ),
        ("candidateBranch", string(&plan.resolution.candidate_branch)),
        ("candidateSha", string(&plan.resolution.candidate_sha)),
        (
            "governanceDeclarationSha256",
            string(&bindings.declaration_sha256),
        ),
        ("governanceProfileSha256", string(&profile_digest)),
        ("observations", observation_json),
        ("phase", string(phase.id())),
        ("planSha256", string(&plan.plan_sha256)),
        (
            "predecessorPhase",
            phase.predecessor().map_or(JsonValue::Null, string),
        ),
        (
            "predecessorSha256",
            predecessor_sha256.map_or(JsonValue::Null, string),
        ),
        ("repository", string(&runtime.repository.full_name)),
        ("repositoryId", number(runtime.repository.numeric_id)),
        ("residualAssumptionSetSha256", string(&residual_digest)),
        ("residualAssumptions", residual_json),
        ("runAttempt", number(runtime.run_attempt)),
        ("runId", number(runtime.run_id)),
        ("schemaVersion", number(1)),
        ("tag", string(&plan.tag)),
        ("workflowRef", string(&runtime.workflow_ref)),
        ("workflowSha", string(&runtime.workflow_sha)),
    ]);
    Ok(Snapshot {
        value,
        observations,
    })
}

fn snapshot_plan_sha(value: &JsonValue) -> Result<JsonValue, String> {
    Ok(string(
        json_member(value.object()?, "planSha256")?.string()?,
    ))
}

pub(crate) fn verify_snapshot(
    path: &Path,
    plan: &ReleasePlan,
    expected_phase: Phase,
    expected_baseline_sha256: Option<&str>,
    expected_predecessor_sha256: Option<&str>,
) -> Result<String, String> {
    let bytes = read_bounded_regular(path, MAX_POLICY_BYTES, "governance snapshot")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "governance snapshot is not UTF-8")?;
    let value = parse_json(text)?;
    if canonical_json_bytes(&value)? != bytes {
        return Err("governance snapshot is not canonical JSON".to_owned());
    }
    let fields = value.object()?;
    require_json_keys(fields, &SNAPSHOT_KEYS)?;
    validate_snapshot_plan_binding(fields, plan, expected_phase)?;
    validate_snapshot_runtime(plan)?;
    validate_snapshot_chain(
        fields,
        expected_phase,
        expected_baseline_sha256,
        expected_predecessor_sha256,
    )?;
    validate_snapshot_contents(fields, plan, expected_phase)?;
    Ok(hell_testkit::sha256_bytes(&bytes).hex())
}

const SNAPSHOT_KEYS: [&str; 21] = [
    "apiPolicySha256",
    "baselineSha256",
    "candidateBranch",
    "candidateSha",
    "governanceDeclarationSha256",
    "governanceProfileSha256",
    "observations",
    "phase",
    "planSha256",
    "predecessorPhase",
    "predecessorSha256",
    "repository",
    "repositoryId",
    "residualAssumptionSetSha256",
    "residualAssumptions",
    "runAttempt",
    "runId",
    "schemaVersion",
    "tag",
    "workflowRef",
    "workflowSha",
];

fn validate_snapshot_plan_binding(
    fields: &BTreeMap<String, JsonValue>,
    plan: &ReleasePlan,
    expected_phase: Phase,
) -> Result<(), String> {
    if json_member(fields, "schemaVersion")?.number()? != 1
        || json_member(fields, "phase")?.string()? != expected_phase.id()
        || json_member(fields, "planSha256")?.string()? != plan.plan_sha256
        || json_member(fields, "repository")?.string()? != plan.resolution.repository
        || json_member(fields, "repositoryId")?.number()? != plan.resolution.repository_id
        || json_member(fields, "candidateBranch")?.string()? != plan.resolution.candidate_branch
        || json_member(fields, "candidateSha")?.string()? != plan.resolution.candidate_sha
        || json_member(fields, "tag")?.string()? != plan.tag
        || json_member(fields, "runAttempt")?.number()? != plan.resolution.run_attempt
        || json_member(fields, "runId")?.number()? != plan.resolution.run_id
        || json_member(fields, "workflowRef")?.string()? != plan.resolution.workflow_ref
        || json_member(fields, "workflowSha")?.string()? != plan.resolution.workflow_sha
        || json_member(fields, "governanceDeclarationSha256")?.string()?
            != plan.governance_declaration_sha256
    {
        return Err("governance snapshot differs from its release plan binding".to_owned());
    }
    Ok(())
}

fn validate_snapshot_runtime(plan: &ReleasePlan) -> Result<(), String> {
    let runtime = GithubRuntime::from_process()?;
    require_runtime_plan_identity(&runtime, plan)
        .map_err(|failure| format!("{}: {}", failure.code, failure.message))
}

fn validate_snapshot_chain(
    fields: &BTreeMap<String, JsonValue>,
    expected_phase: Phase,
    expected_baseline_sha256: Option<&str>,
    expected_predecessor_sha256: Option<&str>,
) -> Result<(), String> {
    require_optional_digest_binding(fields, "baselineSha256", expected_baseline_sha256)?;
    require_optional_digest_binding(fields, "predecessorSha256", expected_predecessor_sha256)?;
    match (
        json_member(fields, "predecessorPhase")?,
        expected_phase.predecessor(),
    ) {
        (JsonValue::Null, None) => {}
        (JsonValue::String(observed), Some(expected)) if observed == expected => {}
        _ => return Err("governance snapshot predecessor phase differs".to_owned()),
    }
    for key in [
        "apiPolicySha256",
        "governanceProfileSha256",
        "residualAssumptionSetSha256",
    ] {
        crate::release::schema::require_digest(json_member(fields, key)?.string()?, key)?;
    }
    Ok(())
}

fn validate_snapshot_contents(
    fields: &BTreeMap<String, JsonValue>,
    plan: &ReleasePlan,
    expected_phase: Phase,
) -> Result<(), String> {
    let observations_value = json_member(fields, "observations")?;
    let observations = parse_observations(observations_value)
        .map_err(|failure| format!("{}: {}", failure.code, failure.message))?;
    let required_controls = [
        "allowed-actions",
        "branch-and-ruleset-protection",
        "candidate-head",
        "default-branch",
        "immutable-releases",
        "merge-queue",
        "release-tag",
        "repository-identity",
        "tag-protection",
        "workflow-token-permissions",
    ];
    if observations
        .keys()
        .map(String::as_str)
        .ne(required_controls)
    {
        return Err("governance snapshot control inventory differs".to_owned());
    }
    for observation in observations.values() {
        if !observation_is_coherent(observation) {
            return Err(format!(
                "governance snapshot control {} has an incoherent state",
                observation.control_id
            ));
        }
    }
    let residuals_value = json_member(fields, "residualAssumptions")?;
    let residuals = residuals_value
        .array()?
        .iter()
        .map(JsonValue::string)
        .collect::<Result<Vec<_>, _>>()?;
    if residuals.windows(2).any(|pair| pair[0] >= pair[1])
        || residuals.iter().copied().collect::<BTreeSet<_>>().len() != residuals.len()
        || observations
            .values()
            .filter_map(|observation| observation.residual_assumption_id.as_deref())
            .ne(residuals.iter().copied())
    {
        return Err("governance snapshot residual inventory differs".to_owned());
    }
    if domain_digest(RESIDUAL_SET_DOMAIN, residuals_value)?
        != json_member(fields, "residualAssumptionSetSha256")?.string()?
    {
        return Err("governance snapshot residual digest differs".to_owned());
    }
    let profile = object([
        (
            "governanceDeclarationSha256",
            string(&plan.governance_declaration_sha256),
        ),
        ("observations", observations_value.clone()),
        ("phase", string(expected_phase.id())),
        ("planSha256", string(&plan.plan_sha256)),
        ("repositoryId", number(plan.resolution.repository_id)),
        ("residualAssumptions", residuals_value.clone()),
        ("schemaVersion", number(1)),
    ]);
    if domain_digest(PROFILE_DOMAIN, &profile)?
        != json_member(fields, "governanceProfileSha256")?.string()?
    {
        return Err("governance snapshot profile digest differs".to_owned());
    }
    Ok(())
}

fn observation_is_coherent(observation: &Observation) -> bool {
    match observation.status {
        ObservationStatus::Observed => {
            observation.normalized_value.is_some()
                && observation.residual_assumption_id.is_none()
                && observation.evaluation == Evaluation::Matched
        }
        ObservationStatus::Unavailable => {
            observation.normalized_value.is_none()
                && observation.residual_assumption_id.is_some()
                && observation.http_status.is_some()
                && observation.evaluation == Evaluation::ResidualAssumption
        }
        ObservationStatus::NotApplicable => {
            observation.normalized_value.is_none()
                && observation.endpoint_id.is_none()
                && observation.http_status.is_none()
                && observation.residual_assumption_id.is_none()
                && observation.evaluation == Evaluation::NotApplicable
        }
    }
}

fn require_optional_digest_binding(
    fields: &BTreeMap<String, JsonValue>,
    key: &str,
    expected: Option<&str>,
) -> Result<(), String> {
    match (json_member(fields, key)?, expected) {
        (JsonValue::Null, None) => Ok(()),
        (JsonValue::String(observed), Some(expected)) if observed == expected => {
            crate::release::schema::require_digest(observed, key)
        }
        _ => Err(format!("governance snapshot {key} binding differs")),
    }
}

impl Observation {
    fn json(&self) -> JsonValue {
        object([
            ("controlId", string(&self.control_id)),
            ("endpointId", option_string(self.endpoint_id.as_deref())),
            ("evaluation", string(self.evaluation.id())),
            (
                "httpStatus",
                self.http_status
                    .map_or(JsonValue::Null, |value| number(u64::from(value))),
            ),
            (
                "normalizedValue",
                self.normalized_value.clone().unwrap_or(JsonValue::Null),
            ),
            (
                "residualAssumptionId",
                option_string(self.residual_assumption_id.as_deref()),
            ),
            ("status", string(self.status.id())),
        ])
    }
}

impl ObservationStatus {
    const fn id(&self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Unavailable => "unavailable",
            Self::NotApplicable => "not-applicable",
        }
    }
}

impl Evaluation {
    const fn id(&self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::Mismatched => "mismatched",
            Self::ResidualAssumption => "residual-assumption",
            Self::NotApplicable => "not-applicable",
        }
    }
}

fn option_string(value: Option<&str>) -> JsonValue {
    value.map_or(JsonValue::Null, string)
}

fn domain_digest(domain: &[u8], value: &JsonValue) -> Result<String, String> {
    let canonical = canonical_json_bytes(value)?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + canonical.len());
    bytes.extend_from_slice(domain);
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(hell_testkit::sha256_bytes(&bytes).hex())
}

fn read_bounded_regular(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label}: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(format!("{label} is not one bounded regular file"));
    }
    let bytes = read_regular(path)?;
    if !bytes.ends_with(b"\n") {
        return Err(format!("{label} lacks its trailing newline"));
    }
    Ok(bytes)
}

impl GovernancePolicy {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        let text =
            std::str::from_utf8(bytes).map_err(|_| "governance policy is not UTF-8".to_owned())?;
        let document = TomlDocument::parse(text)?;
        document.require_table_inventory(&["", "observation"])?;
        document.require_array_inventory(&["control", "residual-assumption"])?;
        let mut root = document.table("")?.clone();
        require_keys(
            &root,
            &[
                "candidate-head-stability",
                "default-branch",
                "default-workflow-token",
                "full-sha-actions",
                "immutable-releases",
                "merge-queue",
                "profile-id",
                "repository-id-source",
                "repository-name",
                "repository-owner",
                "require-numeric-repository-id",
                "schema-version",
                "tag-absence-before-publication",
                "workflow-control-ref",
                "workflows-may-approve-pull-requests",
            ],
        )?;
        if integer(&take(&mut root, "schema-version")?)? != 1
            || quoted(&take(&mut root, "repository-id-source")?)? != "trusted-resolution"
            || !boolean(&take(&mut root, "require-numeric-repository-id")?)?
            || quoted(&take(&mut root, "workflow-control-ref")?)? != "default-branch"
        {
            return Err("governance policy does not require trusted numeric resolution".to_owned());
        }
        let profile_id = quoted(&take(&mut root, "profile-id")?)?;
        let repository_owner = quoted(&take(&mut root, "repository-owner")?)?;
        let repository_name = quoted(&take(&mut root, "repository-name")?)?;
        let default_branch = quoted(&take(&mut root, "default-branch")?)?;
        let merge_queue = boolean(&take(&mut root, "merge-queue")?)?;
        let immutable_releases = quoted(&take(&mut root, "immutable-releases")?)?;
        let full_sha_actions = quoted(&take(&mut root, "full-sha-actions")?)?;
        let default_workflow_token = quoted(&take(&mut root, "default-workflow-token")?)?;
        let workflows_may_approve_pull_requests =
            boolean(&take(&mut root, "workflows-may-approve-pull-requests")?)?;
        let candidate_head_stability = quoted(&take(&mut root, "candidate-head-stability")?)?;
        let tag_absence_before_publication =
            quoted(&take(&mut root, "tag-absence-before-publication")?)?;
        validate_observation_lattice(document.table("observation")?)?;
        let residuals = parse_residuals(document.arrays("residual-assumption")?)?;
        let controls = parse_controls(document.arrays("control")?, &residuals)?;
        let identities = controls
            .iter()
            .map(|control| control.id.as_str())
            .collect::<BTreeSet<_>>();
        for required in [
            "repository-identity",
            "default-branch",
            "workflow-token-permissions",
            "allowed-actions",
            "branch-and-ruleset-protection",
            "tag-protection",
            "immutable-releases",
            "merge-queue",
            "candidate-head",
            "release-tag",
        ] {
            if !identities.contains(required) {
                return Err(format!("governance policy lacks control {required}"));
            }
        }
        Ok(Self {
            profile_id,
            repository_owner,
            repository_name,
            default_branch,
            merge_queue,
            immutable_releases,
            full_sha_actions,
            default_workflow_token,
            workflows_may_approve_pull_requests,
            candidate_head_stability,
            tag_absence_before_publication,
            controls,
            residuals,
        })
    }

    fn declared_profile_json(&self) -> JsonValue {
        object([
            (
                "candidateHeadStability",
                string(&self.candidate_head_stability),
            ),
            ("defaultBranch", string(&self.default_branch)),
            ("defaultWorkflowToken", string(&self.default_workflow_token)),
            ("fullShaActions", string(&self.full_sha_actions)),
            ("immutableReleases", string(&self.immutable_releases)),
            ("mergeQueue", JsonValue::Bool(self.merge_queue)),
            ("profileId", string(&self.profile_id)),
            ("repositoryName", string(&self.repository_name)),
            ("repositoryOwner", string(&self.repository_owner)),
            ("schemaVersion", number(1)),
            (
                "tagAbsenceBeforePublication",
                string(&self.tag_absence_before_publication),
            ),
            (
                "workflowsMayApprovePullRequests",
                JsonValue::Bool(self.workflows_may_approve_pull_requests),
            ),
        ])
    }

    fn declared_residuals_json(&self) -> JsonValue {
        JsonValue::Array(
            self.residuals
                .iter()
                .map(|(id, statement)| {
                    object([("id", string(id)), ("statement", string(statement))])
                })
                .collect(),
        )
    }
}

fn validate_observation_lattice(observation: &BTreeMap<String, String>) -> Result<(), String> {
    require_keys(
        observation,
        &[
            "allowed-evaluations",
            "allowed-statuses",
            "unavailable-is-match",
        ],
    )?;
    if string_array(member(observation, "allowed-statuses")?)?
        != ["observed", "unavailable", "not-applicable"]
        || string_array(member(observation, "allowed-evaluations")?)?
            != [
                "matched",
                "mismatched",
                "residual-assumption",
                "not-applicable",
            ]
        || boolean(member(observation, "unavailable-is-match")?)?
    {
        return Err("governance observation lattice differs from protocol".to_owned());
    }
    Ok(())
}

fn parse_residuals(
    tables: &[BTreeMap<String, String>],
) -> Result<BTreeMap<String, String>, String> {
    let mut residuals = BTreeMap::new();
    for table in tables {
        require_keys(table, &["id", "statement"])?;
        let id = quoted(member(table, "id")?)?;
        let statement = quoted(member(table, "statement")?)?;
        require_identifier(&id, "residual assumption")?;
        if statement.is_empty() || residuals.insert(id.clone(), statement).is_some() {
            return Err(format!("duplicate or empty residual assumption {id}"));
        }
    }
    Ok(residuals)
}

fn parse_controls(
    tables: &[BTreeMap<String, String>],
    residuals: &BTreeMap<String, String>,
) -> Result<Vec<ControlPolicy>, String> {
    let mut controls = Vec::new();
    let mut ids = BTreeSet::new();
    for table in tables {
        require_allowed_keys(
            table,
            &[
                "endpoint",
                "id",
                "phases",
                "residual-assumption",
                "treatment",
            ],
        )?;
        for required in ["endpoint", "id", "treatment"] {
            if !table.contains_key(required) {
                return Err(format!("governance control lacks {required}"));
            }
        }
        let id = quoted(member(table, "id")?)?;
        require_identifier(&id, "control")?;
        if !ids.insert(id.clone()) {
            return Err(format!("duplicate governance control {id}"));
        }
        let endpoint = quoted(member(table, "endpoint")?)?;
        require_identifier(&endpoint, "endpoint")?;
        let treatment = quoted(member(table, "treatment")?)?;
        if !matches!(
            treatment.as_str(),
            "block-on-unavailable-or-mismatch"
                | "block-on-mismatch"
                | "disclose-residual"
                | "not-applicable-when-disabled"
        ) {
            return Err(format!("unknown governance treatment {treatment}"));
        }
        let residual_assumption = table
            .get("residual-assumption")
            .map(|value| quoted(value))
            .transpose()?;
        if residual_assumption
            .as_ref()
            .is_some_and(|id| !residuals.contains_key(id))
        {
            return Err(format!(
                "control {id} references an unknown residual assumption"
            ));
        }
        let phases = table.get("phases").map_or_else(
            || Ok(Phase::all().to_vec()),
            |value| {
                string_array(value)?
                    .iter()
                    .map(|value| Phase::parse(value))
                    .collect::<Result<Vec<_>, _>>()
            },
        )?;
        if phases.is_empty()
            || phases.iter().copied().collect::<BTreeSet<_>>().len() != phases.len()
        {
            return Err(format!("control {id} has duplicate or empty phases"));
        }
        controls.push(ControlPolicy {
            id,
            endpoint,
            treatment,
            phases,
            residual_assumption,
        });
    }
    Ok(controls)
}

impl Phase {
    const fn all() -> &'static [Self; 4] {
        &[
            Self::Resolve,
            Self::PostAssembly,
            Self::PreAttestation,
            Self::PrePublish,
        ]
    }
}

impl ApiPolicy {
    fn read(path: &Path) -> Result<Self, String> {
        let bytes = read_bounded_regular(path, MAX_POLICY_BYTES, "GitHub API policy")?;
        let text =
            std::str::from_utf8(&bytes).map_err(|_| "GitHub API policy is not UTF-8".to_owned())?;
        let document = TomlDocument::parse(text)?;
        document.require_table_inventory(&[""])?;
        document.require_array_inventory(&["endpoint"])?;
        let root = document.table("")?;
        require_keys(
            root,
            &[
                "accept",
                "api-version",
                "connect-timeout-seconds",
                "maximum-redirects",
                "maximum-retries",
                "request-timeout-seconds",
                "retry-idempotent-reads-only",
                "schema-version",
                "user-agent",
            ],
        )?;
        if integer(member(root, "schema-version")?)? != 1
            || integer(member(root, "maximum-redirects")?)? != 0
            || !boolean(member(root, "retry-idempotent-reads-only")?)?
        {
            return Err("GitHub API transport policy is not fail-closed".to_owned());
        }
        let connect_seconds = integer(member(root, "connect-timeout-seconds")?)?;
        let request_seconds = integer(member(root, "request-timeout-seconds")?)?;
        if connect_seconds == 0
            || connect_seconds > 60
            || request_seconds == 0
            || request_seconds > 300
        {
            return Err("GitHub API timeout policy is outside protocol bounds".to_owned());
        }
        let maximum_retries = integer(member(root, "maximum-retries")?)?;
        if maximum_retries > 3 {
            return Err("GitHub API retry count exceeds the protocol limit".to_owned());
        }
        let endpoints = parse_endpoints(document.arrays("endpoint")?)?;
        for id in [
            "repository",
            "branch-ref",
            "tag-ref",
            "repository-actions-permissions",
            "repository-workflow-permissions",
            "repository-immutable-releases",
            "repository-rulesets",
        ] {
            if !endpoints.contains_key(id) {
                return Err(format!("GitHub API policy lacks endpoint {id}"));
            }
        }
        Ok(Self {
            api_version: quoted(member(root, "api-version")?)?,
            accept: quoted(member(root, "accept")?)?,
            user_agent: quoted(member(root, "user-agent")?)?,
            connect_timeout: Duration::from_secs(connect_seconds),
            request_timeout: Duration::from_secs(request_seconds),
            maximum_retries,
            endpoints,
            bytes,
        })
    }
}

fn parse_endpoints(
    tables: &[BTreeMap<String, String>],
) -> Result<BTreeMap<String, EndpointPolicy>, String> {
    let mut endpoints = BTreeMap::new();
    for endpoint in tables {
        require_keys(
            endpoint,
            &[
                "id",
                "maximum-response-bytes",
                "method",
                "not-found",
                "path-segments",
            ],
        )?;
        let id = quoted(member(endpoint, "id")?)?;
        require_identifier(&id, "endpoint")?;
        let method = quoted(member(endpoint, "method")?)?;
        if method != "GET" {
            return Err(format!("governance endpoint {id} is not an idempotent GET"));
        }
        let maximum_response_bytes = integer(member(endpoint, "maximum-response-bytes")?)?;
        if maximum_response_bytes == 0 || maximum_response_bytes > MAX_API_RESPONSE_BYTES {
            return Err(format!(
                "governance endpoint {id} response limit is invalid"
            ));
        }
        let not_found = quoted(member(endpoint, "not-found")?)?;
        if !matches!(
            not_found.as_str(),
            "mismatch" | "unavailable" | "matched-absence"
        ) {
            return Err(format!(
                "governance endpoint {id} has unknown 404 semantics"
            ));
        }
        let path_segments = string_array(member(endpoint, "path-segments")?)?;
        validate_endpoint_path(&id, &path_segments)?;
        let policy = EndpointPolicy {
            method,
            path_segments,
            maximum_response_bytes,
            not_found,
        };
        if endpoints.insert(id.clone(), policy).is_some() {
            return Err(format!("duplicate governance endpoint {id}"));
        }
    }
    Ok(endpoints)
}

fn validate_endpoint_path(id: &str, segments: &[String]) -> Result<(), String> {
    if segments.is_empty() {
        return Err(format!("governance endpoint {id} has an empty path"));
    }
    let allowed_placeholders = ["{owner}", "{repository}", "{encoded-ref}", "{encoded-tag}"];
    for segment in segments {
        if segment.starts_with('{') {
            if !allowed_placeholders.contains(&segment.as_str()) {
                return Err(format!(
                    "governance endpoint {id} has an unknown placeholder"
                ));
            }
        } else if segment.is_empty()
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(format!(
                "governance endpoint {id} has an invalid path segment"
            ));
        }
    }
    Ok(())
}

struct Client<'a> {
    api: &'a ApiPolicy,
    credential: GithubCredential,
    deadline: Instant,
    owner: String,
    repository: String,
    root: String,
}

struct Response {
    body: Option<JsonValue>,
    status: u16,
}

impl<'a> Client<'a> {
    fn new(
        runtime: &GithubRuntime,
        credential: GithubCredential,
        api: &'a ApiPolicy,
        deadline: Instant,
    ) -> Result<Self, Failure> {
        let (owner, repository) = runtime
            .repository
            .full_name
            .split_once('/')
            .ok_or_else(|| Failure::new("governance.repository.identity", "invalid repository"))?;
        Ok(Self {
            api,
            credential,
            deadline,
            owner: owner.to_owned(),
            repository: repository.to_owned(),
            root: runtime.api_url.trim_end_matches('/').to_owned(),
        })
    }

    fn get(
        &self,
        endpoint_id: &str,
        encoded_ref: Option<&str>,
        encoded_tag: Option<&str>,
    ) -> Result<Response, Failure> {
        let endpoint = self.api.endpoints.get(endpoint_id).ok_or_else(|| {
            Failure::new(
                "governance.endpoint.missing",
                format!("API policy lacks endpoint {endpoint_id}"),
            )
        })?;
        if endpoint.method != "GET" {
            return Err(Failure::new(
                "governance.endpoint.method",
                "governance observation attempted a non-GET endpoint",
            ));
        }
        let url = self.endpoint_url(endpoint, encoded_ref, encoded_tag)?;
        let attempts = self.api.maximum_retries.saturating_add(1);
        let mut last_error = None;
        for attempt in 0..attempts {
            let now = Instant::now();
            let remaining = self.deadline.checked_duration_since(now).ok_or_else(|| {
                Failure::new(
                    "governance.deadline.exceeded",
                    "absolute governance deadline expired",
                )
            })?;
            let timeout = remaining.min(self.api.request_timeout);
            let loopback = self.root.starts_with("http://127.0.0.1:");
            let agent = ureq::config::Config::builder()
                .http_status_as_error(false)
                .https_only(!loopback)
                .max_redirects(0)
                .proxy(None)
                .timeout_connect(Some(self.api.connect_timeout.min(timeout)))
                .timeout_global(Some(timeout))
                .build()
                .new_agent();
            let response = self.credential.with_bearer_header(|authorization| {
                agent
                    .get(&url)
                    .header("Authorization", authorization)
                    .header("Accept", &self.api.accept)
                    .header("X-GitHub-Api-Version", &self.api.api_version)
                    .header("User-Agent", &self.api.user_agent)
                    .call()
                    .map_err(|error| format!("request failed: {error}"))
            });
            match response {
                Ok(mut response) => {
                    let status = response.status().as_u16();
                    if matches!(status, 502..=504) && attempt + 1 < attempts {
                        continue;
                    }
                    let body = response
                        .body_mut()
                        .with_config()
                        .limit(endpoint.maximum_response_bytes)
                        .read_to_vec()
                        .map_err(|error| {
                            Failure::new(
                                "governance.response.read",
                                format!("cannot read endpoint {endpoint_id}: {error}"),
                            )
                        })?;
                    let body = if body.is_empty() {
                        None
                    } else {
                        let text = std::str::from_utf8(&body).map_err(|_| {
                            Failure::new(
                                "governance.response.utf8",
                                format!("endpoint {endpoint_id} response is not UTF-8"),
                            )
                        })?;
                        Some(parse_json(text).map_err(|error| {
                            Failure::new(
                                "governance.response.json",
                                format!("endpoint {endpoint_id}: {error}"),
                            )
                        })?)
                    };
                    return Ok(Response { body, status });
                }
                Err(error) if attempt + 1 < attempts => last_error = Some(error),
                Err(error) => {
                    return Err(Failure::new("governance.request.failed", error));
                }
            }
        }
        Err(Failure::new(
            "governance.request.failed",
            last_error.unwrap_or_else(|| "request attempts were exhausted".to_owned()),
        ))
    }

    fn endpoint_url(
        &self,
        endpoint: &EndpointPolicy,
        encoded_ref: Option<&str>,
        encoded_tag: Option<&str>,
    ) -> Result<String, Failure> {
        let mut path = String::new();
        for segment in &endpoint.path_segments {
            path.push('/');
            let value = match segment.as_str() {
                "{owner}" => encode_segment(&self.owner),
                "{repository}" => encode_segment(&self.repository),
                "{encoded-ref}" => encode_segment(encoded_ref.ok_or_else(|| {
                    Failure::new("governance.endpoint.ref", "endpoint requires a branch ref")
                })?),
                "{encoded-tag}" => encode_segment(encoded_tag.ok_or_else(|| {
                    Failure::new("governance.endpoint.tag", "endpoint requires a tag")
                })?),
                value => value.to_owned(),
            };
            path.push_str(&value);
        }
        Ok(format!("{}{path}", self.root))
    }
}

fn encode_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    encoded
}

fn observe(
    policy: &GovernancePolicy,
    plan: &ReleasePlan,
    runtime: &GithubRuntime,
    phase: Phase,
    client: &Client<'_>,
) -> Result<BTreeMap<String, Observation>, Failure> {
    if runtime.repository.full_name
        != format!("{}/{}", policy.repository_owner, policy.repository_name)
        || plan.resolution.default_branch != policy.default_branch
    {
        return Err(Failure::new(
            "governance.declaration.identity",
            "trusted repository identity or default branch differs from governance policy",
        ));
    }
    let mut cache = BTreeMap::<String, Response>::new();
    let mut observations = BTreeMap::new();
    for control in &policy.controls {
        let observation = if control.phases.contains(&phase) {
            observe_control(control, policy, plan, runtime, client, &mut cache)?
        } else {
            not_applicable(control)
        };
        if observations
            .insert(control.id.clone(), observation)
            .is_some()
        {
            return Err(Failure::new(
                "governance.control.duplicate",
                "duplicate observation",
            ));
        }
    }
    Ok(observations)
}

fn observe_control(
    control: &ControlPolicy,
    policy: &GovernancePolicy,
    plan: &ReleasePlan,
    runtime: &GithubRuntime,
    client: &Client<'_>,
    cache: &mut BTreeMap<String, Response>,
) -> Result<Observation, Failure> {
    if control.id == "repository-identity" {
        let value = object([
            ("repository", string(&runtime.repository.full_name)),
            ("repositoryId", number(runtime.repository.numeric_id)),
        ]);
        return Ok(observed(control, value, true, None));
    }
    if control.id == "merge-queue" && !policy.merge_queue {
        return Ok(not_applicable(control));
    }
    let key = format!(
        "{}\0{}\0{}",
        control.endpoint, plan.resolution.candidate_branch, plan.tag
    );
    if !cache.contains_key(&key) {
        let response = client.get(
            &control.endpoint,
            (control.endpoint == "branch-ref").then_some(&plan.resolution.candidate_branch),
            (control.endpoint == "tag-ref").then_some(&plan.tag),
        )?;
        cache.insert(key.clone(), response);
    }
    let response = cache.get(&key).expect("cached response exists");
    let endpoint_policy = client
        .api
        .endpoints
        .get(&control.endpoint)
        .expect("validated endpoint exists");
    if let Some(observation) =
        classify_non_success_response(control, response.status, endpoint_policy.not_found.as_str())?
    {
        return Ok(observation);
    }
    let body = response.body.as_ref().ok_or_else(|| {
        Failure::new(
            "governance.response.empty",
            format!("endpoint {} returned an empty body", control.endpoint),
        )
    })?;
    let (value, matches) = normalize_control(control, policy, plan, runtime, body)?;
    Ok(observed(control, value, matches, Some(200)))
}

fn classify_non_success_response(
    control: &ControlPolicy,
    status: u16,
    not_found: &str,
) -> Result<Option<Observation>, Failure> {
    if status == 200 {
        return Ok(None);
    }
    if status == 403 || (status == 404 && not_found == "unavailable") {
        return unavailable(control, status).map(Some);
    }
    if status == 404 {
        return match not_found {
            "matched-absence" => Ok(Some(observed(
                control,
                object([("present", JsonValue::Bool(false))]),
                true,
                Some(404),
            ))),
            "mismatch" => Ok(Some(observed(
                control,
                object([("present", JsonValue::Bool(false))]),
                false,
                Some(404),
            ))),
            _ => unavailable(control, 404).map(Some),
        };
    }
    Err(Failure::new(
        "governance.response.status",
        format!(
            "endpoint {} returned unexpected HTTP {status}",
            control.endpoint
        ),
    ))
}

fn normalize_control(
    control: &ControlPolicy,
    policy: &GovernancePolicy,
    plan: &ReleasePlan,
    runtime: &GithubRuntime,
    body: &JsonValue,
) -> Result<(JsonValue, bool), Failure> {
    match control.id.as_str() {
        "default-branch" => {
            let (value, id, full_name, branch) = parse_repository_response(body)?;
            Ok((
                value,
                id == runtime.repository.numeric_id
                    && full_name == runtime.repository.full_name
                    && branch == policy.default_branch,
            ))
        }
        "workflow-token-permissions" => {
            let (value, permission, approve) = parse_workflow_permissions_response(body)?;
            Ok((
                value,
                permission == policy.default_workflow_token
                    && approve == policy.workflows_may_approve_pull_requests,
            ))
        }
        "allowed-actions" => {
            let (value, sha_pinning) = parse_actions_permissions_response(body)?;
            Ok((
                value,
                sha_pinning == (policy.full_sha_actions == "required"),
            ))
        }
        "branch-and-ruleset-protection" | "merge-queue" => normalize_rulesets(body, "branch"),
        "tag-protection" => normalize_rulesets(body, "tag"),
        "immutable-releases" => {
            let (value, enabled) = parse_immutable_releases_response(body)?;
            Ok((value, enabled == (policy.immutable_releases == "required")))
        }
        "candidate-head" => {
            let (value, reference, kind, sha) = parse_git_reference_response(body)?;
            Ok((
                value,
                reference == format!("refs/heads/{}", plan.resolution.candidate_branch)
                    && kind == "commit"
                    && sha == plan.resolution.candidate_sha,
            ))
        }
        "release-tag" => {
            let _ = parse_git_reference_response(body)?;
            Ok((object([("present", JsonValue::Bool(true))]), false))
        }
        _ => Err(Failure::new(
            "governance.control.unknown",
            format!("control {} has no typed normalizer", control.id),
        )),
    }
}

fn parse_repository_response(
    body: &JsonValue,
) -> Result<(JsonValue, u64, String, String), Failure> {
    let fields = body.object().map_err(schema_failure)?;
    let id = json_member(fields, "id")
        .and_then(JsonValue::number)
        .map_err(schema_failure)?;
    let full_name = json_member(fields, "full_name")
        .and_then(JsonValue::string)
        .map_err(schema_failure)?
        .to_owned();
    let branch = json_member(fields, "default_branch")
        .and_then(JsonValue::string)
        .map_err(schema_failure)?
        .to_owned();
    Ok((
        object([
            ("defaultBranch", string(&branch)),
            ("repository", string(&full_name)),
            ("repositoryId", number(id)),
        ]),
        id,
        full_name,
        branch,
    ))
}

fn parse_workflow_permissions_response(
    body: &JsonValue,
) -> Result<(JsonValue, String, bool), Failure> {
    let fields = body.object().map_err(schema_failure)?;
    let permission = json_member(fields, "default_workflow_permissions")
        .and_then(JsonValue::string)
        .map_err(schema_failure)?
        .to_owned();
    let approve = json_member(fields, "can_approve_pull_request_reviews")
        .and_then(JsonValue::boolean)
        .map_err(schema_failure)?;
    Ok((
        object([
            ("canApprovePullRequestReviews", JsonValue::Bool(approve)),
            ("defaultWorkflowPermissions", string(&permission)),
        ]),
        permission,
        approve,
    ))
}

fn parse_actions_permissions_response(body: &JsonValue) -> Result<(JsonValue, bool), Failure> {
    let fields = body.object().map_err(schema_failure)?;
    let allowed = json_member(fields, "allowed_actions")
        .and_then(JsonValue::string)
        .map_err(schema_failure)?;
    let sha_pinning = json_member(fields, "sha_pinning_required")
        .and_then(JsonValue::boolean)
        .map_err(schema_failure)?;
    Ok((
        object([
            ("allowedActions", string(allowed)),
            ("shaPinningRequired", JsonValue::Bool(sha_pinning)),
        ]),
        sha_pinning,
    ))
}

fn parse_immutable_releases_response(body: &JsonValue) -> Result<(JsonValue, bool), Failure> {
    let enabled = json_member(body.object().map_err(schema_failure)?, "immutable_releases")
        .and_then(JsonValue::boolean)
        .map_err(schema_failure)?;
    Ok((object([("enabled", JsonValue::Bool(enabled))]), enabled))
}

fn parse_git_reference_response(
    body: &JsonValue,
) -> Result<(JsonValue, String, String, String), Failure> {
    let fields = body.object().map_err(schema_failure)?;
    let reference = json_member(fields, "ref")
        .and_then(JsonValue::string)
        .map_err(schema_failure)?
        .to_owned();
    let target = json_member(fields, "object")
        .and_then(JsonValue::object)
        .map_err(schema_failure)?;
    let kind = json_member(target, "type")
        .and_then(JsonValue::string)
        .map_err(schema_failure)?
        .to_owned();
    let sha = json_member(target, "sha")
        .and_then(JsonValue::string)
        .map_err(schema_failure)?
        .to_owned();
    Ok((
        object([
            ("ref", string(&reference)),
            ("sha", string(&sha)),
            ("type", string(&kind)),
        ]),
        reference,
        kind,
        sha,
    ))
}

fn normalize_rulesets(body: &JsonValue, target: &str) -> Result<(JsonValue, bool), Failure> {
    let rulesets = body.array().map_err(schema_failure)?;
    let mut active_ids = Vec::new();
    for ruleset in rulesets {
        let fields = ruleset.object().map_err(schema_failure)?;
        let id = json_member(fields, "id")
            .and_then(JsonValue::number)
            .map_err(schema_failure)?;
        let observed_target = json_member(fields, "target")
            .and_then(JsonValue::string)
            .map_err(schema_failure)?;
        let enforcement = json_member(fields, "enforcement")
            .and_then(JsonValue::string)
            .map_err(schema_failure)?;
        if observed_target == target && enforcement == "active" {
            active_ids.push(number(id));
        }
    }
    active_ids.sort_by_key(|value| value.number().unwrap_or_default());
    let matched = !active_ids.is_empty();
    Ok((
        object([
            ("activeRulesetIds", JsonValue::Array(active_ids)),
            ("target", string(target)),
        ]),
        matched,
    ))
}

fn schema_failure(error: String) -> Failure {
    Failure::new("governance.response.schema", error)
}

fn observed(
    control: &ControlPolicy,
    value: JsonValue,
    matched: bool,
    http_status: Option<u16>,
) -> Observation {
    Observation {
        control_id: control.id.clone(),
        status: ObservationStatus::Observed,
        normalized_value: Some(value),
        endpoint_id: Some(control.endpoint.clone()),
        http_status,
        residual_assumption_id: None,
        evaluation: if matched {
            Evaluation::Matched
        } else {
            Evaluation::Mismatched
        },
    }
}

fn unavailable(control: &ControlPolicy, status: u16) -> Result<Observation, Failure> {
    if crate::mutation::active("unavailable-governance-is-matched") {
        return Ok(observed(
            control,
            object([
                ("availability", string("unavailable")),
                ("httpStatus", number(u64::from(status))),
            ]),
            true,
            Some(status),
        ));
    }
    let residual = control.residual_assumption.clone().ok_or_else(|| {
        Failure::new(
            "governance.residual.undefined",
            format!(
                "control {} became unavailable without a residual",
                control.id
            ),
        )
    })?;
    Ok(Observation {
        control_id: control.id.clone(),
        status: ObservationStatus::Unavailable,
        normalized_value: None,
        endpoint_id: Some(control.endpoint.clone()),
        http_status: Some(status),
        residual_assumption_id: Some(residual),
        evaluation: Evaluation::ResidualAssumption,
    })
}

fn not_applicable(control: &ControlPolicy) -> Observation {
    Observation {
        control_id: control.id.clone(),
        status: ObservationStatus::NotApplicable,
        normalized_value: None,
        endpoint_id: None,
        http_status: None,
        residual_assumption_id: None,
        evaluation: Evaluation::NotApplicable,
    }
}

fn compare_baseline(
    path: &Path,
    plan: &ReleasePlan,
    runtime: &GithubRuntime,
    bindings: &DeclaredGovernanceBindings,
    observations: &BTreeMap<String, Observation>,
) -> Result<String, Failure> {
    let bytes = read_bounded_regular(path, MAX_POLICY_BYTES, "governance baseline")
        .map_err(|error| Failure::new("governance.baseline.input", error))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Failure::new("governance.baseline.input", "baseline is not UTF-8"))?;
    let value =
        parse_json(text).map_err(|error| Failure::new("governance.baseline.input", error))?;
    let fields = value
        .object()
        .map_err(|error| Failure::new("governance.baseline.schema", error))?;
    let expected_keys = [
        "apiPolicySha256",
        "baselineSha256",
        "candidateBranch",
        "candidateSha",
        "governanceDeclarationSha256",
        "governanceProfileSha256",
        "observations",
        "phase",
        "planSha256",
        "predecessorPhase",
        "predecessorSha256",
        "repository",
        "repositoryId",
        "residualAssumptionSetSha256",
        "residualAssumptions",
        "runAttempt",
        "runId",
        "schemaVersion",
        "tag",
        "workflowRef",
        "workflowSha",
    ];
    require_json_keys(fields, &expected_keys)
        .map_err(|error| Failure::new("governance.baseline.schema", error))?;
    if json_member(fields, "schemaVersion").and_then(JsonValue::number) != Ok(1)
        || json_member(fields, "phase").and_then(JsonValue::string) != Ok("resolve")
        || json_member(fields, "planSha256").and_then(JsonValue::string)
            != Ok(plan.plan_sha256.as_str())
        || json_member(fields, "repositoryId").and_then(JsonValue::number)
            != Ok(runtime.repository.numeric_id)
        || json_member(fields, "repository").and_then(JsonValue::string)
            != Ok(runtime.repository.full_name.as_str())
        || json_member(fields, "candidateSha").and_then(JsonValue::string)
            != Ok(plan.resolution.candidate_sha.as_str())
        || json_member(fields, "tag").and_then(JsonValue::string) != Ok(plan.tag.as_str())
        || json_member(fields, "governanceDeclarationSha256").and_then(JsonValue::string)
            != Ok(bindings.declaration_sha256.as_str())
        || !matches!(json_member(fields, "baselineSha256"), Ok(JsonValue::Null))
        || !matches!(json_member(fields, "predecessorPhase"), Ok(JsonValue::Null))
        || !matches!(
            json_member(fields, "predecessorSha256"),
            Ok(JsonValue::Null)
        )
    {
        return Err(Failure::new(
            "governance.baseline.binding",
            "resolve baseline differs from the plan, runtime, or declaration",
        ));
    }
    let baseline =
        parse_observations(json_member(fields, "observations").map_err(schema_failure)?)?;
    if baseline.len() != observations.len() {
        return Err(Failure::new(
            "governance.baseline.inventory",
            "baseline observation inventory differs",
        ));
    }
    for (id, current) in observations {
        let prior = baseline.get(id).ok_or_else(|| {
            Failure::new(
                "governance.baseline.inventory",
                format!("baseline lacks control {id}"),
            )
        })?;
        if prior.status != current.status
            || prior.evaluation != current.evaluation
            || prior.normalized_value != current.normalized_value
            || prior.residual_assumption_id != current.residual_assumption_id
        {
            return Err(Failure::new(
                "governance.baseline.changed",
                format!("security-relevant governance control {id} changed"),
            ));
        }
    }
    Ok(hell_testkit::sha256_bytes(&bytes).hex())
}

fn require_predecessor(
    path: &Path,
    expected_phase: &str,
    baseline_sha256: &str,
    plan: &ReleasePlan,
    runtime: &GithubRuntime,
    bindings: &DeclaredGovernanceBindings,
) -> Result<String, Failure> {
    let bytes = read_bounded_regular(path, MAX_POLICY_BYTES, "governance predecessor")
        .map_err(|error| Failure::new("governance.predecessor.input", error))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Failure::new("governance.predecessor.input", "predecessor is not UTF-8"))?;
    let value =
        parse_json(text).map_err(|error| Failure::new("governance.predecessor.schema", error))?;
    let fields = value
        .object()
        .map_err(|error| Failure::new("governance.predecessor.schema", error))?;
    let expected_keys = [
        "apiPolicySha256",
        "baselineSha256",
        "candidateBranch",
        "candidateSha",
        "governanceDeclarationSha256",
        "governanceProfileSha256",
        "observations",
        "phase",
        "planSha256",
        "predecessorPhase",
        "predecessorSha256",
        "repository",
        "repositoryId",
        "residualAssumptionSetSha256",
        "residualAssumptions",
        "runAttempt",
        "runId",
        "schemaVersion",
        "tag",
        "workflowRef",
        "workflowSha",
    ];
    require_json_keys(fields, &expected_keys)
        .map_err(|error| Failure::new("governance.predecessor.schema", error))?;
    if json_member(fields, "schemaVersion").and_then(JsonValue::number) != Ok(1)
        || json_member(fields, "phase").and_then(JsonValue::string) != Ok(expected_phase)
        || json_member(fields, "baselineSha256").and_then(JsonValue::string) != Ok(baseline_sha256)
        || json_member(fields, "planSha256").and_then(JsonValue::string)
            != Ok(plan.plan_sha256.as_str())
        || json_member(fields, "repository").and_then(JsonValue::string)
            != Ok(runtime.repository.full_name.as_str())
        || json_member(fields, "repositoryId").and_then(JsonValue::number)
            != Ok(runtime.repository.numeric_id)
        || json_member(fields, "candidateSha").and_then(JsonValue::string)
            != Ok(plan.resolution.candidate_sha.as_str())
        || json_member(fields, "tag").and_then(JsonValue::string) != Ok(plan.tag.as_str())
        || json_member(fields, "governanceDeclarationSha256").and_then(JsonValue::string)
            != Ok(bindings.declaration_sha256.as_str())
    {
        return Err(Failure::new(
            "governance.predecessor.binding",
            "governance predecessor differs from the baseline, plan, runtime, or declaration",
        ));
    }
    Ok(hell_testkit::sha256_bytes(&bytes).hex())
}

fn parse_observations(value: &JsonValue) -> Result<BTreeMap<String, Observation>, Failure> {
    let mut observations = BTreeMap::new();
    for value in value.array().map_err(schema_failure)? {
        let fields = value.object().map_err(schema_failure)?;
        require_json_keys(
            fields,
            &[
                "controlId",
                "endpointId",
                "evaluation",
                "httpStatus",
                "normalizedValue",
                "residualAssumptionId",
                "status",
            ],
        )
        .map_err(|error| Failure::new("governance.baseline.schema", error))?;
        let id = json_member(fields, "controlId")
            .and_then(JsonValue::string)
            .map_err(schema_failure)?
            .to_owned();
        let status = match json_member(fields, "status")
            .and_then(JsonValue::string)
            .map_err(schema_failure)?
        {
            "observed" => ObservationStatus::Observed,
            "unavailable" => ObservationStatus::Unavailable,
            "not-applicable" => ObservationStatus::NotApplicable,
            _ => return Err(Failure::new("governance.baseline.schema", "unknown status")),
        };
        let evaluation = match json_member(fields, "evaluation")
            .and_then(JsonValue::string)
            .map_err(schema_failure)?
        {
            "matched" => Evaluation::Matched,
            "mismatched" => Evaluation::Mismatched,
            "residual-assumption" => Evaluation::ResidualAssumption,
            "not-applicable" => Evaluation::NotApplicable,
            _ => {
                return Err(Failure::new(
                    "governance.baseline.schema",
                    "unknown evaluation",
                ));
            }
        };
        let normalized_value =
            match json_member(fields, "normalizedValue").map_err(schema_failure)? {
                JsonValue::Null => None,
                value => Some(value.clone()),
            };
        let endpoint_id = optional_json_string(fields, "endpointId")?;
        let residual_assumption_id = optional_json_string(fields, "residualAssumptionId")?;
        let http_status = match json_member(fields, "httpStatus").map_err(schema_failure)? {
            JsonValue::Null => None,
            value => Some(
                u16::try_from(value.number().map_err(schema_failure)?).map_err(|_| {
                    Failure::new("governance.baseline.schema", "HTTP status exceeds u16")
                })?,
            ),
        };
        let observation = Observation {
            control_id: id.clone(),
            status,
            normalized_value,
            endpoint_id,
            http_status,
            residual_assumption_id,
            evaluation,
        };
        if observations.insert(id.clone(), observation).is_some() {
            return Err(Failure::new(
                "governance.baseline.inventory",
                format!("duplicate baseline control {id}"),
            ));
        }
    }
    Ok(observations)
}

pub(crate) fn fuzz_parse_api_response(value: &JsonValue) -> Result<(), String> {
    let fields = value.object()?;
    require_json_keys(
        fields,
        &["body", "endpointId", "httpStatus", "schemaVersion"],
    )?;
    if json_member(fields, "schemaVersion")?.number()? != 1 {
        return Err("governance API response fuzz frame schema differs".to_owned());
    }
    let endpoint = json_member(fields, "endpointId")?.string()?;
    let status = u16::try_from(json_member(fields, "httpStatus")?.number()?)
        .map_err(|_| "governance API response status exceeds u16".to_owned())?;
    let body = json_member(fields, "body")?;
    let (control_id, not_found, residual) = match endpoint {
        "repository" => ("default-branch", "mismatch", Some("repository-unavailable")),
        "repository-workflow-permissions" => (
            "workflow-token-permissions",
            "unavailable",
            Some("workflow-permissions-unavailable"),
        ),
        "repository-actions-permissions" => (
            "allowed-actions",
            "unavailable",
            Some("actions-permissions-unavailable"),
        ),
        "repository-rulesets" => (
            "branch-and-ruleset-protection",
            "unavailable",
            Some("rulesets-unavailable"),
        ),
        "repository-immutable-releases" => (
            "immutable-releases",
            "unavailable",
            Some("immutable-releases-unavailable"),
        ),
        "branch-ref" => ("candidate-head", "mismatch", None),
        "tag-ref" => ("release-tag", "matched-absence", None),
        _ => return Err("governance API response endpoint is unknown".to_owned()),
    };
    let control = ControlPolicy {
        id: control_id.to_owned(),
        endpoint: endpoint.to_owned(),
        treatment: "fuzz-parse".to_owned(),
        phases: vec![Phase::Resolve],
        residual_assumption: residual.map(str::to_owned),
    };
    if let Some(observation) = classify_non_success_response(&control, status, not_found)
        .map_err(|failure| format!("{}: {}", failure.code, failure.message))?
    {
        if (status == 403 || not_found == "unavailable")
            && (observation.status != ObservationStatus::Unavailable
                || observation.evaluation != Evaluation::ResidualAssumption)
        {
            return Err("unavailable governance response was treated as matched".to_owned());
        }
        return Ok(());
    }
    match endpoint {
        "repository" => parse_repository_response(body).map(|_| ()),
        "repository-workflow-permissions" => parse_workflow_permissions_response(body).map(|_| ()),
        "repository-actions-permissions" => parse_actions_permissions_response(body).map(|_| ()),
        "repository-rulesets" => normalize_rulesets(body, "branch").map(|_| ()),
        "repository-immutable-releases" => parse_immutable_releases_response(body).map(|_| ()),
        "branch-ref" | "tag-ref" => parse_git_reference_response(body).map(|_| ()),
        _ => unreachable!("endpoint inventory validated above"),
    }
    .map_err(|failure| format!("{}: {}", failure.code, failure.message))
}

pub(crate) fn fuzz_parse_profile(value: &JsonValue) -> Result<(), String> {
    let fields = value.object()?;
    require_json_keys(
        fields,
        &[
            "governanceDeclarationSha256",
            "observations",
            "phase",
            "planSha256",
            "repositoryId",
            "residualAssumptions",
            "schemaVersion",
        ],
    )?;
    if json_member(fields, "schemaVersion")?.number()? != 1
        || json_member(fields, "repositoryId")?.number()? == 0
    {
        return Err("governance profile schema or repository identity differs".to_owned());
    }
    require_digest(
        json_member(fields, "governanceDeclarationSha256")?.string()?,
        "governance declaration digest",
    )?;
    require_digest(
        json_member(fields, "planSha256")?.string()?,
        "governance plan digest",
    )?;
    Phase::parse(json_member(fields, "phase")?.string()?)?;
    let observations = parse_observations(json_member(fields, "observations")?)
        .map_err(|failure| format!("{}: {}", failure.code, failure.message))?;
    let expected_controls = [
        "allowed-actions",
        "branch-and-ruleset-protection",
        "candidate-head",
        "default-branch",
        "immutable-releases",
        "merge-queue",
        "release-tag",
        "repository-identity",
        "tag-protection",
        "workflow-token-permissions",
    ];
    if observations
        .keys()
        .map(String::as_str)
        .ne(expected_controls)
        || observations
            .values()
            .any(|value| !observation_is_coherent(value))
    {
        return Err("governance profile observation inventory or lattice differs".to_owned());
    }
    let residuals = json_member(fields, "residualAssumptions")?
        .array()?
        .iter()
        .map(JsonValue::string)
        .collect::<Result<Vec<_>, _>>()?;
    if residuals.windows(2).any(|pair| pair[0] >= pair[1])
        || observations
            .values()
            .filter_map(|observation| observation.residual_assumption_id.as_deref())
            .ne(residuals.iter().copied())
    {
        return Err("governance profile residual inventory differs".to_owned());
    }
    Ok(())
}

fn optional_json_string(
    fields: &BTreeMap<String, JsonValue>,
    key: &str,
) -> Result<Option<String>, Failure> {
    match json_member(fields, key).map_err(schema_failure)? {
        JsonValue::Null => Ok(None),
        value => value
            .string()
            .map(|value| Some(value.to_owned()))
            .map_err(schema_failure),
    }
}

#[derive(Default)]
pub(crate) struct TomlDocument {
    tables: BTreeMap<String, BTreeMap<String, String>>,
    arrays: BTreeMap<String, Vec<BTreeMap<String, String>>>,
}

enum TomlLocation {
    Table(String),
    Array(String, usize),
}

impl TomlDocument {
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        if text.contains('\0') {
            return Err("TOML input contains a NUL byte".to_owned());
        }
        let mut document = Self::default();
        document.tables.insert(String::new(), BTreeMap::new());
        let mut location = TomlLocation::Table(String::new());
        for (index, original) in text.lines().enumerate() {
            let line_number = index + 1;
            let line = strip_toml_comment(original)?.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(name) = line
                .strip_prefix("[[")
                .and_then(|value| value.strip_suffix("]]"))
            {
                require_identifier(name, "array table")?;
                let tables = document.arrays.entry(name.to_owned()).or_default();
                tables.push(BTreeMap::new());
                location = TomlLocation::Array(name.to_owned(), tables.len() - 1);
                continue;
            }
            if let Some(name) = line
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
            {
                require_identifier(name, "table")?;
                if document
                    .tables
                    .insert(name.to_owned(), BTreeMap::new())
                    .is_some()
                {
                    return Err(format!("duplicate TOML table {name}"));
                }
                location = TomlLocation::Table(name.to_owned());
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("expected TOML assignment at line {line_number}"))?;
            let key = key.trim();
            require_identifier(key, "key")?;
            let value = value.trim();
            validate_toml_scalar(value)?;
            let target = match &location {
                TomlLocation::Table(name) => {
                    document.tables.get_mut(name).expect("current table exists")
                }
                TomlLocation::Array(name, index) => document
                    .arrays
                    .get_mut(name)
                    .and_then(|tables| tables.get_mut(*index))
                    .expect("current array table exists"),
            };
            if target.insert(key.to_owned(), value.to_owned()).is_some() {
                return Err(format!("duplicate TOML key {key} at line {line_number}"));
            }
        }
        Ok(document)
    }

    pub(crate) fn table(&self, name: &str) -> Result<&BTreeMap<String, String>, String> {
        self.tables
            .get(name)
            .ok_or_else(|| format!("missing TOML table {name}"))
    }

    pub(crate) fn arrays(&self, name: &str) -> Result<&[BTreeMap<String, String>], String> {
        self.arrays
            .get(name)
            .map(Vec::as_slice)
            .ok_or_else(|| format!("missing TOML array table {name}"))
    }

    pub(crate) fn require_table_inventory(&self, expected: &[&str]) -> Result<(), String> {
        let observed = self
            .tables
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let expected = expected.iter().copied().collect::<BTreeSet<_>>();
        if observed != expected {
            return Err(format!("TOML table inventory differs: {observed:?}"));
        }
        Ok(())
    }

    pub(crate) fn require_array_inventory(&self, expected: &[&str]) -> Result<(), String> {
        let observed = self
            .arrays
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let expected = expected.iter().copied().collect::<BTreeSet<_>>();
        if observed != expected {
            return Err(format!("TOML array-table inventory differs: {observed:?}"));
        }
        Ok(())
    }
}

fn strip_toml_comment(line: &str) -> Result<&str, String> {
    let mut quoted = false;
    for (index, character) in line.char_indices() {
        match character {
            '"' => quoted = !quoted,
            '#' if !quoted => return Ok(&line[..index]),
            '\\' if quoted => return Err("TOML escapes are not accepted".to_owned()),
            _ => {}
        }
    }
    if quoted {
        return Err("unterminated TOML string".to_owned());
    }
    Ok(line)
}

fn validate_toml_scalar(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.contains(['\n', '\r'])
        || (value.starts_with('[') && !value.ends_with(']'))
    {
        return Err("invalid or multiline TOML scalar".to_owned());
    }
    Ok(())
}

pub(crate) fn require_identifier(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!("invalid TOML {label} {value:?}"));
    }
    Ok(())
}

pub(crate) fn require_keys(
    values: &BTreeMap<String, String>,
    expected: &[&str],
) -> Result<(), String> {
    let observed = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if observed != expected {
        return Err(format!("TOML key inventory differs: {observed:?}"));
    }
    Ok(())
}

pub(crate) fn require_allowed_keys(
    values: &BTreeMap<String, String>,
    allowed: &[&str],
) -> Result<(), String> {
    let allowed = allowed.iter().copied().collect::<BTreeSet<_>>();
    if let Some(key) = values.keys().find(|key| !allowed.contains(key.as_str())) {
        return Err(format!("unknown TOML key {key}"));
    }
    Ok(())
}

pub(crate) fn member<'a>(
    values: &'a BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, String> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing TOML key {key}"))
}

fn take(values: &mut BTreeMap<String, String>, key: &str) -> Result<String, String> {
    values
        .remove(key)
        .ok_or_else(|| format!("missing TOML key {key}"))
}

pub(crate) fn quoted(value: &str) -> Result<String, String> {
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| format!("expected quoted TOML string, observed {value:?}"))?;
    if value.contains(['"', '\\', '\n', '\r']) {
        return Err("escaped or multiline TOML strings are not accepted".to_owned());
    }
    Ok(value.to_owned())
}

pub(crate) fn boolean(value: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("expected TOML boolean, observed {value:?}")),
    }
}

pub(crate) fn integer(value: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("expected unsigned TOML integer, observed {value:?}"))?;
    if value != parsed.to_string() {
        return Err("TOML integer is not canonical".to_owned());
    }
    Ok(parsed)
}

pub(crate) fn string_array(value: &str) -> Result<Vec<String>, String> {
    let inner = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| format!("expected TOML string array, observed {value:?}"))?
        .trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    inner.split(',').map(|value| quoted(value.trim())).collect()
}

fn require_json_keys(
    values: &BTreeMap<String, JsonValue>,
    expected: &[&str],
) -> Result<(), String> {
    let observed = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if observed != expected {
        return Err(format!("JSON key inventory differs: {observed:?}"));
    }
    Ok(())
}
