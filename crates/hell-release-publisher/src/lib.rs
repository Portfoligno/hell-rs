mod digest;
mod github_runtime;
mod json;
mod mutation;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

const MAX_JSON_BYTES: u64 = 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_BUNDLE_FILES: usize = 128;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 4096;
const OPERATION_TIMEOUT: Duration = Duration::from_mins(5);
const REQUEST_TIMEOUT: Duration = Duration::from_mins(1);
const MARKER_PREFIX: &str = "hell-rs-release-plan-sha256:";
const ARTIFACT_ID_MARKER_PREFIX: &str = "hell-rs-input-artifact-id:";
const ARTIFACT_DIGEST_MARKER_PREFIX: &str = "hell-rs-input-artifact-digest:";
const GOVERNANCE_RESOLVE_MARKER_PREFIX: &str = "hell-rs-governance-resolve-sha256:";
const GOVERNANCE_PRE_ATTESTATION_MARKER_PREFIX: &str = "hell-rs-governance-pre-attestation-sha256:";
const GOVERNANCE_PRE_PUBLISH_MARKER_PREFIX: &str = "hell-rs-governance-pre-publish-sha256:";
const GOVERNANCE_SNAPSHOT_KEYS: &[&str] = &[
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
const ENVELOPE_KEYS: &[&str] = &[
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
];
const GOVERNANCE_CONTROLS: &[&str] = &[
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
const BUILD_ATTESTATION: &str = "github-provenance.sigstore.json";
const GATE_ATTESTATION: &str = "github-release-gate.sigstore.json";

#[must_use]
pub fn protocol_sha256(bytes: &[u8]) -> String {
    digest::sha256(bytes)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Failure {
    pub code: &'static str,
    pub message: String,
}

impl Failure {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        let mut message = message.into();
        if message.len() > MAX_DIAGNOSTIC_BYTES {
            let boundary = message
                .char_indices()
                .map(|(index, _)| index)
                .take_while(|index| *index <= MAX_DIAGNOSTIC_BYTES)
                .last()
                .unwrap_or(0);
            message.truncate(boundary);
        }
        Self { code, message }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Method {
    Get,
    Post,
    Patch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Host {
    Api,
    Upload,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub method: Method,
    pub host: Host,
    pub path: String,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

pub trait Transport {
    /// Sends one typed GitHub request before the supplied absolute deadline.
    ///
    /// # Errors
    ///
    /// Returns a stable failure when the request cannot complete or the
    /// response cannot be represented by this bounded transport.
    fn send(&mut self, request: Request, deadline: Instant) -> Result<Response, Failure>;
}

#[derive(Clone)]
pub struct ReleasePlan {
    repository: String,
    repository_id: u64,
    candidate_branch: String,
    candidate_sha: String,
    tag: String,
    version: String,
    prerelease: bool,
    conformance_plan_sha256: String,
    external_inputs_sha256: String,
    governance_declaration_sha256: String,
    governance_profile_sha256: String,
    residual_assumption_set_sha256: String,
    run_attempt: u64,
    run_id: u64,
    source_inventory_sha256: String,
    trusted_conformance_inputs_sha256: String,
    workflow_ref: String,
    workflow_sha: String,
    plan_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Resolve,
    PostAssembly,
    PreAttestation,
    PrePublish,
}

impl Phase {
    fn parse(value: &str) -> Result<Self, Failure> {
        match value {
            "resolve" => Ok(Self::Resolve),
            "post-assembly" => Ok(Self::PostAssembly),
            "pre-attestation" => Ok(Self::PreAttestation),
            "pre-publish" => Ok(Self::PrePublish),
            _ => Err(Failure::new(
                "publisher.phase.invalid",
                "phase must be resolve, post-assembly, pre-attestation, or pre-publish",
            )),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::PostAssembly => "post-assembly",
            Self::PreAttestation => "pre-attestation",
            Self::PrePublish => "pre-publish",
        }
    }
}

/// Dispatches the publisher command-line interface.
///
/// # Errors
///
/// Returns a stable failure for invalid arguments or any rejected publication
/// transition.
pub fn run(arguments: &[OsString]) -> Result<String, Failure> {
    let (command, arguments) = arguments
        .split_first()
        .ok_or_else(|| Failure::new("publisher.cli.usage", usage()))?;
    match command.to_str() {
        Some("check-remote-state") => check_remote_command(arguments),
        Some("stage-attestations") => stage_command(arguments),
        Some("publish") => publish_command(arguments),
        _ => Err(Failure::new("publisher.cli.usage", usage())),
    }
}

fn check_remote_command(arguments: &[OsString]) -> Result<String, Failure> {
    let options = Options::parse(arguments, &["--plan", "--phase", "--report"])?;
    let plan_path = options.path("--plan")?;
    let phase_text = options.text("--phase")?;
    let report_path = options.path("--report")?;
    let result = (|| {
        let phase = Phase::parse(&phase_text)?;
        let plan = ReleasePlan::read(&plan_path)?;
        let runtime = github_runtime::GithubRuntime::from_process()?;
        let mut transport = GithubTransport::new(runtime.credential());
        check_remote_state_with(&mut transport, &plan, phase)
    })();
    write_result_report(&report_path, &phase_text, &result)?;
    result?;
    Ok(format!("remote release state is stable for {phase_text}"))
}

fn stage_command(arguments: &[OsString]) -> Result<String, Failure> {
    let options = Options::parse(
        arguments,
        &[
            "--input",
            "--build-provenance-bundle",
            "--release-gate-bundle",
            "--output",
        ],
    )?;
    stage_attestations(
        &options.path("--input")?,
        &options.path("--build-provenance-bundle")?,
        &options.path("--release-gate-bundle")?,
        &options.path("--output")?,
    )?;
    Ok("staged exact attestation bundles without altering verified inputs".to_owned())
}

fn publish_command(arguments: &[OsString]) -> Result<String, Failure> {
    let options = Options::parse(
        arguments,
        &[
            "--plan",
            "--input",
            "--expected-artifact-id",
            "--expected-artifact-digest",
            "--governance-baseline",
            "--governance-receipt",
            "--report",
        ],
    )?;
    let plan_path = options.path("--plan")?;
    let input = options.path("--input")?;
    let expected_artifact_id_text = options.text("--expected-artifact-id")?;
    let expected_digest = options.text("--expected-artifact-digest")?;
    let governance_baseline = options.path("--governance-baseline")?;
    let governance_receipt = options.path("--governance-receipt")?;
    let report_path = options.path("--report")?;
    let result = (|| {
        let expected_artifact_id = expected_artifact_id_text.parse::<u64>().map_err(|_| {
            Failure::new(
                "publisher.artifact-id.invalid",
                "expected artifact ID must be a numeric GitHub artifact ID",
            )
        })?;
        if expected_artifact_id == 0 {
            return Err(Failure::new(
                "publisher.artifact-id.invalid",
                "expected artifact ID must be nonzero",
            ));
        }
        require_digest(&expected_digest, "publisher.artifact-digest.invalid")?;
        let plan = ReleasePlan::read(&plan_path)?;
        let bundle = PublicationBundle::read(
            &input,
            &plan,
            &expected_digest,
            &governance_baseline,
            &governance_receipt,
        )?;
        let runtime = github_runtime::GithubRuntime::from_process()?;
        let mut transport = GithubTransport::new(runtime.credential());
        publish_with(
            &mut transport,
            &plan,
            &bundle,
            expected_artifact_id,
            &expected_digest,
        )
    })();
    write_result_report(&report_path, "publish", &result)?;
    let receipt = result?;
    Ok(format!(
        "release {} reached state {}",
        receipt.tag, receipt.state
    ))
}

impl ReleasePlan {
    #[must_use]
    pub fn plan_sha256(&self) -> &str {
        &self.plan_sha256
    }

    /// Reads and authenticates a canonical release plan.
    ///
    /// # Errors
    ///
    /// Returns a stable failure when the plan is missing, malformed, outside
    /// its size bound, or fails an identity or digest binding.
    pub fn read(path: &Path) -> Result<Self, Failure> {
        let bytes = read_regular(path, MAX_JSON_BYTES, "publisher.plan.input")?;
        if !bytes.ends_with(b"\n") {
            return Err(Failure::new(
                "publisher.plan.trailing-lf",
                "release plan lacks its required trailing LF",
            ));
        }
        let value = json::parse(&bytes, "publisher.plan.json")?;
        require_canonical_json(&bytes, &value, "publisher.plan.canonical")?;
        let fields = object(&value, "publisher.plan.schema")?;
        validate_plan_keys(fields)?;
        if number(fields, "schemaVersion", "publisher.plan.schema")? != 2
            || string(fields, "releaseBinary", "publisher.plan.schema")? != "hell"
            || string(fields, "releasePackage", "publisher.plan.schema")? != "hell-cli"
        {
            return Err(Failure::new(
                "publisher.plan.schema",
                "release plan schema or package identity differs",
            ));
        }
        let repository = string(fields, "repository", "publisher.plan.schema")?.to_owned();
        validate_repository(&repository)?;
        let repository_id = number(fields, "repositoryId", "publisher.plan.schema")?;
        if repository_id == 0 {
            return Err(Failure::new(
                "publisher.repository.identity",
                "release plan repository ID must be numeric and nonzero",
            ));
        }
        let candidate_sha = string(fields, "candidateSha", "publisher.plan.schema")?.to_owned();
        require_sha(&candidate_sha, "publisher.plan.candidate-sha")?;
        require_sha(
            string(fields, "workflowSha", "publisher.plan.schema")?,
            "publisher.plan.workflow-sha",
        )?;
        for key in [
            "buildInputsSha256",
            "changelogSha256",
            "conformancePlanSha256",
            "externalInputsSha256",
            "governanceDeclarationSha256",
            "governanceProfileSha256",
            "policySha256",
            "residualAssumptionSetSha256",
            "sourceInventorySha256",
            "trustedConformanceInputsSha256",
            "planSha256",
        ] {
            require_digest(
                string(fields, key, "publisher.plan.schema")?,
                "publisher.plan.digest",
            )?;
        }
        validate_expected_platforms(fields)?;
        let plan_sha256 = string(fields, "planSha256", "publisher.plan.schema")?.to_owned();
        let mut without = fields.clone();
        without.remove("planSha256");
        let mut canonical = serde_json::to_vec(&Value::Object(without)).map_err(|error| {
            Failure::new(
                "publisher.plan.canonical",
                format!("cannot canonicalize release plan: {error}"),
            )
        })?;
        canonical.push(b'\n');
        if digest::sha256(&canonical) != plan_sha256 {
            return Err(Failure::new(
                "publisher.plan.self-digest",
                "release plan self-digest differs",
            ));
        }
        release_plan_from_fields(
            fields,
            repository,
            repository_id,
            candidate_sha,
            plan_sha256,
        )
    }
}

fn release_plan_from_fields(
    fields: &Map<String, Value>,
    repository: String,
    repository_id: u64,
    candidate_sha: String,
    plan_sha256: String,
) -> Result<ReleasePlan, Failure> {
    Ok(ReleasePlan {
        repository,
        repository_id,
        candidate_branch: string(fields, "candidateBranch", "publisher.plan.schema")?.to_owned(),
        candidate_sha,
        tag: string(fields, "tag", "publisher.plan.schema")?.to_owned(),
        version: string(fields, "version", "publisher.plan.schema")?.to_owned(),
        prerelease: boolean(fields, "prerelease", "publisher.plan.schema")?,
        conformance_plan_sha256: string(fields, "conformancePlanSha256", "publisher.plan.schema")?
            .to_owned(),
        external_inputs_sha256: string(fields, "externalInputsSha256", "publisher.plan.schema")?
            .to_owned(),
        governance_declaration_sha256: string(
            fields,
            "governanceDeclarationSha256",
            "publisher.plan.schema",
        )?
        .to_owned(),
        governance_profile_sha256: string(
            fields,
            "governanceProfileSha256",
            "publisher.plan.schema",
        )?
        .to_owned(),
        residual_assumption_set_sha256: string(
            fields,
            "residualAssumptionSetSha256",
            "publisher.plan.schema",
        )?
        .to_owned(),
        run_attempt: number(fields, "runAttempt", "publisher.plan.schema")?,
        run_id: number(fields, "runId", "publisher.plan.schema")?,
        source_inventory_sha256: string(fields, "sourceInventorySha256", "publisher.plan.schema")?
            .to_owned(),
        trusted_conformance_inputs_sha256: string(
            fields,
            "trustedConformanceInputsSha256",
            "publisher.plan.schema",
        )?
        .to_owned(),
        workflow_ref: string(fields, "workflowRef", "publisher.plan.schema")?.to_owned(),
        workflow_sha: string(fields, "workflowSha", "publisher.plan.schema")?.to_owned(),
        plan_sha256,
    })
}

fn validate_plan_keys(fields: &Map<String, Value>) -> Result<(), Failure> {
    exact_keys(
        fields,
        &[
            "actor",
            "actorId",
            "buildInputsSha256",
            "candidateBranch",
            "candidateSha",
            "changelogSha256",
            "commitAuthor",
            "commitCommitter",
            "conformancePlanSha256",
            "conformanceStandard",
            "defaultBranch",
            "externalInputsSha256",
            "expectedPlatforms",
            "governanceDeclarationSha256",
            "governanceProfileSha256",
            "planSha256",
            "policySha256",
            "prerelease",
            "releaseBinary",
            "releaseEvaluationInstant",
            "releasePackage",
            "repository",
            "repositoryId",
            "residualAssumptionSetSha256",
            "runAttempt",
            "runId",
            "schemaVersion",
            "sourceDateEpoch",
            "sourceInventorySha256",
            "tag",
            "trustedConformanceInputsSha256",
            "version",
            "workflowRef",
            "workflowSha",
        ],
        "publisher.plan.schema",
    )
}

fn validate_expected_platforms(fields: &Map<String, Value>) -> Result<(), Failure> {
    let expected_platforms = fields
        .get("expectedPlatforms")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            Failure::new(
                "publisher.plan.platforms",
                "expectedPlatforms is not an array",
            )
        })?;
    if expected_platforms
        != &[
            Value::String("linux-x86_64".to_owned()),
            Value::String("macos-aarch64".to_owned()),
            Value::String("windows-x86_64".to_owned()),
        ]
    {
        return Err(Failure::new(
            "publisher.plan.platforms",
            "release plan platform inventory differs",
        ));
    }
    Ok(())
}

#[derive(Clone)]
struct GovernanceBindings {
    resolve: String,
    pre_attestation: String,
    pre_publish: String,
}

struct GovernanceSnapshot {
    sha256: String,
    predecessor_sha256: Option<String>,
    observation_projection: BTreeMap<String, Value>,
}

impl GovernanceBindings {
    fn read(baseline: &Path, receipt: &Path, plan: &ReleasePlan) -> Result<Self, Failure> {
        let baseline = read_governance_snapshot(baseline, plan, "resolve", None, None)?;
        let receipt = read_governance_snapshot(
            receipt,
            plan,
            "pre-publish",
            Some(&baseline.sha256),
            Some("pre-attestation"),
        )?;
        if receipt.observation_projection != baseline.observation_projection {
            return Err(Failure::new(
                "publisher.governance.changed",
                "pre-publish governance observations differ from the resolve baseline",
            ));
        }
        let pre_attestation_sha256 = receipt.predecessor_sha256.ok_or_else(|| {
            Failure::new(
                "publisher.governance.predecessor",
                "pre-publish governance receipt lacks its pre-attestation predecessor",
            )
        })?;
        Ok(Self {
            resolve: baseline.sha256,
            pre_attestation: pre_attestation_sha256,
            pre_publish: receipt.sha256,
        })
    }
}

fn read_governance_snapshot(
    path: &Path,
    plan: &ReleasePlan,
    expected_phase: &str,
    expected_baseline_sha256: Option<&str>,
    expected_predecessor_phase: Option<&str>,
) -> Result<GovernanceSnapshot, Failure> {
    let bytes = read_regular(path, MAX_JSON_BYTES, "publisher.governance.input")?;
    let value = json::parse(&bytes, "publisher.governance.json")?;
    require_canonical_json(&bytes, &value, "publisher.governance.canonical")?;
    let fields = object(&value, "publisher.governance.schema")?;
    exact_keys(
        fields,
        GOVERNANCE_SNAPSHOT_KEYS,
        "publisher.governance.schema",
    )?;
    validate_governance_plan_binding(fields, plan, expected_phase)?;
    require_optional_string(
        fields,
        "baselineSha256",
        expected_baseline_sha256,
        true,
        "publisher.governance.baseline",
    )?;
    require_optional_string(
        fields,
        "predecessorPhase",
        expected_predecessor_phase,
        false,
        "publisher.governance.predecessor",
    )?;
    let predecessor_sha256 = if expected_predecessor_phase.is_some() {
        let predecessor = string(
            fields,
            "predecessorSha256",
            "publisher.governance.predecessor",
        )?;
        require_digest(predecessor, "publisher.governance.predecessor")?;
        Some(predecessor.to_owned())
    } else {
        if fields.get("predecessorSha256") != Some(&Value::Null) {
            return Err(Failure::new(
                "publisher.governance.predecessor",
                "resolve governance receipt has an unexpected predecessor digest",
            ));
        }
        None
    };
    let observation_projection = validate_governance_evidence(fields, plan, expected_phase)?;
    Ok(GovernanceSnapshot {
        sha256: digest::sha256(&bytes),
        predecessor_sha256,
        observation_projection,
    })
}

fn validate_governance_plan_binding(
    fields: &Map<String, Value>,
    plan: &ReleasePlan,
    expected_phase: &str,
) -> Result<(), Failure> {
    if number(fields, "schemaVersion", "publisher.governance.schema")? != 1
        || string(fields, "phase", "publisher.governance.schema")? != expected_phase
        || string(fields, "planSha256", "publisher.governance.schema")? != plan.plan_sha256
        || string(fields, "repository", "publisher.governance.schema")? != plan.repository
        || number(fields, "repositoryId", "publisher.governance.schema")? != plan.repository_id
        || string(fields, "candidateBranch", "publisher.governance.schema")?
            != plan.candidate_branch
        || string(fields, "candidateSha", "publisher.governance.schema")? != plan.candidate_sha
        || string(fields, "tag", "publisher.governance.schema")? != plan.tag
        || number(fields, "runAttempt", "publisher.governance.schema")? != plan.run_attempt
        || number(fields, "runId", "publisher.governance.schema")? != plan.run_id
        || string(fields, "workflowRef", "publisher.governance.schema")? != plan.workflow_ref
        || string(fields, "workflowSha", "publisher.governance.schema")? != plan.workflow_sha
        || string(
            fields,
            "governanceDeclarationSha256",
            "publisher.governance.schema",
        )? != plan.governance_declaration_sha256
    {
        return Err(Failure::new(
            "publisher.governance.binding",
            "governance receipt differs from the release plan",
        ));
    }
    for key in [
        "apiPolicySha256",
        "governanceProfileSha256",
        "residualAssumptionSetSha256",
    ] {
        require_digest(
            string(fields, key, "publisher.governance.schema")?,
            "publisher.governance.digest",
        )?;
    }
    Ok(())
}

fn validate_governance_evidence(
    fields: &Map<String, Value>,
    plan: &ReleasePlan,
    phase: &str,
) -> Result<BTreeMap<String, Value>, Failure> {
    let observations = fields
        .get("observations")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            Failure::new(
                "publisher.governance.observations",
                "governance observations are not an array",
            )
        })?;
    let (projection, active_residuals) = validate_governance_observations(observations)?;
    let residuals = fields
        .get("residualAssumptions")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            Failure::new(
                "publisher.governance.residuals",
                "governance residual assumptions are not an array",
            )
        })?;
    let observed_residuals = residuals
        .iter()
        .map(|value| {
            value.as_str().ok_or_else(|| {
                Failure::new(
                    "publisher.governance.residuals",
                    "governance residual assumption is not a string",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if observed_residuals.windows(2).any(|pair| pair[0] >= pair[1])
        || observed_residuals != active_residuals
    {
        return Err(Failure::new(
            "publisher.governance.residuals",
            "governance residual inventory is duplicated, unsorted, or differs from observations",
        ));
    }
    let residual_value = Value::Array(residuals.clone());
    if domain_digest(b"hell-rs:residual-assumption-set:1", &residual_value)?
        != string(
            fields,
            "residualAssumptionSetSha256",
            "publisher.governance.schema",
        )?
    {
        return Err(Failure::new(
            "publisher.governance.residual-digest",
            "governance residual-assumption digest differs",
        ));
    }
    validate_governance_profile(fields, plan, phase, observations, residuals)?;
    Ok(projection)
}

fn validate_governance_profile(
    fields: &Map<String, Value>,
    plan: &ReleasePlan,
    phase: &str,
    observations: &[Value],
    residuals: &[Value],
) -> Result<(), Failure> {
    let profile = serde_json::json!({
        "governanceDeclarationSha256": plan.governance_declaration_sha256,
        "observations": observations,
        "phase": phase,
        "planSha256": plan.plan_sha256,
        "repositoryId": plan.repository_id,
        "residualAssumptions": residuals,
        "schemaVersion": 1,
    });
    if domain_digest(b"hell-rs:governance-profile:1", &profile)?
        != string(
            fields,
            "governanceProfileSha256",
            "publisher.governance.schema",
        )?
    {
        return Err(Failure::new(
            "publisher.governance.profile-digest",
            "governance profile digest differs",
        ));
    }
    Ok(())
}

fn validate_governance_observations(
    observations: &[Value],
) -> Result<(BTreeMap<String, Value>, Vec<&str>), Failure> {
    if observations.len() != GOVERNANCE_CONTROLS.len() {
        return Err(Failure::new(
            "publisher.governance.observations",
            "governance control inventory length differs",
        ));
    }
    let mut projection = BTreeMap::new();
    let mut residuals = Vec::new();
    for (value, expected_control) in observations.iter().zip(GOVERNANCE_CONTROLS) {
        let fields = object(value, "publisher.governance.observations")?;
        exact_keys(
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
            "publisher.governance.observations",
        )?;
        if string(fields, "controlId", "publisher.governance.observations")? != *expected_control {
            return Err(Failure::new(
                "publisher.governance.observations",
                "governance control inventory or order differs",
            ));
        }
        let status = string(fields, "status", "publisher.governance.observations")?;
        let evaluation = string(fields, "evaluation", "publisher.governance.observations")?;
        let endpoint = fields.get("endpointId");
        let http_status = fields.get("httpStatus");
        let normalized = fields.get("normalizedValue").ok_or_else(|| {
            Failure::new(
                "publisher.governance.observations",
                "normalized value is absent",
            )
        })?;
        let residual = fields.get("residualAssumptionId");
        let coherent = match status {
            "observed" => {
                evaluation == "matched"
                    && endpoint
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty())
                    && http_status
                        .and_then(Value::as_u64)
                        .is_some_and(|value| (100..=599).contains(&value))
                    && !normalized.is_null()
                    && residual == Some(&Value::Null)
            }
            "unavailable" => {
                evaluation == "residual-assumption"
                    && endpoint
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty())
                    && http_status
                        .and_then(Value::as_u64)
                        .is_some_and(|value| (100..=599).contains(&value))
                    && normalized.is_null()
                    && residual
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty())
            }
            "not-applicable" => {
                evaluation == "not-applicable"
                    && endpoint == Some(&Value::Null)
                    && http_status == Some(&Value::Null)
                    && normalized.is_null()
                    && residual == Some(&Value::Null)
            }
            _ => false,
        };
        if !coherent {
            return Err(Failure::new(
                "publisher.governance.observations",
                format!("governance control {expected_control} has an incoherent state"),
            ));
        }
        if let Some(residual) = residual.and_then(Value::as_str) {
            residuals.push(residual);
        }
        projection.insert(
            (*expected_control).to_owned(),
            serde_json::json!({
                "evaluation": evaluation,
                "normalizedValue": normalized,
                "residualAssumptionId": residual,
                "status": status,
            }),
        );
    }
    Ok((projection, residuals))
}

fn require_optional_string(
    fields: &Map<String, Value>,
    key: &str,
    expected: Option<&str>,
    require_sha256: bool,
    code: &'static str,
) -> Result<(), Failure> {
    match (fields.get(key), expected) {
        (Some(Value::Null), None) => Ok(()),
        (Some(Value::String(observed)), Some(expected)) if observed == expected => {
            if require_sha256 {
                require_digest(observed, code)?;
            }
            Ok(())
        }
        _ => Err(Failure::new(
            code,
            format!("governance receipt {key} binding differs"),
        )),
    }
}

fn domain_digest(domain: &[u8], value: &Value) -> Result<String, Failure> {
    let canonical = canonical_json(value, "publisher.governance.canonical")?;
    let mut bytes = Vec::with_capacity(domain.len() + 1 + canonical.len());
    bytes.extend_from_slice(domain);
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(digest::sha256(&bytes))
}

/// Copies the verified release and adds the two distinct GitHub attestations.
///
/// # Errors
///
/// Returns a stable failure for unsafe input inventory, malformed bundles,
/// existing output, I/O failure, or failed atomic promotion.
pub fn stage_attestations(
    input: &Path,
    build_provenance: &Path,
    release_gate: &Path,
    output: &Path,
) -> Result<(), Failure> {
    if output.exists() {
        return Err(Failure::new(
            "publisher.stage.output-exists",
            "attestation staging output already exists",
        ));
    }
    let input_files = directory_inventory(input, "publisher.stage.input")?;
    if input_files.contains(BUILD_ATTESTATION) || input_files.contains(GATE_ATTESTATION) {
        return Err(Failure::new(
            "publisher.stage.inventory",
            "verified input already contains a staged attestation name",
        ));
    }
    validate_verified_inventory(&input_files)?;
    let build = read_regular(
        build_provenance,
        MAX_JSON_BYTES,
        "publisher.attestation.build",
    )?;
    let gate = read_regular(release_gate, MAX_JSON_BYTES, "publisher.attestation.gate")?;
    json::parse(&build, "publisher.attestation.build-json")?;
    json::parse(&gate, "publisher.attestation.gate-json")?;
    if build == gate {
        return Err(Failure::new(
            "publisher.attestation.distinct",
            "build and release-gate attestation bundles must be distinct",
        ));
    }
    let staging = staging_directory(output, "attest")?;
    fs::create_dir(&staging).map_err(|error| {
        Failure::new(
            "publisher.stage.create",
            format!("cannot create attestation staging directory: {error}"),
        )
    })?;
    let result = (|| {
        for name in &input_files {
            copy_new(&input.join(name), &staging.join(name), MAX_BUNDLE_BYTES)?;
        }
        write_new(&staging.join(BUILD_ATTESTATION), &build)?;
        write_new(&staging.join(GATE_ATTESTATION), &gate)?;
        sync_directory(&staging)?;
        fs::rename(&staging, output).map_err(|error| {
            Failure::new(
                "publisher.stage.promote",
                format!("cannot promote attestation staging directory: {error}"),
            )
        })?;
        sync_directory(output.parent().unwrap_or_else(|| Path::new(".")))
    })();
    if result.is_err() {
        let _cleanup_result = fs::remove_dir_all(&staging);
    }
    result
}

#[derive(Clone)]
pub struct PublicationBundle {
    files: BTreeMap<String, Asset>,
    governance: GovernanceBindings,
    input_artifact_digest: String,
}

#[derive(Clone)]
struct Asset {
    bytes: Vec<u8>,
    sha256: String,
}

impl PublicationBundle {
    /// Reads and validates the complete attested publication bundle.
    ///
    /// # Errors
    ///
    /// Returns a stable failure when inventory, size, subjects, attestations,
    /// or release-plan bindings differ.
    pub fn read(
        root: &Path,
        plan: &ReleasePlan,
        expected_digest: &str,
        governance_baseline: &Path,
        governance_receipt: &Path,
    ) -> Result<Self, Failure> {
        require_digest(expected_digest, "publisher.artifact-digest.invalid")?;
        let governance = GovernanceBindings::read(governance_baseline, governance_receipt, plan)?;
        let names = directory_inventory(root, "publisher.bundle.inventory")?;
        validate_verified_inventory(&names)?;
        for required in [BUILD_ATTESTATION, GATE_ATTESTATION] {
            if !names.contains(required) {
                return Err(Failure::new(
                    "publisher.bundle.inventory",
                    format!("attested release set lacks {required:?}"),
                ));
            }
        }
        let mut files = BTreeMap::new();
        let mut total = 0_u64;
        for name in names {
            let bytes = read_regular(&root.join(&name), MAX_BUNDLE_BYTES, "publisher.bundle.file")?;
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| Failure::new("publisher.bundle.size", "bundle size overflow"))?;
            if total > MAX_BUNDLE_BYTES {
                return Err(Failure::new(
                    "publisher.bundle.size",
                    "attested release set exceeds the cumulative size bound",
                ));
            }
            files.insert(
                name,
                Asset {
                    sha256: digest::sha256(&bytes),
                    bytes,
                },
            );
        }
        validate_subjects(&files)?;
        validate_shallow_publication_envelope(&files, plan, &governance)?;
        json::parse(
            &files
                .get(BUILD_ATTESTATION)
                .ok_or_else(|| {
                    Failure::new("publisher.bundle.inventory", "build attestation is absent")
                })?
                .bytes,
            "publisher.attestation.build-json",
        )?;
        json::parse(
            &files
                .get(GATE_ATTESTATION)
                .ok_or_else(|| {
                    Failure::new("publisher.bundle.inventory", "gate attestation is absent")
                })?
                .bytes,
            "publisher.attestation.gate-json",
        )?;
        Ok(Self {
            files,
            governance,
            input_artifact_digest: expected_digest.to_owned(),
        })
    }
}

fn validate_shallow_publication_envelope(
    files: &BTreeMap<String, Asset>,
    plan: &ReleasePlan,
    governance: &GovernanceBindings,
) -> Result<(), Failure> {
    if mutation::active(mutation::Mutant::SkipShallowEnvelopeVerification) {
        return Ok(());
    }
    validate_envelope(files, plan, governance)?;
    validate_envelope_receipt(files)
}

fn validate_verified_inventory(names: &BTreeSet<String>) -> Result<(), Failure> {
    for required in [
        "SUBJECTS.sha256",
        "release-gate.json",
        "primary-verifier-decision.json",
        "primary-verifier-report.json",
        "independent-verifier-decision.json",
        "independent-verifier-report.json",
        "verifier-agreement.json",
        "publication-envelope.json",
        "publication-envelope-verification.json",
    ] {
        if !names.contains(required) {
            return Err(Failure::new(
                "publisher.bundle.inventory",
                format!("verified release set lacks {required:?}"),
            ));
        }
    }
    Ok(())
}

fn validate_subjects(files: &BTreeMap<String, Asset>) -> Result<(), Failure> {
    let manifest = files
        .get("SUBJECTS.sha256")
        .ok_or_else(|| Failure::new("publisher.subjects.missing", "SUBJECTS.sha256 is absent"))?;
    if !manifest.bytes.ends_with(b"\n") {
        return Err(Failure::new(
            "publisher.subjects.trailing-lf",
            "SUBJECTS.sha256 lacks a trailing LF",
        ));
    }
    let text = std::str::from_utf8(&manifest.bytes)
        .map_err(|_| Failure::new("publisher.subjects.utf8", "SUBJECTS.sha256 is not UTF-8"))?;
    let mut previous = None::<String>;
    let mut count = 0;
    for line in text.lines() {
        let (digest, name) = line.split_once("  ").ok_or_else(|| {
            Failure::new(
                "publisher.subjects.syntax",
                "SUBJECTS.sha256 line is malformed",
            )
        })?;
        require_digest(digest, "publisher.subjects.digest")?;
        validate_asset_name(name)?;
        if previous.as_deref().is_some_and(|value| value >= name) {
            return Err(Failure::new(
                "publisher.subjects.order",
                "SUBJECTS.sha256 names are duplicated or unsorted",
            ));
        }
        let asset = files.get(name).ok_or_else(|| {
            Failure::new(
                "publisher.subjects.missing-file",
                format!("subject {name:?} is absent from the release set"),
            )
        })?;
        if asset.sha256 != digest {
            return Err(Failure::new(
                "publisher.subjects.digest",
                format!("subject {name:?} digest differs"),
            ));
        }
        previous = Some(name.to_owned());
        count += 1;
    }
    if count == 0 {
        return Err(Failure::new(
            "publisher.subjects.empty",
            "SUBJECTS.sha256 contains no subjects",
        ));
    }
    Ok(())
}

fn validate_envelope(
    files: &BTreeMap<String, Asset>,
    plan: &ReleasePlan,
    governance: &GovernanceBindings,
) -> Result<(), Failure> {
    let envelope = files.get("publication-envelope.json").ok_or_else(|| {
        Failure::new(
            "publisher.envelope.missing",
            "publication envelope is absent",
        )
    })?;
    let value = json::parse(&envelope.bytes, "publisher.envelope.json")?;
    require_canonical_json(&envelope.bytes, &value, "publisher.envelope.canonical")?;
    let fields = object(&value, "publisher.envelope.schema")?;
    exact_keys(fields, ENVELOPE_KEYS, "publisher.envelope.schema")?;
    validate_envelope_plan_binding(fields, plan)?;
    validate_envelope_governance_binding(fields, governance)?;
    validate_envelope_repository_binding(fields, plan)?;
    validate_envelope_file_bindings(fields, files)?;
    Ok(())
}

fn validate_envelope_plan_binding(
    fields: &Map<String, Value>,
    plan: &ReleasePlan,
) -> Result<(), Failure> {
    if number(fields, "schemaVersion", "publisher.envelope.schema")? != 1
        || !boolean(fields, "admitted", "publisher.envelope.schema")?
        || number(fields, "repositoryId", "publisher.envelope.schema")? != plan.repository_id
        || string(fields, "candidateSha", "publisher.envelope.schema")? != plan.candidate_sha
        || string(fields, "releasePlanSha256", "publisher.envelope.schema")? != plan.plan_sha256
        || string(fields, "conformancePlanSha256", "publisher.envelope.schema")?
            != plan.conformance_plan_sha256
        || string(fields, "externalInputsSha256", "publisher.envelope.schema")?
            != plan.external_inputs_sha256
        || string(
            fields,
            "governanceDeclarationSha256",
            "publisher.envelope.schema",
        )? != plan.governance_declaration_sha256
        || string(
            fields,
            "governanceProfileSha256",
            "publisher.envelope.schema",
        )? != plan.governance_profile_sha256
        || string(
            fields,
            "residualAssumptionSetSha256",
            "publisher.envelope.schema",
        )? != plan.residual_assumption_set_sha256
        || string(fields, "sourceInventorySha256", "publisher.envelope.schema")?
            != plan.source_inventory_sha256
        || string(fields, "trustedInputsSha256", "publisher.envelope.schema")?
            != plan.trusted_conformance_inputs_sha256
        || string(fields, "workflowSha", "publisher.envelope.schema")? != plan.workflow_sha
        || string(fields, "tag", "publisher.envelope.schema")? != plan.tag
        || string(fields, "version", "publisher.envelope.schema")? != plan.version
    {
        return Err(Failure::new(
            "publisher.envelope.binding",
            "publication envelope differs from the release plan",
        ));
    }
    Ok(())
}

fn validate_envelope_governance_binding(
    fields: &Map<String, Value>,
    governance: &GovernanceBindings,
) -> Result<(), Failure> {
    for (field, expected) in [
        ("governanceResolveSha256", governance.resolve.as_str()),
        (
            "governancePreAttestationSha256",
            governance.pre_attestation.as_str(),
        ),
    ] {
        if string(fields, field, "publisher.envelope.schema")? != expected {
            return Err(Failure::new(
                "publisher.envelope.governance",
                format!("publication envelope {field} binding differs"),
            ));
        }
    }
    require_digest(
        string(
            fields,
            "governancePostAssemblySha256",
            "publisher.envelope.schema",
        )?,
        "publisher.envelope.governance",
    )
}

fn validate_envelope_repository_binding(
    fields: &Map<String, Value>,
    plan: &ReleasePlan,
) -> Result<(), Failure> {
    let (owner, name) = plan.repository.split_once('/').ok_or_else(|| {
        Failure::new(
            "publisher.repository.identity",
            "repository identity is malformed",
        )
    })?;
    if string(fields, "repositoryOwner", "publisher.envelope.schema")? != owner
        || string(fields, "repositoryName", "publisher.envelope.schema")? != name
    {
        return Err(Failure::new(
            "publisher.envelope.repository",
            "publication envelope repository identity differs",
        ));
    }
    Ok(())
}

fn validate_envelope_file_bindings(
    fields: &Map<String, Value>,
    files: &BTreeMap<String, Asset>,
) -> Result<(), Failure> {
    if string(fields, "subjectManifestSha256", "publisher.envelope.schema")?
        != files
            .get("SUBJECTS.sha256")
            .ok_or_else(|| {
                Failure::new("publisher.subjects.missing", "subject manifest is absent")
            })?
            .sha256
    {
        return Err(Failure::new(
            "publisher.envelope.subjects",
            "publication envelope subject-manifest digest differs",
        ));
    }
    for (field, filename) in [
        (
            "primaryVerifierDecisionSha256",
            "primary-verifier-decision.json",
        ),
        (
            "independentVerifierDecisionSha256",
            "independent-verifier-decision.json",
        ),
    ] {
        if string(fields, field, "publisher.envelope.schema")?
            != files
                .get(filename)
                .ok_or_else(|| {
                    Failure::new("publisher.bundle.inventory", "verifier decision is absent")
                })?
                .sha256
        {
            return Err(Failure::new(
                "publisher.envelope.verifier",
                format!("publication envelope does not bind {filename:?}"),
            ));
        }
    }
    Ok(())
}

fn validate_envelope_receipt(files: &BTreeMap<String, Asset>) -> Result<(), Failure> {
    let envelope = files
        .get("publication-envelope.json")
        .ok_or_else(|| Failure::new("publisher.envelope.missing", "envelope is absent"))?;
    let envelope_value = json::parse(&envelope.bytes, "publisher.envelope.json")?;
    let assembled_artifact_digest = string(
        object(&envelope_value, "publisher.envelope.schema")?,
        "assembledArtifactDigest",
        "publisher.envelope.schema",
    )?;
    let receipt = files
        .get("publication-envelope-verification.json")
        .ok_or_else(|| {
            Failure::new(
                "publisher.envelope-receipt.missing",
                "envelope receipt is absent",
            )
        })?;
    let value = json::parse(&receipt.bytes, "publisher.envelope-receipt.json")?;
    require_canonical_json(
        &receipt.bytes,
        &value,
        "publisher.envelope-receipt.canonical",
    )?;
    let fields = object(&value, "publisher.envelope-receipt.schema")?;
    exact_keys(
        fields,
        &["artifactDigest", "envelopeSha256", "schemaVersion", "state"],
        "publisher.envelope-receipt.schema",
    )?;
    if number(fields, "schemaVersion", "publisher.envelope-receipt.schema")? != 1
        || string(fields, "state", "publisher.envelope-receipt.schema")? != "verified"
        || string(
            fields,
            "artifactDigest",
            "publisher.envelope-receipt.schema",
        )? != assembled_artifact_digest
        || string(
            fields,
            "envelopeSha256",
            "publisher.envelope-receipt.schema",
        )? != envelope.sha256
    {
        return Err(Failure::new(
            "publisher.envelope-receipt.binding",
            "envelope verification receipt differs from publication inputs",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteReceipt {
    pub phase: String,
    pub repository: String,
    pub repository_id: u64,
    pub candidate_sha: String,
    pub branch_sha: String,
    pub tag_state: String,
    pub release_state: String,
    pub state: String,
}

/// Observes the repository, branch, tag, and release before a privileged phase.
///
/// # Errors
///
/// Returns a stable failure when the remote state is unavailable, malformed,
/// moved, conflicting, or outside the operation deadline.
pub fn check_remote_state_with<T: Transport>(
    transport: &mut T,
    plan: &ReleasePlan,
    phase: Phase,
) -> Result<RemoteReceipt, Failure> {
    let deadline = deadline()?;
    let repository = get_json(
        transport,
        api_path(&plan.repository, ""),
        deadline,
        "publisher.remote.repository",
    )?;
    let repository_fields = object(&repository, "publisher.remote.repository-json")?;
    validate_repository_response(repository_fields)?;
    if repository_fields.get("id").and_then(Value::as_u64) != Some(plan.repository_id)
        || repository_fields.get("full_name").and_then(Value::as_str) != Some(&plan.repository)
    {
        return Err(Failure::new(
            "publisher.repository.identity",
            "remote repository numeric identity differs from the release plan",
        ));
    }
    let branch_path = format!(
        "/repos/{}/git/ref/heads/{}",
        encode_path(&plan.repository),
        encode_segment(&plan.candidate_branch)
    );
    let branch = get_json(transport, branch_path, deadline, "publisher.remote.branch")?;
    let branch_sha = git_object(&branch, "publisher.remote.branch-json")?;
    if branch_sha != plan.candidate_sha {
        return Err(Failure::new(
            "publisher.candidate.moved",
            "candidate branch no longer resolves to the planned SHA",
        ));
    }
    let tag = get_optional_json(
        transport,
        tag_ref_path(plan),
        deadline,
        "publisher.remote.tag",
    )?;
    if tag.is_some() {
        return Err(Failure::new(
            "publisher.remote.tag-conflict",
            "release tag already exists before publication",
        ));
    }
    let release = get_optional_json(
        transport,
        release_path(plan),
        deadline,
        "publisher.remote.release",
    )?;
    if release.is_some() {
        return Err(Failure::new(
            "publisher.remote.release-conflict",
            "release already exists before publication",
        ));
    }
    Ok(RemoteReceipt {
        phase: phase.name().to_owned(),
        repository: plan.repository.clone(),
        repository_id: plan.repository_id,
        candidate_sha: plan.candidate_sha.clone(),
        branch_sha,
        tag_state: "absent".to_owned(),
        release_state: "absent".to_owned(),
        state: "stable-absent".to_owned(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishReceipt {
    pub release_id: u64,
    pub tag: String,
    pub state: String,
    pub asset_count: usize,
    pub idempotent: bool,
    pub input_artifact_digest: String,
    pub input_artifact_id: u64,
    pub governance_pre_attestation_sha256: String,
    pub governance_pre_publish_sha256: String,
    pub governance_resolve_sha256: String,
}

struct PublicationIdentity<'a> {
    input_artifact_digest: &'a str,
    input_artifact_id: u64,
}

/// Drives the exact resumable draft-to-immutable publication state machine.
///
/// # Errors
///
/// Returns a stable failure for invalid artifact bindings, conflicting remote
/// state, unsafe assets, deadline expiry, or a failed transition.
pub fn publish_with<T: Transport>(
    transport: &mut T,
    plan: &ReleasePlan,
    bundle: &PublicationBundle,
    input_artifact_id: u64,
    input_artifact_digest: &str,
) -> Result<PublishReceipt, Failure> {
    if input_artifact_id == 0 {
        return Err(Failure::new(
            "publisher.artifact-id.invalid",
            "expected artifact ID must be nonzero",
        ));
    }
    require_digest(input_artifact_digest, "publisher.artifact-digest.invalid")?;
    if bundle.input_artifact_digest != input_artifact_digest {
        return Err(Failure::new(
            "publisher.artifact-digest.binding",
            "publication input digest differs from the authenticated bundle binding",
        ));
    }
    let identity = PublicationIdentity {
        input_artifact_digest,
        input_artifact_id,
    };
    let deadline = deadline()?;
    verify_repository_and_branch(transport, plan, deadline)?;
    let (tag, release) = load_or_create_release(transport, plan, bundle, &identity, deadline)?;
    let state = parse_release(&release, plan, bundle, &identity)?;
    verify_assets(&state.assets, bundle)?;
    if !state.draft {
        return existing_publication_receipt(
            tag.as_ref(),
            plan,
            bundle,
            &state,
            input_artifact_id,
            input_artifact_digest,
        );
    }
    let final_release = complete_draft(transport, plan, bundle, &identity, &state, deadline)?;
    Ok(PublishReceipt {
        release_id: final_release.id,
        tag: plan.tag.clone(),
        state: "exact-published-immutable".to_owned(),
        asset_count: bundle.files.len(),
        idempotent: false,
        input_artifact_digest: input_artifact_digest.to_owned(),
        input_artifact_id,
        governance_pre_attestation_sha256: bundle.governance.pre_attestation.clone(),
        governance_pre_publish_sha256: bundle.governance.pre_publish.clone(),
        governance_resolve_sha256: bundle.governance.resolve.clone(),
    })
}

fn load_or_create_release<T: Transport>(
    transport: &mut T,
    plan: &ReleasePlan,
    bundle: &PublicationBundle,
    identity: &PublicationIdentity<'_>,
    deadline: Instant,
) -> Result<(Option<Value>, Value), Failure> {
    let tag = get_optional_json(
        transport,
        tag_ref_path(plan),
        deadline,
        "publisher.remote.tag",
    )?;
    let release = get_optional_json(
        transport,
        release_path(plan),
        deadline,
        "publisher.remote.release",
    )?;
    let release = match (&tag, release) {
        (Some(_), None) => {
            return Err(Failure::new(
                "publisher.state.conflicting-tag",
                "tag exists without the exact expected release",
            ));
        }
        (None, Some(release)) => release,
        (None, None) => create_draft(transport, plan, bundle, identity, deadline)?,
        (Some(tag), Some(release)) => {
            let resolved = resolve_tag_target(transport, plan, tag, deadline)?;
            if resolved != plan.candidate_sha {
                return Err(Failure::new(
                    "publisher.state.conflicting-tag",
                    "release tag resolves to a different candidate SHA",
                ));
            }
            release
        }
    };
    Ok((tag, release))
}

fn existing_publication_receipt(
    tag: Option<&Value>,
    plan: &ReleasePlan,
    bundle: &PublicationBundle,
    state: &ReleaseState,
    input_artifact_id: u64,
    input_artifact_digest: &str,
) -> Result<PublishReceipt, Failure> {
    if tag.is_none() {
        return Err(Failure::new(
            "publisher.state.conflicting-published",
            "published release exists without its exact tag ref",
        ));
    }
    if !asset_inventory_is_complete(&state.assets, bundle) {
        return Err(Failure::new(
            "publisher.state.missing-asset",
            "published release lacks an expected asset",
        ));
    }
    if !state.immutable {
        return Err(Failure::new(
            "publisher.state.mutable-published",
            "published release is not immutable",
        ));
    }
    Ok(PublishReceipt {
        release_id: state.id,
        tag: plan.tag.clone(),
        state: "exact-published-immutable".to_owned(),
        asset_count: bundle.files.len(),
        idempotent: true,
        input_artifact_digest: input_artifact_digest.to_owned(),
        input_artifact_id,
        governance_pre_attestation_sha256: bundle.governance.pre_attestation.clone(),
        governance_pre_publish_sha256: bundle.governance.pre_publish.clone(),
        governance_resolve_sha256: bundle.governance.resolve.clone(),
    })
}

fn complete_draft<T: Transport>(
    transport: &mut T,
    plan: &ReleasePlan,
    bundle: &PublicationBundle,
    identity: &PublicationIdentity<'_>,
    state: &ReleaseState,
    deadline: Instant,
) -> Result<ReleaseState, Failure> {
    for (name, asset) in &bundle.files {
        if !state.assets.contains_key(name) {
            upload_asset(transport, plan, state.id, name, asset, deadline)?;
        }
    }
    let refreshed = get_json(
        transport,
        release_path(plan),
        deadline,
        "publisher.remote.release-refresh",
    )?;
    let refreshed = parse_release(&refreshed, plan, bundle, identity)?;
    if !refreshed.draft {
        return Err(Failure::new(
            "publisher.state.concurrent-transition",
            "release draft changed concurrently during asset upload",
        ));
    }
    verify_assets(&refreshed.assets, bundle)?;
    if !asset_inventory_is_complete(&refreshed.assets, bundle) {
        return Err(Failure::new(
            "publisher.state.missing-asset",
            "release draft still lacks an expected asset after uploads",
        ));
    }
    publish_draft(transport, refreshed.id, plan, bundle, identity, deadline)?;
    let final_release = get_json(
        transport,
        release_path(plan),
        deadline,
        "publisher.remote.final-release",
    )?;
    let final_release = parse_release(&final_release, plan, bundle, identity)?;
    verify_assets(&final_release.assets, bundle)?;
    if !asset_inventory_is_complete(&final_release.assets, bundle) {
        return Err(Failure::new(
            "publisher.state.missing-asset",
            "published release lacks an expected asset",
        ));
    }
    if final_release.draft || !final_release.immutable {
        return Err(Failure::new(
            "publisher.state.not-immutable",
            "release did not reach the exact immutable published state",
        ));
    }
    let final_tag = get_json(
        transport,
        tag_ref_path(plan),
        deadline,
        "publisher.remote.final-tag",
    )?;
    if resolve_tag_target(transport, plan, &final_tag, deadline)? != plan.candidate_sha {
        return Err(Failure::new(
            "publisher.state.conflicting-tag",
            "published tag does not resolve to the candidate SHA",
        ));
    }
    Ok(final_release)
}

fn verify_repository_and_branch<T: Transport>(
    transport: &mut T,
    plan: &ReleasePlan,
    deadline: Instant,
) -> Result<(), Failure> {
    let repository = get_json(
        transport,
        api_path(&plan.repository, ""),
        deadline,
        "publisher.remote.repository",
    )?;
    let repository = object(&repository, "publisher.remote.repository-json")?;
    validate_repository_response(repository)?;
    if repository.get("id").and_then(Value::as_u64) != Some(plan.repository_id)
        || repository.get("full_name").and_then(Value::as_str) != Some(&plan.repository)
    {
        return Err(Failure::new(
            "publisher.repository.identity",
            "remote repository numeric identity differs from the release plan",
        ));
    }
    let branch = get_json(
        transport,
        format!(
            "/repos/{}/git/ref/heads/{}",
            encode_path(&plan.repository),
            encode_segment(&plan.candidate_branch)
        ),
        deadline,
        "publisher.remote.branch",
    )?;
    if git_object(&branch, "publisher.remote.branch-json")? != plan.candidate_sha {
        return Err(Failure::new(
            "publisher.candidate.moved",
            "candidate branch no longer resolves to the planned SHA",
        ));
    }
    Ok(())
}

fn create_draft<T: Transport>(
    transport: &mut T,
    plan: &ReleasePlan,
    bundle: &PublicationBundle,
    identity: &PublicationIdentity<'_>,
    deadline: Instant,
) -> Result<Value, Failure> {
    let body = serde_json::to_vec(&serde_json::json!({
        "body": release_marker(plan, bundle, identity),
        "draft": true,
        "generate_release_notes": false,
        "name": plan.tag,
        "prerelease": plan.prerelease,
        "tag_name": plan.tag,
        "target_commitish": plan.candidate_sha,
    }))
    .map_err(|error| {
        Failure::new(
            "publisher.remote.encode",
            format!("cannot encode draft: {error}"),
        )
    })?;
    let response = send_expected(
        transport,
        Request {
            method: Method::Post,
            host: Host::Api,
            path: api_path(&plan.repository, "/releases"),
            content_type: Some("application/json".to_owned()),
            body,
        },
        deadline,
        &[201],
        "publisher.remote.create-draft",
    )?;
    json::parse(&response.body, "publisher.remote.create-draft-json")
}

fn publish_draft<T: Transport>(
    transport: &mut T,
    release_id: u64,
    plan: &ReleasePlan,
    bundle: &PublicationBundle,
    identity: &PublicationIdentity<'_>,
    deadline: Instant,
) -> Result<(), Failure> {
    let body = serde_json::to_vec(&serde_json::json!({
        "body": release_marker(plan, bundle, identity),
        "draft": false,
        "name": plan.tag,
        "prerelease": plan.prerelease,
        "tag_name": plan.tag,
        "target_commitish": plan.candidate_sha,
    }))
    .map_err(|error| {
        Failure::new(
            "publisher.remote.encode",
            format!("cannot encode publish: {error}"),
        )
    })?;
    send_expected(
        transport,
        Request {
            method: Method::Patch,
            host: Host::Api,
            path: format!(
                "/repos/{}/releases/{release_id}",
                encode_path(&plan.repository)
            ),
            content_type: Some("application/json".to_owned()),
            body,
        },
        deadline,
        &[200],
        "publisher.remote.publish-draft",
    )?;
    Ok(())
}

fn upload_asset<T: Transport>(
    transport: &mut T,
    plan: &ReleasePlan,
    release_id: u64,
    name: &str,
    asset: &Asset,
    deadline: Instant,
) -> Result<(), Failure> {
    validate_asset_name(name)?;
    send_expected(
        transport,
        Request {
            method: Method::Post,
            host: Host::Upload,
            path: format!(
                "/repos/{}/releases/{release_id}/assets?name={}",
                encode_path(&plan.repository),
                encode_segment(name)
            ),
            content_type: Some("application/octet-stream".to_owned()),
            body: asset.bytes.clone(),
        },
        deadline,
        &[201],
        "publisher.remote.upload-asset",
    )?;
    Ok(())
}

#[derive(Clone)]
struct ReleaseState {
    id: u64,
    draft: bool,
    immutable: bool,
    assets: BTreeMap<String, RemoteAsset>,
}

#[derive(Clone)]
struct RemoteAsset {
    size: u64,
    sha256: String,
}

fn parse_release(
    value: &Value,
    plan: &ReleasePlan,
    bundle: &PublicationBundle,
    identity: &PublicationIdentity<'_>,
) -> Result<ReleaseState, Failure> {
    let fields = object(value, "publisher.remote.release-json")?;
    validate_release_response(fields)?;
    let draft = fields
        .get("draft")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            Failure::new(
                "publisher.remote.release-json",
                "release draft flag is absent",
            )
        })?;
    let immutable = fields
        .get("immutable")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if fields.get("tag_name").and_then(Value::as_str) != Some(&plan.tag)
        || fields.get("target_commitish").and_then(Value::as_str) != Some(&plan.candidate_sha)
        || fields.get("name").and_then(Value::as_str) != Some(&plan.tag)
        || fields.get("body").and_then(Value::as_str)
            != Some(&release_marker(plan, bundle, identity))
        || fields.get("prerelease").and_then(Value::as_bool) != Some(plan.prerelease)
    {
        return Err(Failure::new(
            if draft {
                "publisher.state.unexpected-draft"
            } else {
                "publisher.state.conflicting-published"
            },
            "release metadata differs from the exact expected marker and plan bindings",
        ));
    }
    let id = fields
        .get("id")
        .and_then(Value::as_u64)
        .filter(|id| *id != 0)
        .ok_or_else(|| Failure::new("publisher.remote.release-json", "release ID is invalid"))?;
    let assets = fields
        .get("assets")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            Failure::new("publisher.remote.release-json", "release assets are absent")
        })?;
    Ok(ReleaseState {
        id,
        draft,
        immutable,
        assets: parse_remote_assets(assets)?,
    })
}

fn validate_release_response(fields: &Map<String, Value>) -> Result<(), Failure> {
    known_keys(
        fields,
        &[
            "url",
            "assets_url",
            "upload_url",
            "html_url",
            "id",
            "author",
            "node_id",
            "tag_name",
            "target_commitish",
            "name",
            "draft",
            "immutable",
            "prerelease",
            "created_at",
            "updated_at",
            "published_at",
            "assets",
            "tarball_url",
            "zipball_url",
            "body",
            "mentions_count",
            "reactions",
            "discussion_url",
        ],
        "publisher.remote.release-json",
    )
}

fn parse_remote_assets(assets: &[Value]) -> Result<BTreeMap<String, RemoteAsset>, Failure> {
    if assets.len() > MAX_BUNDLE_FILES {
        return Err(Failure::new(
            "publisher.remote.assets-oversize",
            "remote release asset count exceeds the bound",
        ));
    }
    let mut parsed = BTreeMap::new();
    for asset in assets {
        let asset = object(asset, "publisher.remote.asset-json")?;
        known_keys(
            asset,
            &[
                "url",
                "id",
                "node_id",
                "name",
                "label",
                "uploader",
                "content_type",
                "state",
                "size",
                "digest",
                "download_count",
                "created_at",
                "updated_at",
                "browser_download_url",
            ],
            "publisher.remote.asset-json",
        )?;
        let name = asset
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| Failure::new("publisher.remote.asset-json", "asset name is absent"))?;
        validate_asset_name(name)?;
        let size = asset
            .get("size")
            .and_then(Value::as_u64)
            .ok_or_else(|| Failure::new("publisher.remote.asset-json", "asset size is absent"))?;
        let digest_value = asset
            .get("digest")
            .and_then(Value::as_str)
            .ok_or_else(|| Failure::new("publisher.remote.asset-json", "asset digest is absent"))?;
        let sha256 = digest_value.strip_prefix("sha256:").ok_or_else(|| {
            Failure::new("publisher.remote.asset-json", "asset digest is not SHA-256")
        })?;
        require_digest(sha256, "publisher.remote.asset-json")?;
        if parsed
            .insert(
                name.to_owned(),
                RemoteAsset {
                    size,
                    sha256: sha256.to_owned(),
                },
            )
            .is_some()
        {
            return Err(Failure::new(
                "publisher.remote.asset-duplicate",
                "remote release repeats an asset name",
            ));
        }
    }
    Ok(parsed)
}

fn verify_assets(
    remote: &BTreeMap<String, RemoteAsset>,
    bundle: &PublicationBundle,
) -> Result<(), Failure> {
    for (name, asset) in remote {
        let Some(expected) = bundle.files.get(name) else {
            if mutation::active(mutation::Mutant::AcceptUnknownPublisherDraft) {
                continue;
            }
            return Err(Failure::new(
                "publisher.state.unexpected-asset",
                format!("remote release has unexpected asset {name:?}"),
            ));
        };
        if asset.size != expected.bytes.len() as u64 || asset.sha256 != expected.sha256 {
            return Err(Failure::new(
                "publisher.state.asset-mismatch",
                format!("remote asset {name:?} size or digest differs"),
            ));
        }
    }
    Ok(())
}

fn asset_inventory_is_complete(
    remote: &BTreeMap<String, RemoteAsset>,
    bundle: &PublicationBundle,
) -> bool {
    if mutation::active(mutation::Mutant::AcceptUnknownPublisherDraft) {
        bundle.files.keys().all(|name| remote.contains_key(name))
    } else {
        remote.len() == bundle.files.len()
    }
}

fn get_json<T: Transport>(
    transport: &mut T,
    path: String,
    deadline: Instant,
    code: &'static str,
) -> Result<Value, Failure> {
    let response = send_expected(
        transport,
        Request {
            method: Method::Get,
            host: Host::Api,
            path,
            content_type: None,
            body: Vec::new(),
        },
        deadline,
        &[200],
        code,
    )?;
    json::parse(&response.body, code)
}

fn get_optional_json<T: Transport>(
    transport: &mut T,
    path: String,
    deadline: Instant,
    code: &'static str,
) -> Result<Option<Value>, Failure> {
    let response = transport.send(
        Request {
            method: Method::Get,
            host: Host::Api,
            path,
            content_type: None,
            body: Vec::new(),
        },
        deadline,
    )?;
    require_bounded_response(&response)?;
    match response.status {
        200 => json::parse(&response.body, code).map(Some),
        404 => Ok(None),
        401 | 403 => Err(Failure::new(
            "publisher.remote.forbidden",
            "GitHub denied the remote-state request",
        )),
        status => Err(Failure::new(
            code,
            format!("remote-state request returned unexpected HTTP status {status}"),
        )),
    }
}

fn send_expected<T: Transport>(
    transport: &mut T,
    request: Request,
    deadline: Instant,
    expected: &[u16],
    code: &'static str,
) -> Result<Response, Failure> {
    let response = transport.send(request, deadline)?;
    require_bounded_response(&response)?;
    if !expected.contains(&response.status) {
        let code = if matches!(response.status, 401 | 403) {
            "publisher.remote.forbidden"
        } else if response.status == 409 {
            "publisher.remote.conflict"
        } else {
            code
        };
        return Err(Failure::new(
            code,
            format!(
                "GitHub request returned unexpected HTTP status {}",
                response.status
            ),
        ));
    }
    Ok(response)
}

fn git_object(value: &Value, code: &'static str) -> Result<String, Failure> {
    let fields = object(value, code)?;
    known_keys(fields, &["ref", "node_id", "url", "object"], code)?;
    let target = fields
        .get("object")
        .and_then(Value::as_object)
        .ok_or_else(|| Failure::new(code, "git ref lacks an object"))?;
    known_keys(target, &["type", "sha", "url"], code)?;
    if target.get("type").and_then(Value::as_str) != Some("commit") {
        return Err(Failure::new(
            code,
            "branch ref does not directly target a commit",
        ));
    }
    let sha = target
        .get("sha")
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::new(code, "git ref object SHA is absent"))?;
    require_sha(sha, code)?;
    Ok(sha.to_owned())
}

fn resolve_tag_target<T: Transport>(
    transport: &mut T,
    plan: &ReleasePlan,
    value: &Value,
    deadline: Instant,
) -> Result<String, Failure> {
    let fields = object(value, "publisher.remote.tag-json")?;
    known_keys(
        fields,
        &["ref", "node_id", "url", "object"],
        "publisher.remote.tag-json",
    )?;
    let target = fields
        .get("object")
        .and_then(Value::as_object)
        .ok_or_else(|| Failure::new("publisher.remote.tag-json", "tag ref lacks an object"))?;
    known_keys(target, &["type", "sha", "url"], "publisher.remote.tag-json")?;
    let kind = target
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::new("publisher.remote.tag-json", "tag object type is absent"))?;
    let sha = target
        .get("sha")
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::new("publisher.remote.tag-json", "tag object SHA is absent"))?;
    require_sha(sha, "publisher.remote.tag-json")?;
    match kind {
        "commit" => Ok(sha.to_owned()),
        "tag" => {
            let annotated = get_json(
                transport,
                format!(
                    "/repos/{}/git/tags/{}",
                    encode_path(&plan.repository),
                    encode_segment(sha)
                ),
                deadline,
                "publisher.remote.annotated-tag",
            )?;
            let annotated = object(&annotated, "publisher.remote.annotated-tag-json")?;
            known_keys(
                annotated,
                &[
                    "node_id",
                    "tag",
                    "sha",
                    "url",
                    "message",
                    "tagger",
                    "object",
                    "verification",
                ],
                "publisher.remote.annotated-tag-json",
            )?;
            let target = annotated
                .get("object")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    Failure::new(
                        "publisher.remote.annotated-tag-json",
                        "annotated tag target is absent",
                    )
                })?;
            known_keys(
                target,
                &["type", "sha", "url"],
                "publisher.remote.annotated-tag-json",
            )?;
            if target.get("type").and_then(Value::as_str) != Some("commit") {
                return Err(Failure::new(
                    "publisher.remote.annotated-tag-json",
                    "nested or non-commit annotated tag target is forbidden",
                ));
            }
            let sha = target.get("sha").and_then(Value::as_str).ok_or_else(|| {
                Failure::new(
                    "publisher.remote.annotated-tag-json",
                    "annotated tag commit SHA is absent",
                )
            })?;
            require_sha(sha, "publisher.remote.annotated-tag-json")?;
            Ok(sha.to_owned())
        }
        _ => Err(Failure::new(
            "publisher.remote.tag-json",
            "tag ref has an unsupported target type",
        )),
    }
}

fn api_path(repository: &str, suffix: &str) -> String {
    format!("/repos/{}{suffix}", encode_path(repository))
}

fn tag_ref_path(plan: &ReleasePlan) -> String {
    format!(
        "/repos/{}/git/ref/tags/{}",
        encode_path(&plan.repository),
        encode_segment(&plan.tag)
    )
}

fn release_path(plan: &ReleasePlan) -> String {
    format!(
        "/repos/{}/releases/tags/{}",
        encode_path(&plan.repository),
        encode_segment(&plan.tag)
    )
}

fn release_marker(
    plan: &ReleasePlan,
    bundle: &PublicationBundle,
    identity: &PublicationIdentity<'_>,
) -> String {
    [
        format!("{MARKER_PREFIX}{}", plan.plan_sha256),
        format!("{ARTIFACT_ID_MARKER_PREFIX}{}", identity.input_artifact_id),
        format!(
            "{ARTIFACT_DIGEST_MARKER_PREFIX}{}",
            identity.input_artifact_digest
        ),
        format!(
            "{GOVERNANCE_RESOLVE_MARKER_PREFIX}{}",
            bundle.governance.resolve
        ),
        format!(
            "{GOVERNANCE_PRE_ATTESTATION_MARKER_PREFIX}{}",
            bundle.governance.pre_attestation
        ),
        format!(
            "{GOVERNANCE_PRE_PUBLISH_MARKER_PREFIX}{}",
            bundle.governance.pre_publish
        ),
    ]
    .join("\n")
}

fn encode_path(path: &str) -> String {
    path.split('/')
        .map(encode_segment)
        .collect::<Vec<_>>()
        .join("/")
}

fn encode_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            write!(&mut encoded, "{byte:02X}").expect("writing to a String cannot fail");
        }
    }
    encoded
}

struct GithubTransport<'a> {
    credential: &'a github_runtime::Credential,
}

impl<'a> GithubTransport<'a> {
    fn new(credential: &'a github_runtime::Credential) -> Self {
        Self { credential }
    }

    fn send_once(&self, request: &Request, deadline: Instant) -> Result<Response, Failure> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                Failure::new(
                    "publisher.deadline.exceeded",
                    "absolute operation deadline expired",
                )
            })?;
        let timeout = remaining.min(REQUEST_TIMEOUT);
        let agent = ureq::config::Config::builder()
            .http_status_as_error(false)
            .https_only(true)
            .max_redirects(0)
            .proxy(None)
            .timeout_global(Some(timeout))
            .build()
            .new_agent();
        let base = match request.host {
            Host::Api => "https://api.github.com",
            Host::Upload => "https://uploads.github.com",
        };
        let url = format!("{base}{}", request.path);
        let mut authorization = b"Bearer ".to_vec();
        authorization.extend_from_slice(self.credential.expose().as_bytes());
        let authorization_text = std::str::from_utf8(&authorization)
            .expect("authorization header contains only validated UTF-8");
        let response = match request.method {
            Method::Get => agent
                .get(&url)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .header("User-Agent", "hell-release-publisher")
                .header("Authorization", authorization_text)
                .call(),
            Method::Post => agent
                .post(&url)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .header("User-Agent", "hell-release-publisher")
                .header("Authorization", authorization_text)
                .header(
                    "Content-Type",
                    request
                        .content_type
                        .as_deref()
                        .unwrap_or("application/octet-stream"),
                )
                .send(request.body.as_slice()),
            Method::Patch => agent
                .patch(&url)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .header("User-Agent", "hell-release-publisher")
                .header("Authorization", authorization_text)
                .header(
                    "Content-Type",
                    request
                        .content_type
                        .as_deref()
                        .unwrap_or("application/json"),
                )
                .send(request.body.as_slice()),
        };
        authorization.fill(0);
        let response = response.map_err(|error| {
            Failure::new(
                "publisher.remote.transport",
                format!("bounded GitHub request failed: {error}"),
            )
        })?;
        let status = response.status().as_u16();
        let (_, body) = response.into_parts();
        let bytes = body
            .into_with_config()
            .limit(MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_vec()
            .map_err(|error| {
                Failure::new(
                    "publisher.remote.response",
                    format!("cannot read bounded GitHub response: {error}"),
                )
            })?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(Failure::new(
                "publisher.remote.response-oversize",
                "GitHub response exceeds the size bound",
            ));
        }
        Ok(Response {
            status,
            body: bytes,
        })
    }
}

impl Transport for GithubTransport<'_> {
    fn send(&mut self, request: Request, deadline: Instant) -> Result<Response, Failure> {
        let attempts = if request.method == Method::Get { 3 } else { 1 };
        let mut last = None;
        for attempt in 0..attempts {
            let response = self.send_once(&request, deadline);
            match response {
                Ok(response) if response.status >= 500 && attempt + 1 < attempts => {
                    last = Some(Failure::new(
                        "publisher.remote.transient",
                        format!("GitHub returned transient HTTP status {}", response.status),
                    ));
                }
                Ok(response) => return Ok(response),
                Err(error) if attempt + 1 < attempts => last = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last.unwrap_or_else(|| {
            Failure::new(
                "publisher.remote.transport",
                "GitHub request did not execute",
            )
        }))
    }
}

trait ReportReceipt {
    fn report(&self) -> Value;
}

impl ReportReceipt for RemoteReceipt {
    fn report(&self) -> Value {
        serde_json::json!({
            "admitted": true,
            "candidateSha": self.candidate_sha,
            "diagnostic": null,
            "governanceReceipt": {
                "repository": self.repository,
                "repositoryId": self.repository_id,
                "source": "trusted-github-api",
            },
            "observations": {
                "branchSha": self.branch_sha,
                "release": self.release_state,
                "tag": self.tag_state,
            },
            "phase": self.phase,
            "schemaVersion": 1,
            "state": self.state,
        })
    }
}

impl ReportReceipt for PublishReceipt {
    fn report(&self) -> Value {
        serde_json::json!({
            "admitted": true,
            "assetCount": self.asset_count,
            "diagnostic": null,
            "governancePreAttestationSha256": self.governance_pre_attestation_sha256,
            "governancePrePublishSha256": self.governance_pre_publish_sha256,
            "governanceResolveSha256": self.governance_resolve_sha256,
            "idempotent": self.idempotent,
            "inputArtifactDigest": self.input_artifact_digest,
            "inputArtifactId": self.input_artifact_id,
            "releaseId": self.release_id,
            "schemaVersion": 1,
            "state": self.state,
            "tag": self.tag,
        })
    }
}

fn write_result_report<T: ReportReceipt>(
    path: &Path,
    phase: &str,
    result: &Result<T, Failure>,
) -> Result<(), Failure> {
    let value = match result {
        Ok(receipt) => receipt.report(),
        Err(error) => serde_json::json!({
            "admitted": false,
            "diagnostic": {"code": error.code, "message": error.message},
            "phase": phase,
            "schemaVersion": 1,
            "state": "rejected",
        }),
    };
    write_json_new(path, &value, "publisher.report.write")
}

struct Options {
    values: BTreeMap<String, OsString>,
}

impl Options {
    fn parse(arguments: &[OsString], allowed: &[&str]) -> Result<Self, Failure> {
        if !arguments.len().is_multiple_of(2) {
            return Err(Failure::new(
                "publisher.cli.option",
                "publisher option lacks a value",
            ));
        }
        let mut values = BTreeMap::new();
        for pair in arguments.chunks_exact(2) {
            let name = pair[0]
                .to_str()
                .ok_or_else(|| Failure::new("publisher.cli.option", "option name must be UTF-8"))?;
            if !allowed.contains(&name) {
                return Err(Failure::new(
                    "publisher.cli.option",
                    format!("unknown publisher option {name:?}"),
                ));
            }
            if values.insert(name.to_owned(), pair[1].clone()).is_some() {
                return Err(Failure::new(
                    "publisher.cli.option",
                    format!("option {name:?} was provided more than once"),
                ));
            }
        }
        Ok(Self { values })
    }

    fn path(&self, name: &str) -> Result<PathBuf, Failure> {
        self.values.get(name).map(PathBuf::from).ok_or_else(|| {
            Failure::new(
                "publisher.cli.option",
                format!("required option {name} is absent"),
            )
        })
    }

    fn text(&self, name: &str) -> Result<String, Failure> {
        self.values
            .get(name)
            .ok_or_else(|| {
                Failure::new(
                    "publisher.cli.option",
                    format!("required option {name} is absent"),
                )
            })?
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| {
                Failure::new(
                    "publisher.cli.option",
                    format!("option {name} must be UTF-8"),
                )
            })
    }
}

fn usage() -> String {
    "usage: hell-release-publisher check-remote-state|stage-attestations|publish [options]"
        .to_owned()
}

fn canonical_json(value: &Value, code: &'static str) -> Result<Vec<u8>, Failure> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| Failure::new(code, format!("cannot canonicalize JSON: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn require_canonical_json(bytes: &[u8], value: &Value, code: &'static str) -> Result<(), Failure> {
    if canonical_json(value, code)? != bytes {
        return Err(Failure::new(
            code,
            "JSON input is not canonical with one trailing LF",
        ));
    }
    Ok(())
}

fn read_regular(path: &Path, limit: u64, code: &'static str) -> Result<Vec<u8>, Failure> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Failure::new(
            code,
            format!("cannot inspect input {}: {error}", path.display()),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Failure::new(code, "input is linked or non-regular"));
    }
    if metadata.len() > limit {
        return Err(Failure::new(code, "input exceeds its size bound"));
    }
    fs::read(path).map_err(|error| {
        Failure::new(
            code,
            format!("cannot read input {}: {error}", path.display()),
        )
    })
}

fn directory_inventory(root: &Path, code: &'static str) -> Result<BTreeSet<String>, Failure> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| Failure::new(code, format!("cannot inspect directory: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Failure::new(code, "input is linked or is not a directory"));
    }
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(root)
        .map_err(|error| Failure::new(code, format!("cannot enumerate directory: {error}")))?
    {
        let entry = entry.map_err(|error| {
            Failure::new(code, format!("cannot inspect directory entry: {error}"))
        })?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            Failure::new(code, format!("cannot inspect entry metadata: {error}"))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Failure::new(
                code,
                "release set contains a linked or non-regular entry",
            ));
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Failure::new(code, "release-set filename is not UTF-8"))?;
        validate_asset_name(&name)?;
        if !names.insert(name) {
            return Err(Failure::new(code, "release set repeats a filename"));
        }
        if names.len() > MAX_BUNDLE_FILES {
            return Err(Failure::new(
                code,
                "release-set file count exceeds the bound",
            ));
        }
    }
    Ok(names)
}

fn staging_directory(output: &Path, label: &str) -> Result<PathBuf, Failure> {
    let parent = output
        .parent()
        .ok_or_else(|| Failure::new("publisher.stage.path", "output has no parent"))?;
    let name = output
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| Failure::new("publisher.stage.path", "output name is invalid"))?;
    Ok(parent.join(format!(".{label}-{name}-{}", std::process::id())))
}

fn copy_new(source: &Path, target: &Path, limit: u64) -> Result<(), Failure> {
    let bytes = read_regular(source, limit, "publisher.stage.copy")?;
    write_new(target, &bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Failure> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            Failure::new(
                "publisher.stage.write",
                format!("cannot create file: {error}"),
            )
        })?;
    file.write_all(bytes).map_err(|error| {
        Failure::new(
            "publisher.stage.write",
            format!("cannot write file: {error}"),
        )
    })?;
    file.sync_all().map_err(|error| {
        Failure::new(
            "publisher.stage.write",
            format!("cannot sync file: {error}"),
        )
    })
}

fn write_json_new(path: &Path, value: &Value, code: &'static str) -> Result<(), Failure> {
    if path.exists() {
        return Err(Failure::new(code, "output report already exists"));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| Failure::new(code, format!("cannot create report directory: {error}")))?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| Failure::new(code, "report filename is invalid"))?;
    let staging = parent.join(format!(".{name}.{}.partial", std::process::id()));
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| Failure::new(code, format!("cannot encode report: {error}")))?;
    bytes.push(b'\n');
    let result = (|| {
        write_new(&staging, &bytes)?;
        fs::rename(&staging, path)
            .map_err(|error| Failure::new(code, format!("cannot promote report: {error}")))?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _cleanup_result = fs::remove_file(&staging);
    }
    result
}

fn sync_directory(path: &Path) -> Result<(), Failure> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            Failure::new(
                "publisher.filesystem.sync",
                format!("cannot sync directory: {error}"),
            )
        })
}

fn deadline() -> Result<Instant, Failure> {
    Instant::now()
        .checked_add(OPERATION_TIMEOUT)
        .ok_or_else(|| {
            Failure::new(
                "publisher.deadline.invalid",
                "cannot represent operation deadline",
            )
        })
}

fn object<'a>(value: &'a Value, code: &'static str) -> Result<&'a Map<String, Value>, Failure> {
    value
        .as_object()
        .ok_or_else(|| Failure::new(code, "expected a JSON object"))
}

fn exact_keys(
    value: &Map<String, Value>,
    expected: &[&str],
    code: &'static str,
) -> Result<(), Failure> {
    let observed = value.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if observed != expected {
        return Err(Failure::new(
            code,
            "JSON object keys differ from the closed schema",
        ));
    }
    Ok(())
}

fn known_keys(
    value: &Map<String, Value>,
    allowed: &[&str],
    code: &'static str,
) -> Result<(), Failure> {
    if let Some(key) = value.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(Failure::new(
            code,
            format!("GitHub response contains unknown field {key:?}"),
        ));
    }
    Ok(())
}

const REPOSITORY_RESPONSE_FIELDS: &[&str] = &[
    "id",
    "node_id",
    "name",
    "full_name",
    "private",
    "owner",
    "html_url",
    "description",
    "fork",
    "url",
    "archive_url",
    "assignees_url",
    "blobs_url",
    "branches_url",
    "collaborators_url",
    "comments_url",
    "commits_url",
    "compare_url",
    "contents_url",
    "contributors_url",
    "deployments_url",
    "downloads_url",
    "events_url",
    "forks_url",
    "git_commits_url",
    "git_refs_url",
    "git_tags_url",
    "git_url",
    "issue_comment_url",
    "issue_events_url",
    "issues_url",
    "keys_url",
    "labels_url",
    "languages_url",
    "merges_url",
    "milestones_url",
    "notifications_url",
    "pulls_url",
    "releases_url",
    "ssh_url",
    "stargazers_url",
    "statuses_url",
    "subscribers_url",
    "subscription_url",
    "tags_url",
    "teams_url",
    "trees_url",
    "clone_url",
    "mirror_url",
    "hooks_url",
    "svn_url",
    "homepage",
    "language",
    "forks_count",
    "forks",
    "stargazers_count",
    "watchers_count",
    "watchers",
    "size",
    "default_branch",
    "open_issues_count",
    "open_issues",
    "is_template",
    "topics",
    "has_issues",
    "has_projects",
    "has_wiki",
    "has_pages",
    "has_downloads",
    "has_discussions",
    "archived",
    "disabled",
    "visibility",
    "pushed_at",
    "created_at",
    "updated_at",
    "permissions",
    "allow_rebase_merge",
    "temp_clone_token",
    "allow_squash_merge",
    "allow_auto_merge",
    "delete_branch_on_merge",
    "allow_update_branch",
    "use_squash_pr_title_as_default",
    "squash_merge_commit_message",
    "squash_merge_commit_title",
    "merge_commit_message",
    "merge_commit_title",
    "network_count",
    "subscribers_count",
    "license",
    "organization",
    "parent",
    "source",
    "security_and_analysis",
    "web_commit_signoff_required",
    "custom_properties",
];

fn validate_repository_response(value: &Map<String, Value>) -> Result<(), Failure> {
    known_keys(
        value,
        REPOSITORY_RESPONSE_FIELDS,
        "publisher.remote.repository-json",
    )
}

fn require_bounded_response(response: &Response) -> Result<(), Failure> {
    if response.body.len() > MAX_RESPONSE_BYTES {
        return Err(Failure::new(
            "publisher.remote.response-oversize",
            "GitHub response exceeds the size bound",
        ));
    }
    Ok(())
}

fn string<'a>(
    value: &'a Map<String, Value>,
    key: &str,
    code: &'static str,
) -> Result<&'a str, Failure> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::new(code, format!("field {key:?} must be a string")))
}

fn number(value: &Map<String, Value>, key: &str, code: &'static str) -> Result<u64, Failure> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| Failure::new(code, format!("field {key:?} must be an unsigned integer")))
}

fn boolean(value: &Map<String, Value>, key: &str, code: &'static str) -> Result<bool, Failure> {
    value
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| Failure::new(code, format!("field {key:?} must be a boolean")))
}

fn require_sha(value: &str, code: &'static str) -> Result<(), Failure> {
    if value.len() != 40 || !value.bytes().all(lower_hex) {
        return Err(Failure::new(
            code,
            "value is not a lowercase full commit SHA",
        ));
    }
    Ok(())
}

fn require_digest(value: &str, code: &'static str) -> Result<(), Failure> {
    if value.len() != 64 || !value.bytes().all(lower_hex) {
        return Err(Failure::new(
            code,
            "value is not a lowercase SHA-256 digest",
        ));
    }
    Ok(())
}

fn lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn validate_repository(value: &str) -> Result<(), Failure> {
    let Some((owner, name)) = value.split_once('/') else {
        return Err(Failure::new(
            "publisher.repository.identity",
            "repository must use owner/name form",
        ));
    };
    if owner.is_empty()
        || name.is_empty()
        || name.contains('/')
        || !owner.bytes().all(repository_character)
        || !name.bytes().all(repository_character)
    {
        return Err(Failure::new(
            "publisher.repository.identity",
            "repository owner/name contains unsupported characters",
        ));
    }
    Ok(())
}

fn repository_character(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

fn validate_asset_name(name: &str) -> Result<(), Failure> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains(['/', '\\', '\0'])
        || name.len() > 255
    {
        return Err(Failure::new(
            "publisher.asset.name",
            "asset name is unsafe or exceeds the bound",
        ));
    }
    Ok(())
}
