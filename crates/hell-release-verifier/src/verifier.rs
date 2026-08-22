use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::ArchiveLimits;
use crate::archive::{self, MemberSet};
use crate::digest;
use crate::external_inputs;
use crate::json::{self, Value};
use crate::model::{
    self, CellKey, ConformancePlan, ConformanceReport, Counts, Decision, PlannedCell, ReleasePlan,
    Scope,
};

const MAX_EVIDENCE_RECORDS: usize = 1_000_000;
const MAX_DIAGNOSTIC_BYTES: usize = 4096;
const TRUSTED_CONTROL_PATHS: [&str; 9] = [
    ".github/release/conformance-exemptions.toml",
    "compat/builtin-registry.json",
    "compat/claim-rules.toml",
    "compat/corpus-obligations.toml",
    "compat/divergences.toml",
    "compat/expected-mismatches.toml",
    "compat/normalizers.toml",
    "compat/requirements/2026-05-29.toml",
    "release-policy.toml",
];
const RELEASE_GATE_FIELDS: [&str; 24] = [
    "candidateCodeExecutedInPublisher",
    "candidateSha",
    "conformanceAcceptanceSha256",
    "conformanceCounts",
    "conformanceEvidenceSha256",
    "conformancePlanSha256",
    "conformanceReportSha256",
    "conformanceStandard",
    "externalInputsSha256",
    "governanceDeclarationSha256",
    "governanceProfileSha256",
    "nativeEnvironmentSetSha256",
    "releaseGateSha256",
    "releasePlanSha256",
    "repository",
    "residualAssumptionSetSha256",
    "runAttempt",
    "runId",
    "schemaVersion",
    "state",
    "subjectsSha256",
    "tag",
    "version",
    "workflowSha",
];

pub struct Options {
    pub plan: PathBuf,
    pub conformance_plan: PathBuf,
    pub bundle: PathBuf,
    pub protocol_projection: PathBuf,
    pub governance_resolve: Option<PathBuf>,
    pub governance_post_assembly: Option<PathBuf>,
    pub governance_pre_attestation: Option<PathBuf>,
    pub output: PathBuf,
}

struct Projection {
    protocol_sha256: String,
    obligation_rules_sha256: String,
    obligation_rules: ObligationRules,
    repository_root: PathBuf,
    archive_limits: ArchiveLimits,
    external_inputs: external_inputs::Authority,
}

struct ObligationRules {
    rules: Vec<ObligationRule>,
}

struct ObligationRule {
    id: String,
    condition: RuleCondition,
    requirement: RuleRequirement,
}

enum RuleCondition {
    Equals {
        field: RuleField,
        value: String,
    },
    Includes {
        field: RuleField,
        values: BTreeSet<String>,
    },
}

enum RuleRequirement {
    EvidenceKinds(BTreeSet<String>),
    DateAfterEvaluation { field: RuleField },
    All(Vec<RuleRequirement>),
    Any(Vec<RuleRequirement>),
}

#[derive(Clone, Copy)]
enum RuleField {
    Applicability,
    DispositionClass,
    ExpiresAt,
    Profile,
}

struct TrustedInputs {
    builtin_ids: BTreeMap<String, u64>,
    oracle_repository: String,
    oracle_commit: String,
    linux_oracle_executable_sha256: String,
}

struct Verification {
    decision: Decision,
}

struct VerificationTransaction(Options);

impl VerificationTransaction {
    fn new(options: Options) -> Self {
        Self(options)
    }

    fn options(&self) -> &Options {
        &self.0
    }
}

struct Failure {
    code: &'static str,
    message: String,
}

impl Failure {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self::new("release.independent-verifier-rejected", message)
    }
}

#[derive(Clone)]
struct EvidenceMember {
    id: Option<String>,
    path: String,
    sha256: String,
}

#[derive(Clone)]
struct Oracle {
    value: Value,
}

struct Manifest {
    platform: String,
    candidate_executable_sha256: String,
    oracle: Oracle,
    records: Vec<EvidenceMember>,
    exploratory_records: Vec<EvidenceMember>,
    observations: Vec<EvidenceMember>,
    assigned_obligations: u64,
}

struct EvidenceRecord {
    id: String,
    cell: CellKey,
    obligation_id: String,
    case_id: String,
    candidate_observation: String,
    oracle_observation: String,
    requested_normalizers: Vec<String>,
    producer_platform: String,
}

struct SemanticBoundary {
    builtin: u64,
    argument: u64,
    class: String,
    outcome: String,
    error_code: Option<String>,
}

struct SemanticObligationEvent {
    builtin: u64,
    outcome: String,
    materialized_before: u64,
    materialized_after: u64,
    callback_count: usize,
}

type EvidenceTarget = (CellKey, String, String);

/// Independently reconstructs a release decision and atomically persists it.
///
/// # Errors
///
/// Returns an error when an input is invalid, the reconstructed release is
/// blocked, or the decision/report transaction cannot be persisted.
pub fn verify(options: Options) -> Result<String, String> {
    let transaction = VerificationTransaction::new(options);
    let options = transaction.options();
    if options.output.exists() {
        return Err("independent verifier output already exists".to_owned());
    }
    let result = verify_inner(options);
    let staging = staging_path(&options.output)?;
    fs::create_dir(&staging)
        .map_err(|error| format!("cannot create independent verifier staging: {error}"))?;
    let persist = match &result {
        Ok(verification) => write_json_new(
            &staging.join("independent-verifier-decision.json"),
            &verification.decision.json(),
        )
        .and_then(|()| {
            write_json_new(
                &staging.join("independent-verifier-report.json"),
                &json::object([
                    ("admitted", Value::Bool(true)),
                    ("diagnosticCode", Value::Null),
                    ("implementation", json::string("hell-release-verifier")),
                    ("schemaVersion", json::number(1)),
                    ("state", json::string("admitted")),
                ]),
            )
        }),
        Err(error) => write_json_new(
            &staging.join("independent-verifier-report.json"),
            &json::object([
                ("admitted", Value::Bool(false)),
                ("diagnosticCode", json::string(error.code)),
                (
                    "diagnosticMessage",
                    json::string(&bounded_diagnostic(&error.message)),
                ),
                ("implementation", json::string("hell-release-verifier")),
                ("schemaVersion", json::number(1)),
                ("state", json::string("blocked")),
            ]),
        ),
    };
    if let Err(persist) = persist {
        return match result {
            Ok(_) => Err(persist),
            Err(primary) => Err(format!("{}; additionally, {persist}", primary.message)),
        };
    }
    fs::rename(&staging, &options.output).map_err(|promote| match &result {
        Ok(_) => format!("cannot atomically promote independent verifier output: {promote}"),
        Err(primary) => format!(
            "{}; additionally, cannot atomically promote independent verifier diagnostics: {promote}", primary.message
        ),
    })?;
    match result {
        Ok(_) => Ok("independently reconstructed and admitted the release bundle".to_owned()),
        Err(error) => Err(error.message),
    }
}

fn staging_path(output: &Path) -> Result<PathBuf, String> {
    let parent = output
        .parent()
        .ok_or_else(|| "independent verifier output has no parent".to_owned())?;
    let name = output
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| "independent verifier output name is not UTF-8".to_owned())?;
    let staging = parent.join(format!(".{name}.staging-{}", std::process::id()));
    if staging.exists() {
        return Err("independent verifier staging already exists".to_owned());
    }
    Ok(staging)
}

fn verify_inner(options: &Options) -> Result<Verification, Failure> {
    let ParsedVerificationInputs {
        projection,
        plan,
        conformance,
        conformance_bytes,
    } = load_verification_inputs(options)?;
    let subjects_bytes = verify_subjects(&options.bundle, &plan)?;
    let native_environment_set_sha256 =
        verify_native_environment_set(&options.bundle.join("native-environment-set.json"), &plan)
            .map_err(|message| Failure::new("release.binding.native-environment", message))?;
    let executables = verify_packages(&options.bundle, &plan, projection.archive_limits)?;
    let evidence_path = options.bundle.join("conformance-evidence.tar.gz");
    let evidence_bytes = read_bounded(&evidence_path, 256 * 1024 * 1024)?;
    let evidence_sha256 = digest::sha256_hex(&evidence_bytes);
    let evidence = archive::read_classified(
        &evidence_path,
        Some(plan.source_date_epoch),
        projection.archive_limits,
    )
    .map_err(|error| Failure::new(error.code, error.message))?;
    let report = verify_evidence_and_ledger(&EvidenceVerification {
        projection: &projection,
        plan: &plan,
        conformance: &conformance,
        conformance_bytes: &conformance_bytes,
        evidence: &evidence,
        executables: &executables,
        bundle: &options.bundle,
        evidence_sha256: &evidence_sha256,
    })?;
    let required = report
        .counts
        .verified()?
        .checked_add(report.counts.exempted)
        .and_then(|count| {
            report
                .counts
                .blocked()
                .ok()
                .and_then(|blocked| count.checked_add(blocked))
        })
        .ok_or_else(|| "required cell count overflow".to_owned())?;
    let gate_sha256 = verify_release_gate(
        &options.bundle,
        &plan,
        &conformance,
        &report,
        &subjects_bytes,
        &evidence_sha256,
        &native_environment_set_sha256,
    )?;
    let governance_receipts = verify_governance_receipt_chain(options, &plan)?;
    let decision = build_decision(DecisionInputs {
        projection,
        plan: &plan,
        conformance: &conformance,
        report: &report,
        subjects_bytes: &subjects_bytes,
        native_environment_set_sha256,
        gate_sha256,
        governance_receipts,
        required,
    })?;
    if !decision.admitted {
        return Err(Failure::new(
            "release.ledger.blocked",
            "independent ledger contains blocked cells",
        ));
    }
    Ok(Verification { decision })
}

struct ParsedVerificationInputs {
    projection: Projection,
    plan: ReleasePlan,
    conformance: ConformancePlan,
    conformance_bytes: Vec<u8>,
}

fn load_verification_inputs(options: &Options) -> Result<ParsedVerificationInputs, Failure> {
    let projection = load_projection(&options.protocol_projection)?;
    let plan_bytes = read_bounded(&options.plan, json::MAX_JSON_BYTES)?;
    let plan_json = json::parse_canonical_classified(&plan_bytes)
        .map_err(|error| Failure::new(error.code, error.message))?;
    if plan_json
        .object()
        .ok()
        .and_then(|fields| fields.get("schemaVersion"))
        .and_then(|value| value.number().ok())
        != Some(2)
    {
        return Err(Failure::new(
            "release.protocol.downgrade",
            "release plan schema version is not the bound protocol version",
        ));
    }
    let plan = ReleasePlan::parse(&plan_json)
        .map_err(|message| Failure::new("release.json.unknown-field", message))?;
    external_inputs::require_expected(&projection.external_inputs, &plan.external_inputs_sha256)
        .map_err(|message| Failure::new("release.binding.external-input-lock", message))?;
    let conformance_bytes = read_bounded(&options.conformance_plan, json::MAX_JSON_BYTES)?;
    let conformance_json = json::parse_canonical_classified(&conformance_bytes)
        .map_err(|error| Failure::new(error.code, error.message))?;
    let exemption_diagnostic = classify_exemption_violation(&conformance_json, &plan)?;
    let conformance = ConformancePlan::parse(&conformance_json).map_err(|message| {
        Failure::new(
            exemption_diagnostic.unwrap_or("release.independent-verifier-rejected"),
            message,
        )
    })?;
    if conformance.candidate_sha != plan.candidate_sha {
        return Err(Failure::new(
            "release.binding.candidate-sha",
            "conformance candidate SHA differs from release plan",
        ));
    }
    if conformance.workflow_sha != plan.workflow_sha {
        return Err(Failure::new(
            "release.binding.workflow-sha",
            "conformance workflow SHA differs from release plan",
        ));
    }
    if conformance.source_inventory_sha256 != plan.source_inventory_sha256 {
        return Err(Failure::new(
            "release.binding.source-inventory",
            "conformance source inventory differs from release plan",
        ));
    }
    if conformance.plan_sha256 != plan.conformance_plan_sha256
        || conformance.evaluation_instant != plan.evaluation_instant
    {
        return Err(Failure::new(
            "release.binding.conformance-plan",
            "conformance plan binding differs from release plan",
        ));
    }
    Ok(ParsedVerificationInputs {
        projection,
        plan,
        conformance,
        conformance_bytes,
    })
}

fn verify_subjects(bundle: &Path, plan: &ReleasePlan) -> Result<Vec<u8>, Failure> {
    let subjects_bytes = read_bounded(&bundle.join("SUBJECTS.sha256"), json::MAX_JSON_BYTES)?;
    let subjects = parse_subjects(&subjects_bytes)?;
    let expected_subjects = expected_subjects(plan);
    let observed_subjects = subjects.keys().cloned().collect::<BTreeSet<_>>();
    if observed_subjects != expected_subjects {
        let code = if expected_subjects
            .difference(&observed_subjects)
            .next()
            .is_some()
        {
            "release.subject.missing"
        } else {
            "release.subject.extra"
        };
        return Err(Failure::new(code, "SUBJECTS.sha256 exact set differs"));
    }
    require_bundle_inventory(bundle, &expected_subjects)
        .map_err(|message| Failure::new("release.subject.extra", message))?;
    for (name, expected) in &subjects {
        let bytes = read_bounded(&bundle.join(name), 256 * 1024 * 1024)?;
        if digest::sha256_hex(&bytes) != *expected {
            return Err(Failure::new(
                "release.subject.digest",
                format!("release subject {name:?} digest differs"),
            ));
        }
    }
    Ok(subjects_bytes)
}

struct DecisionInputs<'a> {
    projection: Projection,
    plan: &'a ReleasePlan,
    conformance: &'a ConformancePlan,
    report: &'a ConformanceReport,
    subjects_bytes: &'a [u8],
    native_environment_set_sha256: String,
    gate_sha256: String,
    governance_receipts: GovernanceReceiptDigests,
    required: u64,
}

fn build_decision(input: DecisionInputs<'_>) -> Result<Decision, Failure> {
    let DecisionInputs {
        projection,
        plan,
        conformance,
        report,
        subjects_bytes,
        native_environment_set_sha256,
        gate_sha256,
        governance_receipts,
        required,
    } = input;
    Ok(Decision {
        implementation: "hell-release-verifier".to_owned(),
        protocol_sha256: projection.protocol_sha256,
        candidate_sha: plan.candidate_sha.clone(),
        workflow_sha: plan.workflow_sha.clone(),
        release_plan_sha256: plan.plan_sha256.clone(),
        conformance_plan_sha256: conformance.plan_sha256.clone(),
        source_inventory_sha256: plan.source_inventory_sha256.clone(),
        trusted_inputs_sha256: plan.trusted_inputs_sha256.clone(),
        obligation_rules_sha256: projection.obligation_rules_sha256,
        governance_declaration_sha256: plan.governance_declaration_sha256.clone(),
        governance_profile_sha256: plan.governance_profile_sha256.clone(),
        governance_resolve_sha256: governance_receipts.resolve,
        governance_post_assembly_sha256: governance_receipts.post_assembly,
        governance_pre_attestation_sha256: governance_receipts.pre_attestation,
        residual_assumption_set_sha256: plan.residual_assumption_set_sha256.clone(),
        external_inputs_sha256: plan.external_inputs_sha256.clone(),
        native_environment_set_sha256,
        cell_ledger_sha256: digest::domain("cell-ledger", 1, &report.cells_bytes),
        subject_manifest_sha256: digest::sha256_hex(subjects_bytes),
        release_gate_sha256: gate_sha256,
        required_cell_count: required,
        verified_cell_count: report.counts.verified()?,
        exempted_cell_count: report.counts.exempted,
        blocked_cell_count: report.counts.blocked()?,
        admitted: report.admitted,
    })
}

struct GovernanceReceiptDigests {
    resolve: String,
    post_assembly: String,
    pre_attestation: String,
}

fn verify_governance_receipt_chain(
    options: &Options,
    plan: &ReleasePlan,
) -> Result<GovernanceReceiptDigests, Failure> {
    let resolve_path = options.governance_resolve.as_deref().ok_or_else(|| {
        Failure::new(
            "release.binding.governance-receipt",
            "independent verification requires the resolve governance receipt",
        )
    })?;
    let post_assembly_path = options.governance_post_assembly.as_deref().ok_or_else(|| {
        Failure::new(
            "release.binding.governance-receipt",
            "independent verification requires the post-assembly governance receipt",
        )
    })?;
    let pre_attestation_path = options
        .governance_pre_attestation
        .as_deref()
        .ok_or_else(|| {
            Failure::new(
                "release.binding.governance-receipt",
                "independent verification requires the pre-attestation governance receipt",
            )
        })?;
    verify_governance_receipt_paths(resolve_path, post_assembly_path, pre_attestation_path, plan)
        .map_err(|message| Failure::new("release.binding.governance-receipt", message))
}

fn verify_governance_receipt_paths(
    resolve_path: &Path,
    post_assembly_path: &Path,
    pre_attestation_path: &Path,
    plan: &ReleasePlan,
) -> Result<GovernanceReceiptDigests, String> {
    let resolve = verify_governance_receipt(resolve_path, plan, "resolve", None, None)?;
    let post_assembly = verify_governance_receipt(
        post_assembly_path,
        plan,
        "post-assembly",
        Some(&resolve),
        Some(&resolve),
    )?;
    let pre_attestation = verify_governance_receipt(
        pre_attestation_path,
        plan,
        "pre-attestation",
        Some(&resolve),
        Some(&post_assembly),
    )?;
    Ok(GovernanceReceiptDigests {
        resolve,
        post_assembly,
        pre_attestation,
    })
}

fn verify_governance_receipt(
    path: &Path,
    plan: &ReleasePlan,
    phase: &str,
    baseline_sha256: Option<&str>,
    predecessor_sha256: Option<&str>,
) -> Result<String, String> {
    let bytes = read_bounded(path, json::MAX_JSON_BYTES)?;
    let value = json::parse_canonical(&bytes)?;
    let fields = value.object()?;
    json::exact_keys(
        fields,
        &[
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
        ],
    )?;
    let expected_predecessor_phase = match phase {
        "resolve" => None,
        "post-assembly" => Some("resolve"),
        "pre-attestation" => Some("post-assembly"),
        _ => return Err("unknown governance receipt phase".to_owned()),
    };
    if json::member(fields, "schemaVersion")?.number()? != 1
        || json::member(fields, "phase")?.string()? != phase
        || json::member(fields, "planSha256")?.string()? != plan.plan_sha256
        || json::member(fields, "candidateSha")?.string()? != plan.candidate_sha
        || json::member(fields, "candidateBranch")?.string()? != plan.candidate_branch
        || json::member(fields, "repository")?.string()? != plan.repository
        || json::member(fields, "repositoryId")?.number()? != plan.repository_id
        || json::member(fields, "runId")?.number()? != plan.run_id
        || json::member(fields, "runAttempt")?.number()? != plan.run_attempt
        || json::member(fields, "tag")?.string()? != plan.tag
        || json::member(fields, "workflowRef")?.string()? != plan.workflow_ref
        || json::member(fields, "workflowSha")?.string()? != plan.workflow_sha
        || json::member(fields, "governanceDeclarationSha256")?.string()?
            != plan.governance_declaration_sha256
        || json::member(fields, "observations")?.array()?.is_empty()
    {
        return Err("governance receipt differs from the independent plan binding".to_owned());
    }
    require_optional_governance_digest(fields, "baselineSha256", baseline_sha256)?;
    require_optional_governance_digest(fields, "predecessorSha256", predecessor_sha256)?;
    match (
        json::member(fields, "predecessorPhase")?,
        expected_predecessor_phase,
    ) {
        (Value::Null, None) => {}
        (Value::String(observed), Some(expected)) if observed == expected => {}
        _ => return Err("governance receipt predecessor phase differs".to_owned()),
    }
    for name in [
        "apiPolicySha256",
        "governanceProfileSha256",
        "residualAssumptionSetSha256",
    ] {
        model::require_digest(json::member(fields, name)?.string()?, name)?;
    }
    let residuals = json::member(fields, "residualAssumptions")?.array()?;
    let mut previous = None::<&str>;
    for residual in residuals {
        let residual = residual.string()?;
        if residual.is_empty() || previous.is_some_and(|previous| previous >= residual) {
            return Err(
                "governance receipt residual inventory is not sorted and unique".to_owned(),
            );
        }
        previous = Some(residual);
    }
    Ok(digest::sha256_hex(&bytes))
}

fn require_optional_governance_digest(
    fields: &BTreeMap<String, Value>,
    name: &str,
    expected: Option<&str>,
) -> Result<(), String> {
    match (json::member(fields, name)?, expected) {
        (Value::Null, None) => Ok(()),
        (Value::String(observed), Some(expected)) if observed == expected => {
            model::require_digest(observed, name)
        }
        _ => Err(format!("governance receipt {name} binding differs")),
    }
}

fn classify_exemption_violation(
    conformance: &Value,
    plan: &ReleasePlan,
) -> Result<Option<&'static str>, String> {
    let fields = conformance.object()?;
    let evaluation = json::member(fields, "releaseEvaluationInstant")?.string()?;
    let evaluation_date = evaluation
        .split_once('T')
        .ok_or_else(|| "conformance evaluation instant lacks date".to_owned())?
        .0;
    for cell in json::member(fields, "cells")?.array()? {
        let cell = cell.object()?;
        let exemptions = json::member(cell, "exemptions")?.array()?;
        if exemptions.is_empty() {
            continue;
        }
        if evaluation != plan.evaluation_instant {
            return Ok(Some("release.exemption.evaluation-instant"));
        }
        let exemption = exemptions[0].object()?;
        let key = json::member(cell, "key")?;
        let obligations = json::member(cell, "obligations")?.array()?;
        let obligation = json::member(exemption, "obligationId")?.string()?;
        let targets_obligation = obligations.iter().any(|value| {
            value
                .object()
                .ok()
                .and_then(|fields| fields.get("id"))
                .and_then(|value| value.string().ok())
                == Some(obligation)
        });
        if json::member(exemption, "candidateSha")?.string()? != plan.candidate_sha
            || json::member(exemption, "standard")?.string()?
                != json::member(fields, "standard")?.string()?
            || json::member(exemption, "baseline")?.string()?
                != json::member(fields, "baseline")?.string()?
            || json::member(exemption, "cell")? != key
            || !targets_obligation
        {
            return Ok(Some("release.exemption.selector"));
        }
        if json::member(exemption, "expiresOn")?.string()? <= evaluation_date {
            return Ok(Some("release.exemption.expired"));
        }
    }
    Ok(None)
}

fn load_projection(path: &Path) -> Result<Projection, String> {
    let bytes = read_bounded(path, json::MAX_JSON_BYTES)?;
    let value = json::parse_canonical(&bytes)?;
    let fields = value.object()?;
    json::exact_keys(
        fields,
        &[
            "limits",
            "protocolSha256",
            "protocolVersion",
            "schemaVersion",
        ],
    )?;
    if json::member(fields, "schemaVersion")?.number()? != 1
        || json::member(fields, "protocolVersion")?.string()? != model::ADMISSION_PROTOCOL
    {
        return Err("unsupported release protocol projection".to_owned());
    }
    let limits = json::member(fields, "limits")?.object()?;
    json::exact_keys(
        limits,
        &[
            "maxArchiveCompressedBytes",
            "maxArchiveExpandedBytes",
            "maxArchiveMembers",
            "maxArchivePathBytes",
            "maxDiagnostics",
            "maxEvidenceRecords",
            "maxJsonBytes",
            "maxJsonDepth",
            "maxJsonMembers",
            "maxStringBytes",
        ],
    )?;
    let expected = [
        ("maxArchiveCompressedBytes", 256 * 1024 * 1024_u64),
        ("maxArchiveExpandedBytes", 1024 * 1024 * 1024_u64),
        ("maxArchiveMembers", 65_536),
        ("maxArchivePathBytes", 4096),
        ("maxDiagnostics", 4096),
        ("maxEvidenceRecords", 1_000_000),
        ("maxJsonBytes", 16 * 1024 * 1024),
        ("maxJsonDepth", 64),
        ("maxJsonMembers", 1_000_000),
        ("maxStringBytes", 1024 * 1024),
    ];
    for (name, expected) in expected {
        if json::member(limits, name)?.number()? != expected {
            return Err(format!(
                "protocol projection limit {name} differs from implementation"
            ));
        }
    }
    let archive_limits = ArchiveLimits {
        maximum_compressed_bytes: projection_limit(limits, "maxArchiveCompressedBytes")?,
        maximum_expanded_bytes: projection_limit(limits, "maxArchiveExpandedBytes")?,
        maximum_members: projection_limit(limits, "maxArchiveMembers")?,
        maximum_path_bytes: projection_limit(limits, "maxArchivePathBytes")?,
    };
    let protocol_sha256 = json::member(fields, "protocolSha256")?.string()?.to_owned();
    model::require_digest(&protocol_sha256, "protocol input digest")?;
    let observed = normative_protocol_digest(path, fields)?;
    if observed != protocol_sha256 {
        return Err("protocol projection does not bind the normative inputs".to_owned());
    }
    let repository_root = path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| "protocol projection repository root is unavailable".to_owned())?
        .to_path_buf();
    let obligation_rules = read_bounded(
        &repository_root
            .join("compat")
            .join("release-obligation-rules-v1.json"),
        json::MAX_JSON_BYTES,
    )?;
    let obligation_rules_value = json::parse(&obligation_rules)?;
    let obligation_rules_sha256 = digest::sha256_hex(&json::canonical(&obligation_rules_value)?);
    let obligation_rules = parse_obligation_rules(&obligation_rules_value)?;
    let external_inputs = external_inputs::load(&repository_root.join("ci/external-inputs.toml"))?;
    Ok(Projection {
        protocol_sha256,
        obligation_rules_sha256,
        obligation_rules,
        repository_root,
        archive_limits,
        external_inputs,
    })
}

fn projection_limit(limits: &BTreeMap<String, Value>, name: &str) -> Result<usize, String> {
    usize::try_from(json::member(limits, name)?.number()?)
        .map_err(|_| format!("protocol projection limit {name} does not fit this platform"))
}

fn parse_obligation_rules(value: &Value) -> Result<ObligationRules, String> {
    let fields = value.object()?;
    json::exact_keys(fields, &["protocolVersion", "rules", "schemaVersion"])?;
    if json::member(fields, "schemaVersion")?.number()? != 1
        || json::member(fields, "protocolVersion")?.string()? != model::ADMISSION_PROTOCOL
    {
        return Err("unsupported obligation-rule document".to_owned());
    }
    let expected = [
        "required-exact-agreement",
        "required-platform-equivalence",
        "not-applicable",
        "excluded-profile",
        "reviewed-exemption",
    ];
    let rules = json::member(fields, "rules")?.array()?;
    if rules.len() != expected.len() {
        return Err("obligation-rule inventory differs".to_owned());
    }
    let mut parsed = Vec::with_capacity(rules.len());
    for (rule, expected_id) in rules.iter().zip(expected) {
        let rule = rule.object()?;
        json::exact_keys(rule, &["id", "require", "when"])?;
        if json::member(rule, "id")?.string()? != expected_id {
            return Err("obligation-rule order or identity differs".to_owned());
        }
        parsed.push(ObligationRule {
            id: expected_id.to_owned(),
            condition: parse_rule_condition(json::member(rule, "when")?)?,
            requirement: parse_rule_requirement(json::member(rule, "require")?)?,
        });
    }
    Ok(ObligationRules { rules: parsed })
}

fn parse_rule_condition(value: &Value) -> Result<RuleCondition, String> {
    let fields = value.object()?;
    if fields.len() != 1 {
        return Err("obligation-rule expression must have one operator".to_owned());
    }
    let (operator, operand) = fields
        .first_key_value()
        .ok_or_else(|| "obligation-rule expression is empty".to_owned())?;
    match operator.as_str() {
        "fieldEquals" => {
            let operand = operand.object()?;
            json::exact_keys(operand, &["field", "value"])?;
            let value = json::member(operand, "value")?.string()?.to_owned();
            if value.is_empty() {
                return Err("obligation-rule equality contains an empty value".to_owned());
            }
            Ok(RuleCondition::Equals {
                field: parse_rule_field(json::member(operand, "field")?.string()?)?,
                value,
            })
        }
        "fieldIn" => {
            let operand = operand.object()?;
            json::exact_keys(operand, &["field", "values"])?;
            if json::member(operand, "values")?.array()?.is_empty() {
                return Err("obligation-rule membership is empty".to_owned());
            }
            let mut values = BTreeSet::new();
            for value in json::member(operand, "values")?.array()? {
                let value = value.string()?.to_owned();
                if value.is_empty() || !values.insert(value) {
                    return Err("obligation-rule membership is duplicated".to_owned());
                }
            }
            Ok(RuleCondition::Includes {
                field: parse_rule_field(json::member(operand, "field")?.string()?)?,
                values,
            })
        }
        _ => Err("unknown obligation-rule condition operator".to_owned()),
    }
}

fn parse_rule_requirement(value: &Value) -> Result<RuleRequirement, String> {
    let fields = value.object()?;
    if fields.len() != 1 {
        return Err("obligation-rule expression must have one operator".to_owned());
    }
    let (operator, operand) = fields
        .first_key_value()
        .ok_or_else(|| "obligation-rule expression is empty".to_owned())?;
    match operator.as_str() {
        "evidenceKindIn" => {
            let values = operand.array()?;
            if values.is_empty() {
                return Err("obligation-rule evidence kinds are empty".to_owned());
            }
            let mut observed = BTreeSet::new();
            for value in values {
                let value = value.string()?.to_owned();
                if !matches!(
                    value.as_str(),
                    "applicability-decision"
                        | "candidate-observation"
                        | "comparison"
                        | "mismatch"
                        | "native-oracle-observation"
                        | "oracle-observation"
                        | "profile-exclusion"
                        | "reviewed-exemption"
                ) || !observed.insert(value)
                {
                    return Err("obligation-rule evidence kinds are duplicated".to_owned());
                }
            }
            Ok(RuleRequirement::EvidenceKinds(observed))
        }
        "boundedDateAtOrAfterPlanInstant" => {
            let operand = operand.object()?;
            json::exact_keys(operand, &["field"])?;
            let field = parse_rule_field(json::member(operand, "field")?.string()?)?;
            if !matches!(field, RuleField::ExpiresAt) {
                return Err("obligation-rule bounded-date field differs".to_owned());
            }
            Ok(RuleRequirement::DateAfterEvaluation { field })
        }
        "all" | "any" => {
            let expressions = operand.array()?;
            if expressions.is_empty() {
                return Err("obligation-rule boolean expression is empty".to_owned());
            }
            let expressions = expressions
                .iter()
                .map(parse_rule_requirement)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(if operator == "all" {
                RuleRequirement::All(expressions)
            } else {
                RuleRequirement::Any(expressions)
            })
        }
        _ => Err("unknown or misplaced obligation-rule operator".to_owned()),
    }
}

fn parse_rule_field(value: &str) -> Result<RuleField, String> {
    match value {
        "applicability" => Ok(RuleField::Applicability),
        "dispositionClass" => Ok(RuleField::DispositionClass),
        "expiresAt" => Ok(RuleField::ExpiresAt),
        "profile" => Ok(RuleField::Profile),
        _ => Err("obligation-rule field is unknown".to_owned()),
    }
}

struct RuleFacts<'a> {
    applicability: &'a str,
    disposition_class: Option<&'a str>,
    evidence_kinds: BTreeSet<&'a str>,
    evaluation_date: &'a str,
    expires_at: Option<&'a str>,
    profile: &'a str,
}

impl ObligationRules {
    fn require_cell(
        &self,
        cell: &PlannedCell,
        disposition: &Value,
        evaluation: &str,
    ) -> Result<(), String> {
        let fields = disposition.object()?;
        let kind = json::member(fields, "kind")?.string()?;
        if kind == "blocked" {
            return Ok(());
        }
        let (applicability, disposition_class, evidence_kinds) = match kind {
            "not-applicable" => (
                "not-applicable",
                None,
                BTreeSet::from(["applicability-decision"]),
            ),
            "excluded" => ("excluded", None, BTreeSet::from(["profile-exclusion"])),
            "verified-exact" | "verified-normalized" => (
                "required",
                Some("exact-agreement"),
                BTreeSet::from(["candidate-observation", "comparison", "oracle-observation"]),
            ),
            "verified-platform-equivalent" => (
                "required",
                Some("platform-equivalence"),
                BTreeSet::from([
                    "candidate-observation",
                    "comparison",
                    "native-oracle-observation",
                ]),
            ),
            "exempted" => (
                "required",
                Some("exemption"),
                BTreeSet::from(["mismatch", "reviewed-exemption"]),
            ),
            _ => return Err("ledger disposition has no declarative-rule class".to_owned()),
        };
        let evaluation_date = evaluation
            .split_once('T')
            .map(|(date, _)| date)
            .ok_or_else(|| "release evaluation instant has no date separator".to_owned())?;
        let facts = RuleFacts {
            applicability,
            disposition_class,
            evidence_kinds,
            evaluation_date,
            expires_at: cell
                .exemption
                .as_ref()
                .map(|value| value.expires_on.as_str()),
            profile: &cell.key.profile,
        };
        let matching = self
            .rules
            .iter()
            .filter(|rule| rule.condition.matches(&facts))
            .collect::<Vec<_>>();
        let [rule] = matching.as_slice() else {
            return Err(
                "ledger cell does not select one exact declarative obligation rule".to_owned(),
            );
        };
        if !rule.requirement.satisfied_by(&facts) {
            return Err(format!(
                "ledger cell does not satisfy declarative obligation rule {:?}",
                rule.id
            ));
        }
        Ok(())
    }
}

impl RuleCondition {
    fn matches(&self, facts: &RuleFacts<'_>) -> bool {
        match self {
            Self::Equals { field, value } => field.value(facts) == Some(value.as_str()),
            Self::Includes { field, values } => field
                .value(facts)
                .is_some_and(|value| values.contains(value)),
        }
    }
}

impl RuleRequirement {
    fn satisfied_by(&self, facts: &RuleFacts<'_>) -> bool {
        match self {
            Self::EvidenceKinds(required) => required
                .iter()
                .all(|kind| facts.evidence_kinds.contains(kind.as_str())),
            Self::DateAfterEvaluation { field } => field
                .value(facts)
                .is_some_and(|date| date > facts.evaluation_date),
            Self::All(requirements) => requirements
                .iter()
                .all(|requirement| requirement.satisfied_by(facts)),
            Self::Any(requirements) => requirements
                .iter()
                .any(|requirement| requirement.satisfied_by(facts)),
        }
    }
}

impl RuleField {
    fn value<'a>(self, facts: &'a RuleFacts<'_>) -> Option<&'a str> {
        match self {
            Self::Applicability => Some(facts.applicability),
            Self::DispositionClass => facts.disposition_class,
            Self::ExpiresAt => facts.expires_at,
            Self::Profile => Some(facts.profile),
        }
    }
}

fn normative_protocol_digest(
    projection_path: &Path,
    fields: &BTreeMap<String, Value>,
) -> Result<String, String> {
    let repository_root = projection_path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| "protocol projection is not under ci/release-protocol/v1".to_owned())?;
    let expected = repository_root
        .join("ci")
        .join("release-protocol")
        .join("v1")
        .join("projection.json");
    if fs::canonicalize(projection_path).ok() != fs::canonicalize(&expected).ok() {
        return Err(
            "protocol projection path differs from the repository protocol path".to_owned(),
        );
    }
    let mut projection = fields.clone();
    projection.remove("protocolSha256");
    let projection = json::canonical(&Value::Object(projection))?;
    let rules_path = repository_root
        .join("compat")
        .join("release-obligation-rules-v1.json");
    let rules = read_bounded(&rules_path, json::MAX_JSON_BYTES)?;
    let rules = json::canonical(&json::parse(&rules)?)?;
    let specification = read_bounded(
        &repository_root
            .join("spec")
            .join("release-admission-protocol-v1.md"),
        json::MAX_JSON_BYTES,
    )?;
    let mut bound = b"hell-rs:release-admission-inputs:1\0".to_vec();
    bound.extend_from_slice(projection.strip_suffix(b"\n").unwrap_or(&projection));
    bound.push(0);
    bound.extend_from_slice(rules.strip_suffix(b"\n").unwrap_or(&rules));
    bound.push(0);
    bound.extend_from_slice(&specification);
    Ok(digest::sha256_hex(&bound))
}

fn validate_trusted_inputs(
    projection: &Projection,
    bytes: &[u8],
    plan: &ReleasePlan,
) -> Result<TrustedInputs, String> {
    let value = json::parse_canonical(bytes)?;
    let fields = value.object()?;
    json::exact_keys(
        fields,
        &[
            "aggregateSha256",
            "exploratoryPolicy",
            "files",
            "schemaVersion",
            "workflowSha",
        ],
    )?;
    if json::member(fields, "schemaVersion")?.number()? != 1
        || json::member(fields, "workflowSha")?.string()? != plan.workflow_sha
    {
        return Err("trusted-input manifest identity differs".to_owned());
    }
    let policy = json::member(fields, "exploratoryPolicy")?.object()?;
    json::exact_keys(
        policy,
        &["generatedAgreementMayVerify", "generatedMismatchBlocks"],
    )?;
    if json::member(policy, "generatedAgreementMayVerify")?.boolean()?
        || !json::member(policy, "generatedMismatchBlocks")?.boolean()?
    {
        return Err("trusted-input exploratory policy weakens admission".to_owned());
    }
    validate_trusted_control_files(projection, fields)?;
    let builtin_ids = load_builtin_ids(&projection.repository_root)?;
    Ok(TrustedInputs {
        builtin_ids,
        oracle_repository: projection.external_inputs.oracle_repository.clone(),
        oracle_commit: projection.external_inputs.oracle_commit.clone(),
        linux_oracle_executable_sha256: projection
            .external_inputs
            .linux_oracle_executable_sha256
            .clone(),
    })
}

fn validate_trusted_control_files(
    projection: &Projection,
    fields: &BTreeMap<String, Value>,
) -> Result<(), String> {
    let files = json::member(fields, "files")?.array()?;
    if files.len() != TRUSTED_CONTROL_PATHS.len() {
        return Err("trusted-input exact file inventory differs".to_owned());
    }
    for (entry, expected_path) in files.iter().zip(TRUSTED_CONTROL_PATHS) {
        let entry = entry.object()?;
        json::exact_keys(entry, &["path", "sha256"])?;
        if json::member(entry, "path")?.string()? != expected_path {
            return Err("trusted-input file order or path differs".to_owned());
        }
        let expected_digest = json::member(entry, "sha256")?.string()?;
        model::require_digest(expected_digest, "trusted-input file digest")?;
        let trusted_bytes = read_bounded(
            &projection.repository_root.join(expected_path),
            json::MAX_JSON_BYTES,
        )?;
        if digest::sha256_hex(&trusted_bytes) != expected_digest {
            return Err(format!(
                "trusted-input file {expected_path:?} differs from the trusted checkout"
            ));
        }
    }
    let stated = json::member(fields, "aggregateSha256")?.string()?;
    model::require_digest(stated, "trusted-input aggregate digest")?;
    let mut without = fields.clone();
    without.remove("aggregateSha256");
    if digest::sha256_hex(&json::canonical(&Value::Object(without))?) != stated {
        return Err("trusted-input aggregate self-digest differs".to_owned());
    }
    Ok(())
}

fn load_builtin_ids(repository_root: &Path) -> Result<BTreeMap<String, u64>, String> {
    let registry = read_bounded(
        &repository_root.join("compat").join("builtin-registry.json"),
        json::MAX_JSON_BYTES,
    )?;
    let registry = json::parse_canonical(&registry)?;
    let registry_fields = registry.object()?;
    json::exact_keys(registry_fields, &["builtins", "schemaVersion"])?;
    if json::member(registry_fields, "schemaVersion")?.number()? != 1 {
        return Err("unsupported trusted builtin registry".to_owned());
    }
    let mut builtin_ids = BTreeMap::new();
    for (index, builtin) in json::member(registry_fields, "builtins")?
        .array()?
        .iter()
        .enumerate()
    {
        let builtin = builtin.object()?;
        json::exact_keys(builtin, &["arity", "id", "visibility", "wiring"])?;
        let name = json::member(builtin, "id")?.string()?.to_owned();
        if name.is_empty()
            || builtin_ids
                .insert(
                    name,
                    u64::try_from(index).map_err(|_| "builtin ID overflow".to_owned())?,
                )
                .is_some()
        {
            return Err("trusted builtin registry contains a duplicate identity".to_owned());
        }
    }
    Ok(builtin_ids)
}

fn expected_subjects(plan: &ReleasePlan) -> BTreeSet<String> {
    BTreeSet::from([
        "conformance-acceptance.json".to_owned(),
        "conformance-evidence.tar.gz".to_owned(),
        "conformance-plan.json".to_owned(),
        "conformance-report.html".to_owned(),
        "conformance-report.json".to_owned(),
        "dependency-policy.json".to_owned(),
        "mutation-report.json".to_owned(),
        "native-environment-set.json".to_owned(),
        "release-manifest.json".to_owned(),
        "release-notes.md".to_owned(),
        format!("hell-v{}-linux-x86_64.tar.gz", plan.version),
        format!("hell-v{}-macos-aarch64.tar.gz", plan.version),
        format!("hell-v{}-windows-x86_64.tar.gz", plan.version),
    ])
}

fn verify_native_environment_set(path: &Path, plan: &ReleasePlan) -> Result<String, String> {
    let bytes = read_bounded(path, json::MAX_JSON_BYTES)?;
    let value = json::parse_canonical(&bytes)?;
    let fields = value.object()?;
    json::exact_keys(
        fields,
        &["externalInputsSha256", "receipts", "schemaVersion"],
    )?;
    if json::member(fields, "schemaVersion")?.number()? != 1
        || json::member(fields, "externalInputsSha256")?.string()? != plan.external_inputs_sha256
    {
        return Err(
            "native environment set does not bind the release external-input lock".to_owned(),
        );
    }
    let records = json::member(fields, "receipts")?.array()?;
    let platforms = ["linux-x86_64", "macos-aarch64", "windows-x86_64"];
    if records.len() != platforms.len() {
        return Err("native environment set does not contain exactly three receipts".to_owned());
    }
    for (record, platform) in records.iter().zip(platforms) {
        let record = record.object()?;
        json::exact_keys(
            record,
            &["nativeEnvironmentSha256", "platformId", "receipt"],
        )?;
        if json::member(record, "platformId")?.string()? != platform {
            return Err("native environment receipt platform order differs".to_owned());
        }
        let receipt = json::member(record, "receipt")?;
        verify_native_environment_receipt(receipt, platform, &plan.external_inputs_sha256)?;
        let receipt_bytes = json::canonical(receipt)?;
        if json::member(record, "nativeEnvironmentSha256")?.string()?
            != digest::domain("native-environment", 1, &receipt_bytes)
        {
            return Err(format!(
                "native environment receipt digest differs for {platform}"
            ));
        }
    }
    Ok(digest::domain("native-environment-set", 1, &bytes))
}

fn verify_native_environment_receipt(
    value: &Value,
    platform: &str,
    external_inputs_sha256: &str,
) -> Result<(), String> {
    let fields = value.object()?;
    json::exact_keys(
        fields,
        &[
            "architecture",
            "archiveImplementationProtocolVersion",
            "candidateExecutableSha256",
            "externalInputsSha256",
            "githubHostedRunner",
            "kernelVersion",
            "logicalPlatformId",
            "operatingSystemName",
            "operatingSystemVersion",
            "oracleExecutableSha256",
            "oracleSourceSha",
            "schemaVersion",
            "tools",
        ],
    )?;
    if json::member(fields, "schemaVersion")?.number()? != 1
        || json::member(fields, "archiveImplementationProtocolVersion")?.number()? != 1
        || json::member(fields, "logicalPlatformId")?.string()? != platform
        || json::member(fields, "externalInputsSha256")?.string()? != external_inputs_sha256
        || json::member(fields, "candidateExecutableSha256")? != &Value::Null
        || json::member(fields, "oracleExecutableSha256")? != &Value::Null
    {
        return Err(format!(
            "native environment receipt binding differs for {platform}"
        ));
    }
    model::require_sha(
        json::member(fields, "oracleSourceSha")?.string()?,
        "native environment oracle source SHA",
    )?;
    for name in ["architecture", "operatingSystemName"] {
        if json::member(fields, name)?.string()?.is_empty() {
            return Err(format!("native environment receipt {name} is empty"));
        }
    }
    let runner = json::member(fields, "githubHostedRunner")?.object()?;
    json::exact_keys(
        runner,
        &["imageOs", "imageVersion", "runnerArchitecture", "runnerOs"],
    )?;
    for name in ["runnerArchitecture", "runnerOs"] {
        if json::member(runner, name)?.string()?.is_empty() {
            return Err(format!("native environment runner {name} is empty"));
        }
    }
    let tools = json::member(fields, "tools")?.array()?;
    if tools.is_empty() {
        return Err(format!(
            "native environment receipt has no tools for {platform}"
        ));
    }
    let mut previous = None::<String>;
    for tool in tools {
        let tool = tool.object()?;
        json::exact_keys(
            tool,
            &[
                "executableSha256",
                "id",
                "lockVersion",
                "outputSha256",
                "parsedVersion",
            ],
        )?;
        let id = json::member(tool, "id")?.string()?.to_owned();
        if id.is_empty() || previous.as_ref().is_some_and(|previous| previous >= &id) {
            return Err(
                "native environment tool identities are empty, duplicated, or unsorted".to_owned(),
            );
        }
        previous = Some(id);
        model::require_digest(
            json::member(tool, "executableSha256")?.string()?,
            "native tool executable digest",
        )?;
        model::require_digest(
            json::member(tool, "outputSha256")?.string()?,
            "native tool output digest",
        )?;
        if json::member(tool, "parsedVersion")?.string()?.is_empty() {
            return Err("native environment tool version is empty".to_owned());
        }
    }
    Ok(())
}

fn parse_subjects(bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "SUBJECTS.sha256 is not UTF-8".to_owned())?;
    if !text.ends_with('\n') {
        return Err("SUBJECTS.sha256 has no trailing LF".to_owned());
    }
    let mut subjects = BTreeMap::new();
    let mut previous: Option<&str> = None;
    for line in text.lines() {
        let (hash, name) = line
            .split_once("  ")
            .ok_or_else(|| "SUBJECTS.sha256 line is malformed".to_owned())?;
        model::require_digest(hash, "subject digest")?;
        if name.is_empty()
            || name.contains(['/', '\\'])
            || name == "release-gate.json"
            || previous.is_some_and(|prior| prior >= name)
            || subjects.insert(name.to_owned(), hash.to_owned()).is_some()
        {
            return Err("SUBJECTS.sha256 names are unsafe, duplicated, or unsorted".to_owned());
        }
        previous = Some(name);
    }
    Ok(subjects)
}

pub(crate) fn fuzz_parse_subjects(bytes: &[u8]) -> Result<(), String> {
    parse_subjects(bytes).map(|_| ())
}

pub(crate) fn fuzz_validate_evidence(value: &Value) -> Result<(), String> {
    let fields = value.object()?;
    json::exact_keys(fields, &["observation", "schemaVersion"])?;
    if json::member(fields, "schemaVersion")?.number()? != 1 {
        return Err("unsupported independent evidence fuzz frame schema".to_owned());
    }
    let bytes = json::canonical(json::member(fields, "observation")?)?;
    validate_observation(&bytes)
}

pub(crate) fn fuzz_validate_ledger(value: &Value) -> Result<(), String> {
    ConformanceReport::parse(value).map(|_| ())
}

fn require_bundle_inventory(bundle: &Path, subjects: &BTreeSet<String>) -> Result<(), String> {
    let metadata = fs::symlink_metadata(bundle)
        .map_err(|error| format!("cannot inspect release bundle: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("release bundle is not a real directory".to_owned());
    }
    let mut expected = subjects.clone();
    expected.insert("SUBJECTS.sha256".to_owned());
    expected.insert("release-gate.json".to_owned());
    let observed = fs::read_dir(bundle)
        .map_err(|error| format!("cannot enumerate release bundle: {error}"))?
        .map(|entry| {
            let entry = entry.map_err(|error| format!("cannot inspect bundle entry: {error}"))?;
            let kind = entry
                .file_type()
                .map_err(|error| format!("cannot inspect bundle entry type: {error}"))?;
            if !kind.is_file() || kind.is_symlink() {
                return Err("release bundle contains a non-regular entry".to_owned());
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| "release bundle filename is not UTF-8".to_owned())
        })
        .collect::<Result<BTreeSet<_>, String>>()?;
    if observed != expected {
        return Err("release bundle top-level exact set differs".to_owned());
    }
    Ok(())
}

fn verify_packages(
    bundle: &Path,
    plan: &ReleasePlan,
    archive_limits: ArchiveLimits,
) -> Result<BTreeMap<String, String>, String> {
    let mut executables = BTreeMap::new();
    for (platform, executable) in [
        ("linux-x86_64", "hell"),
        ("macos-aarch64", "hell"),
        ("windows-x86_64", "hell.exe"),
    ] {
        let name = format!("hell-v{}-{platform}.tar.gz", plan.version);
        let archive = archive::read(
            &bundle.join(name),
            Some(plan.source_date_epoch),
            archive_limits,
        )?;
        let prefix = format!("hell-v{}-{platform}", plan.version);
        let expected_directories = BTreeSet::from([prefix.clone(), format!("{prefix}/bin")]);
        let expected_files = BTreeSet::from([
            format!("{prefix}/CONFORMANCE.md"),
            format!("{prefix}/LICENSE"),
            format!("{prefix}/NOTICE"),
            format!("{prefix}/README.md"),
            format!("{prefix}/bin/{executable}"),
        ]);
        if archive.directories != expected_directories
            || archive.files.keys().cloned().collect::<BTreeSet<_>>() != expected_files
        {
            return Err(format!(
                "{platform} package archive exact inventory differs"
            ));
        }
        let bytes = archive
            .files
            .get(&format!("{prefix}/bin/{executable}"))
            .ok_or_else(|| format!("{platform} package lacks executable"))?;
        executables.insert(platform.to_owned(), digest::sha256_hex(bytes));
    }
    Ok(executables)
}

struct EvidenceVerification<'a> {
    projection: &'a Projection,
    plan: &'a ReleasePlan,
    conformance: &'a ConformancePlan,
    conformance_bytes: &'a [u8],
    evidence: &'a MemberSet,
    executables: &'a BTreeMap<String, String>,
    bundle: &'a Path,
    evidence_sha256: &'a str,
}

fn verify_evidence_and_ledger(
    input: &EvidenceVerification<'_>,
) -> Result<ConformanceReport, Failure> {
    let trusted_inputs = validate_evidence_roots(input)?;
    let inventory = collect_evidence_inventory(input, &trusted_inputs)?;
    let observations = load_evidence_observations(input.evidence, &inventory.observations)?;
    let mut records = collect_evidence_records(input, &inventory, &observations)?;
    verify_reconstructed_report(input, &trusted_inputs, &observations, &mut records)
}

struct EvidenceInventory {
    manifests: BTreeMap<String, Manifest>,
    observations: BTreeMap<String, String>,
}

fn collect_evidence_inventory(
    input: &EvidenceVerification<'_>,
    trusted_inputs: &TrustedInputs,
) -> Result<EvidenceInventory, Failure> {
    let mut manifests = BTreeMap::new();
    let mut expected_files = BTreeSet::from([
        "conformance-plan.json".to_owned(),
        "source-inventory.json".to_owned(),
        "trusted-conformance-inputs.json".to_owned(),
    ]);
    let mut record_declarations = BTreeMap::<String, EvidenceMember>::new();
    let mut observation_declarations = BTreeMap::<String, String>::new();
    for platform in ["linux-x86_64", "macos-aarch64", "windows-x86_64"] {
        let path = format!("platform-manifests/{platform}.json");
        expected_files.insert(path.clone());
        let bytes = input
            .evidence
            .files
            .get(&path)
            .ok_or_else(|| format!("evidence archive lacks {path}"))?;
        validate_manifest_authority(bytes, platform, input.executables, trusted_inputs)?;
        let manifest = parse_manifest(
            bytes,
            platform,
            input.plan,
            input.conformance,
            input.executables,
            trusted_inputs,
        )?;
        for member in manifest.records.iter().chain(&manifest.exploratory_records) {
            let archive_path =
                evidence_archive_path(&member.path, "conformance-evidence", "records")?;
            if record_declarations
                .insert(archive_path.clone(), member.clone())
                .is_some()
            {
                return Err(Failure::new(
                    "release.ledger.duplicate-cell",
                    "evidence record is declared more than once",
                ));
            }
            expected_files.insert(archive_path);
        }
        for member in &manifest.observations {
            let archive_path =
                evidence_archive_path(&member.path, "conformance-observations", "observations")?;
            match observation_declarations.entry(archive_path.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(member.sha256.clone());
                }
                std::collections::btree_map::Entry::Occupied(entry)
                    if entry.get() == &member.sha256 => {}
                std::collections::btree_map::Entry::Occupied(_) => {
                    return Err(Failure::new(
                        "release.evidence.contradictory",
                        "shared observation has contradictory declarations",
                    ));
                }
            }
            expected_files.insert(archive_path);
        }
        manifests.insert(platform.to_owned(), manifest);
    }
    require_shared_oracle_source(&manifests)?;
    if input
        .evidence
        .files
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != expected_files
    {
        return Err(Failure::new(
            "release.archive.extra-member",
            "evidence archive exact member inventory differs",
        ));
    }
    for (path, declaration) in &record_declarations {
        let bytes = input
            .evidence
            .files
            .get(path)
            .ok_or_else(|| "manifest-declared evidence record is absent".to_owned())?;
        if digest::sha256_hex(bytes) != declaration.sha256 {
            return Err(Failure::new(
                "release.evidence.contradictory",
                "evidence record digest differs from manifest",
            ));
        }
    }
    Ok(EvidenceInventory {
        manifests,
        observations: observation_declarations,
    })
}

fn require_shared_oracle_source(manifests: &BTreeMap<String, Manifest>) -> Result<(), Failure> {
    let oracle_sources = manifests
        .values()
        .map(|manifest| {
            let fields = manifest.oracle.value.object()?;
            Ok(json::member(fields, "sourceSha256")?.string()?.to_owned())
        })
        .collect::<Result<BTreeSet<_>, String>>()?;
    if oracle_sources.len() != 1 {
        return Err(Failure::new(
            "release.binding.oracle",
            "platform manifests disagree on the pinned oracle source",
        ));
    }
    Ok(())
}

fn load_evidence_observations(
    evidence: &MemberSet,
    declarations: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, Vec<u8>>, Failure> {
    let mut observations = BTreeMap::new();
    for (path, expected_digest) in declarations {
        let bytes = evidence
            .files
            .get(path)
            .ok_or_else(|| "manifest-declared observation is absent".to_owned())?;
        validate_observation(bytes)?;
        let observed = digest::sha256_hex(bytes);
        if observed != *expected_digest
            || path != &format!("observations/{observed}.json")
            || observations.insert(observed, bytes.clone()).is_some()
        {
            return Err(Failure::new(
                "release.evidence.contradictory",
                "observation identity, path, or uniqueness differs",
            ));
        }
    }
    Ok(observations)
}

fn collect_evidence_records(
    input: &EvidenceVerification<'_>,
    inventory: &EvidenceInventory,
    observations: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<EvidenceTarget, EvidenceRecord>, Failure> {
    let mut records = BTreeMap::new();
    let mut record_ids = BTreeSet::new();
    let mut referenced_observations = BTreeSet::new();
    let mut exploratory_mismatches = Vec::new();
    for (platform, manifest) in &inventory.manifests {
        for member in &manifest.records {
            let path = evidence_archive_path(&member.path, "conformance-evidence", "records")?;
            let bytes = input
                .evidence
                .files
                .get(&path)
                .ok_or_else(|| "manifest evidence record is absent".to_owned())?;
            require_record_case_binding(bytes, input.conformance)
                .map_err(|message| Failure::new("release.evidence.case", message))?;
            let record = parse_record(
                bytes,
                member,
                platform,
                manifest,
                input.plan,
                input.conformance,
            )?;
            let target = (
                record.cell.clone(),
                record.obligation_id.clone(),
                record.case_id.clone(),
            );
            referenced_observations.insert(record.candidate_observation.clone());
            referenced_observations.insert(record.oracle_observation.clone());
            if !record_ids.insert(record.id.clone()) || records.insert(target, record).is_some() {
                return Err(Failure::new(
                    "release.ledger.duplicate-cell",
                    "evidence record ID or target is duplicated",
                ));
            }
            if records.len() > MAX_EVIDENCE_RECORDS {
                return Err(Failure::new(
                    "release.limit.evidence-records",
                    "evidence record count exceeds protocol limit",
                ));
            }
        }
        validate_assigned_obligations(manifest, input.conformance)?;
        let exploratory = validate_exploratory_records(
            platform,
            manifest,
            input.evidence,
            input.plan,
            input.conformance,
            observations,
        )?;
        referenced_observations.extend(exploratory.referenced_observations);
        exploratory_mismatches.extend(exploratory.mismatch_digests);
    }
    if referenced_observations != observations.keys().cloned().collect::<BTreeSet<_>>() {
        return Err(Failure::new(
            "release.evidence.unused",
            "manifest declares an observation not referenced by exact evidence",
        ));
    }
    if !exploratory_mismatches.is_empty() {
        return Err(Failure::new(
            "release.evidence.contradictory",
            format!(
                "independent exploratory replay derived {} unclassified mismatch(es)",
                exploratory_mismatches.len()
            ),
        ));
    }
    Ok(records)
}

fn verify_reconstructed_report(
    input: &EvidenceVerification<'_>,
    trusted_inputs: &TrustedInputs,
    observations: &BTreeMap<String, Vec<u8>>,
    records: &mut BTreeMap<EvidenceTarget, EvidenceRecord>,
) -> Result<ConformanceReport, Failure> {
    let report_bytes = read_bounded(
        &input.bundle.join("conformance-report.json"),
        json::MAX_JSON_BYTES,
    )?;
    let report_value = json::parse_canonical(&report_bytes)?;
    let report = ConformanceReport::parse(&report_value)
        .map_err(|message| Failure::new("release.ledger.forged-count", message))?;
    validate_report_bindings(
        &report_value,
        &report,
        input.plan,
        input.conformance,
        input.evidence_sha256,
    )?;
    let derived = reconstruct_ledger(
        input.conformance,
        records,
        observations,
        trusted_inputs,
        &input.projection.obligation_rules,
    )?;
    if !records.is_empty() {
        return Err(Failure::new(
            "release.evidence.unused",
            "unused authoritative evidence records remain",
        ));
    }
    if derived.counts.blocked_missing > report.counts.blocked_missing {
        return Err(Failure::new(
            "release.ledger.missing-cell",
            "independent reconstruction found missing authoritative evidence",
        ));
    }
    if derived.cells != report.cells.len()
        || derived.counts != report.counts
        || derived.admitted != report.admitted
    {
        return Err(Failure::new(
            "release.ledger.forged-count",
            "producer report differs from independent ledger reconstruction",
        ));
    }
    for (planned, reported) in input.conformance.cells.iter().zip(&report.cells) {
        let expected = derived
            .dispositions
            .get(&planned.key)
            .ok_or_else(|| "independent ledger lacks planned cell".to_owned())?;
        if planned.key != reported.key || expected != &reported.disposition {
            return Err(Failure::new(
                "release.ledger.forged-count",
                "reported cell disposition differs from independent reconstruction",
            ));
        }
        validate_report_exemptions(planned, reported)?;
    }
    verify_acceptance(
        input.bundle,
        input.plan,
        input.conformance,
        &report,
        input.evidence_sha256,
    )?;
    Ok(report)
}

fn validate_evidence_roots(input: &EvidenceVerification<'_>) -> Result<TrustedInputs, Failure> {
    let expected_directories = BTreeSet::from([
        "observations".to_owned(),
        "platform-manifests".to_owned(),
        "records".to_owned(),
    ]);
    if input.evidence.directories != expected_directories {
        return Err(Failure::new(
            "release.archive.extra-member",
            "evidence archive directory inventory differs",
        ));
    }
    if input
        .evidence
        .files
        .get("conformance-plan.json")
        .map(Vec::as_slice)
        != Some(input.conformance_bytes)
    {
        return Err(Failure::new(
            "release.binding.conformance-plan",
            "evidence archive conformance plan differs from trusted plan",
        ));
    }
    let source_inventory = input
        .evidence
        .files
        .get("source-inventory.json")
        .ok_or_else(|| "evidence archive lacks source inventory".to_owned())?;
    json::parse_canonical(source_inventory)?;
    if digest::sha256_hex(source_inventory) != input.plan.source_inventory_sha256 {
        return Err(Failure::new(
            "release.binding.source-inventory",
            "evidence source inventory differs from release plan",
        ));
    }
    let trusted = input
        .evidence
        .files
        .get("trusted-conformance-inputs.json")
        .ok_or_else(|| "evidence archive lacks trusted inputs".to_owned())?;
    let trusted_inputs = validate_trusted_inputs(input.projection, trusted, input.plan)?;
    let trusted_value = json::parse_canonical(trusted)?;
    let trusted_fields = trusted_value.object()?;
    let aggregate = json::member(trusted_fields, "aggregateSha256")?.string()?;
    if aggregate != input.conformance.trusted_inputs_sha256
        || aggregate != input.plan.trusted_inputs_sha256
    {
        return Err(Failure::new(
            "release.binding.trusted-inputs",
            "evidence trusted-input digest differs from conformance plan",
        ));
    }
    Ok(trusted_inputs)
}

fn require_record_case_binding(bytes: &[u8], conformance: &ConformancePlan) -> Result<(), String> {
    let value = json::parse_canonical(bytes)?;
    let fields = value.object()?;
    let cell = CellKey::parse(json::member(fields, "cellKey")?)?;
    let obligation_id = json::member(fields, "obligationId")?.string()?;
    let case_id = json::member(fields, "caseId")?.string()?;
    let descriptor = json::member(fields, "descriptorSha256")?.string()?;
    let planned = conformance
        .cells
        .iter()
        .find(|planned| planned.key == cell)
        .ok_or_else(|| "evidence record cell is outside the conformance plan".to_owned())?;
    let obligation = planned
        .obligations
        .iter()
        .find(|obligation| obligation.id == obligation_id)
        .ok_or_else(|| "evidence record obligation is outside its planned cell".to_owned())?;
    if obligation.descriptors.get(case_id).map(String::as_str) != Some(descriptor) {
        return Err("evidence record case descriptor differs from the planned case".to_owned());
    }
    Ok(())
}

fn parse_manifest(
    bytes: &[u8],
    expected_platform: &str,
    plan: &ReleasePlan,
    conformance: &ConformancePlan,
    executables: &BTreeMap<String, String>,
    trusted: &TrustedInputs,
) -> Result<Manifest, String> {
    let value = json::parse_canonical(bytes)?;
    let fields = value.object()?;
    json::exact_keys(
        fields,
        &[
            "assignedObligations",
            "candidateExecutableSha256",
            "candidateSha",
            "conformancePlanSha256",
            "exploratoryRecords",
            "manifestSha256",
            "observations",
            "oracle",
            "platform",
            "producedRecords",
            "records",
            "releasePlanSha256",
            "schemaVersion",
        ],
    )?;
    if json::member(fields, "schemaVersion")?.number()? != 1
        || json::member(fields, "platform")?.string()? != expected_platform
        || json::member(fields, "candidateSha")?.string()? != plan.candidate_sha
        || json::member(fields, "releasePlanSha256")?.string()? != plan.plan_sha256
        || json::member(fields, "conformancePlanSha256")?.string()? != conformance.plan_sha256
    {
        return Err("evidence manifest identity differs from trusted inputs".to_owned());
    }
    let stated = json::member(fields, "manifestSha256")?.string()?;
    model::require_digest(stated, "evidence manifest digest")?;
    let mut without = fields.clone();
    without.remove("manifestSha256");
    if digest::sha256_hex(&json::canonical(&Value::Object(without))?) != stated {
        return Err("evidence manifest self-digest mismatch".to_owned());
    }
    let candidate_executable_sha256 = json::member(fields, "candidateExecutableSha256")?
        .string()?
        .to_owned();
    if executables.get(expected_platform) != Some(&candidate_executable_sha256) {
        return Err("manifest executable identity differs from packaged executable".to_owned());
    }
    let records = parse_evidence_members(json::member(fields, "records")?, true, "ev-")?;
    let exploratory_records =
        parse_evidence_members(json::member(fields, "exploratoryRecords")?, true, "gx-")?;
    let observations = parse_evidence_members(json::member(fields, "observations")?, false, "")?;
    if json::member(fields, "producedRecords")?.number()?
        != u64::try_from(records.len()).map_err(|_| "record count overflow".to_owned())?
    {
        return Err("manifest produced-record count is forged".to_owned());
    }
    for members in [&records, &exploratory_records, &observations] {
        if members.windows(2).any(|pair| pair[0].path >= pair[1].path) {
            return Err("evidence manifest members are duplicated or unsorted".to_owned());
        }
    }
    let oracle = parse_oracle(json::member(fields, "oracle")?)?;
    validate_oracle_authority(&oracle, expected_platform, trusted)?;
    Ok(Manifest {
        platform: expected_platform.to_owned(),
        candidate_executable_sha256,
        oracle,
        records,
        exploratory_records,
        observations,
        assigned_obligations: json::member(fields, "assignedObligations")?.number()?,
    })
}

fn validate_manifest_authority(
    bytes: &[u8],
    expected_platform: &str,
    executables: &BTreeMap<String, String>,
    trusted: &TrustedInputs,
) -> Result<(), Failure> {
    let value = json::parse_canonical_classified(bytes)
        .map_err(|error| Failure::new(error.code, error.message))?;
    let fields = value.object()?;
    if json::member(fields, "platform")?.string()? != expected_platform {
        return Err(Failure::new(
            "release.evidence.platform",
            "evidence platform manifest is relabeled",
        ));
    }
    if executables.get(expected_platform).map(String::as_str)
        != Some(json::member(fields, "candidateExecutableSha256")?.string()?)
    {
        return Err(Failure::new(
            "release.binding.executable",
            "evidence candidate executable differs from packaged executable",
        ));
    }
    let oracle = json::member(fields, "oracle")?.object()?;
    if json::member(oracle, "repository")?.string()? != trusted.oracle_repository
        || json::member(oracle, "commit")?.string()? != trusted.oracle_commit
        || (expected_platform == "linux-x86_64"
            && json::member(oracle, "executableSha256")?.string()?
                != trusted.linux_oracle_executable_sha256)
    {
        return Err(Failure::new(
            "release.binding.oracle",
            "evidence oracle differs from trusted external inputs",
        ));
    }
    Ok(())
}

fn parse_evidence_members(
    value: &Value,
    has_id: bool,
    id_prefix: &str,
) -> Result<Vec<EvidenceMember>, String> {
    value
        .array()?
        .iter()
        .map(|value| {
            let fields = value.object()?;
            json::exact_keys(
                fields,
                if has_id {
                    &["id", "path", "sha256"]
                } else {
                    &["path", "sha256"]
                },
            )?;
            let id = if has_id {
                let id = json::member(fields, "id")?.string()?.to_owned();
                if !id.starts_with(id_prefix) {
                    return Err("evidence member ID has the wrong class".to_owned());
                }
                Some(id)
            } else {
                None
            };
            let path = json::member(fields, "path")?.string()?.to_owned();
            let sha256 = json::member(fields, "sha256")?.string()?.to_owned();
            model::require_digest(&sha256, "evidence member digest")?;
            Ok(EvidenceMember { id, path, sha256 })
        })
        .collect()
}

fn evidence_archive_path(
    path: &str,
    source_prefix: &str,
    archive_prefix: &str,
) -> Result<String, String> {
    let tail = path
        .strip_prefix(source_prefix)
        .and_then(|tail| tail.strip_prefix('/'))
        .ok_or_else(|| "evidence member path has an unknown class".to_owned())?;
    if tail.is_empty()
        || tail.contains(['/', '\\'])
        || Path::new(tail)
            .extension()
            .is_none_or(|extension| extension != "json")
        || tail.starts_with('.')
    {
        return Err("evidence member path is unsafe".to_owned());
    }
    Ok(format!("{archive_prefix}/{tail}"))
}

fn parse_oracle(value: &Value) -> Result<Oracle, String> {
    let fields = value.object()?;
    json::exact_keys(
        fields,
        &["commit", "executableSha256", "repository", "sourceSha256"],
    )?;
    model::require_sha(json::member(fields, "commit")?.string()?, "oracle commit")?;
    model::require_digest(
        json::member(fields, "executableSha256")?.string()?,
        "oracle executable digest",
    )?;
    model::require_digest(
        json::member(fields, "sourceSha256")?.string()?,
        "oracle source digest",
    )?;
    if json::member(fields, "repository")?.string()?.is_empty() {
        return Err("oracle repository is empty".to_owned());
    }
    Ok(Oracle {
        value: value.clone(),
    })
}

fn validate_oracle_authority(
    oracle: &Oracle,
    platform: &str,
    trusted: &TrustedInputs,
) -> Result<(), String> {
    let fields = oracle.value.object()?;
    if json::member(fields, "repository")?.string()? != trusted.oracle_repository
        || json::member(fields, "commit")?.string()? != trusted.oracle_commit
    {
        return Err("oracle identity differs from the external-input authority".to_owned());
    }
    if platform == "linux-x86_64"
        && json::member(fields, "executableSha256")?.string()?
            != trusted.linux_oracle_executable_sha256
    {
        return Err("Linux oracle executable differs from the external-input lock".to_owned());
    }
    Ok(())
}

fn parse_record(
    bytes: &[u8],
    member: &EvidenceMember,
    platform: &str,
    manifest: &Manifest,
    plan: &ReleasePlan,
    conformance: &ConformancePlan,
) -> Result<EvidenceRecord, String> {
    let value = json::parse_canonical(bytes)?;
    let fields = value.object()?;
    validate_record_bindings(fields, platform, manifest, plan, conformance)?;
    let source = json::member(fields, "caseSource")?.object()?;
    json::exact_keys(source, &["kind"])?;
    if json::member(source, "kind")?.string()? != "committed" {
        return Err("authoritative evidence uses a generated case".to_owned());
    }
    let cell = CellKey::parse(json::member(fields, "cellKey")?)?;
    let obligation_id = json::member(fields, "obligationId")?.string()?.to_owned();
    let case_id = json::member(fields, "caseId")?.string()?.to_owned();
    let planned_cell = conformance
        .cells
        .binary_search_by(|planned| planned.key.cmp(&cell))
        .ok()
        .and_then(|index| conformance.cells.get(index))
        .ok_or_else(|| "evidence record targets an unplanned cell".to_owned())?;
    let obligation = planned_cell
        .obligations
        .iter()
        .find(|obligation| obligation.id == obligation_id)
        .ok_or_else(|| "evidence record targets an unplanned obligation".to_owned())?;
    let platform_binding_valid = match obligation.strategy.as_str() {
        "native-oracle" | "committed-differential-corpus" | "cross-platform-relation" => {
            cell.platform == platform
        }
        "portable-static" | "structural-invariant" => platform == "linux-x86_64",
        _ => false,
    };
    if !platform_binding_valid || json::member(fields, "profile")?.string()? != cell.profile {
        return Err("evidence record repeats contradictory platform or profile".to_owned());
    }
    if obligation.descriptors.get(&case_id).map(String::as_str)
        != Some(json::member(fields, "descriptorSha256")?.string()?)
    {
        return Err("evidence record case descriptor binding differs".to_owned());
    }
    let requested_normalizers = json::member(fields, "requestedNormalizers")?
        .array()?
        .iter()
        .map(|value| Ok(value.string()?.to_owned()))
        .collect::<Result<Vec<_>, String>>()?;
    if requested_normalizers != obligation.allowed_normalizers {
        return Err("evidence record normalizer closure differs".to_owned());
    }
    let id = json::member(fields, "recordId")?.string()?.to_owned();
    let mut without = fields.clone();
    without.remove("recordId");
    let observed_id = format!(
        "ev-{}",
        digest::sha256_hex(&json::canonical(&Value::Object(without))?)
    );
    if id != observed_id || member.id.as_deref() != Some(id.as_str()) {
        return Err("evidence record content-derived ID differs".to_owned());
    }
    let candidate_observation = json::member(fields, "candidateObservationSha256")?
        .string()?
        .to_owned();
    let oracle_observation = json::member(fields, "oracleObservationSha256")?
        .string()?
        .to_owned();
    model::require_digest(&candidate_observation, "candidate observation digest")?;
    model::require_digest(&oracle_observation, "oracle observation digest")?;
    Ok(EvidenceRecord {
        id,
        cell,
        obligation_id,
        case_id,
        candidate_observation,
        oracle_observation,
        requested_normalizers,
        producer_platform: platform.to_owned(),
    })
}

fn validate_record_bindings(
    fields: &BTreeMap<String, Value>,
    platform: &str,
    manifest: &Manifest,
    plan: &ReleasePlan,
    conformance: &ConformancePlan,
) -> Result<(), String> {
    json::exact_keys(
        fields,
        &[
            "candidateBuildInfoSchemaVersion",
            "candidateCompatTracing",
            "candidateExecutableSha256",
            "candidateObservationSha256",
            "candidateSha",
            "caseId",
            "caseSource",
            "cellKey",
            "conformancePlanSha256",
            "descriptorSha256",
            "obligationId",
            "oracle",
            "oracleObservationSha256",
            "platform",
            "profile",
            "recordId",
            "releasePlanSha256",
            "requestedNormalizers",
            "schemaVersion",
            "sourceInventorySha256",
        ],
    )?;
    if json::member(fields, "schemaVersion")?.number()? != 2
        || json::member(fields, "candidateBuildInfoSchemaVersion")?.number()? != 2
        || !json::member(fields, "candidateCompatTracing")?.boolean()?
        || json::member(fields, "candidateSha")?.string()? != plan.candidate_sha
        || json::member(fields, "releasePlanSha256")?.string()? != plan.plan_sha256
        || json::member(fields, "conformancePlanSha256")?.string()? != conformance.plan_sha256
        || json::member(fields, "sourceInventorySha256")?.string()? != plan.source_inventory_sha256
        || json::member(fields, "platform")?.string()? != platform
        || json::member(fields, "candidateExecutableSha256")?.string()?
            != manifest.candidate_executable_sha256
        || json::member(fields, "oracle")? != &manifest.oracle.value
    {
        return Err("evidence record binding differs from trusted inputs".to_owned());
    }
    Ok(())
}

fn validate_assigned_obligations(
    manifest: &Manifest,
    conformance: &ConformancePlan,
) -> Result<(), String> {
    let assigned = conformance
        .cells
        .iter()
        .flat_map(|cell| {
            cell.obligations
                .iter()
                .map(move |obligation| (cell, obligation))
        })
        .filter(|(cell, obligation)| match obligation.strategy.as_str() {
            "native-oracle" | "committed-differential-corpus" => {
                cell.key.platform == manifest.platform
            }
            "portable-static" | "structural-invariant" => manifest.platform == "linux-x86_64",
            "cross-platform-relation" => cell.key.platform == manifest.platform,
            _ => false,
        })
        .count();
    if manifest.assigned_obligations
        != u64::try_from(assigned).map_err(|_| "assigned obligation count overflow".to_owned())?
    {
        return Err("manifest assigned-obligation count is forged".to_owned());
    }
    Ok(())
}

struct ExploratoryValidation {
    referenced_observations: BTreeSet<String>,
    mismatch_digests: Vec<String>,
}

fn validate_exploratory_records(
    platform: &str,
    manifest: &Manifest,
    evidence: &MemberSet,
    plan: &ReleasePlan,
    conformance: &ConformancePlan,
    observations: &BTreeMap<String, Vec<u8>>,
) -> Result<ExploratoryValidation, String> {
    let expected_count = usize::try_from(conformance.generator_count_per_platform)
        .map_err(|_| "exploratory schedule count does not fit memory".to_owned())?;
    if manifest.exploratory_records.len() != expected_count {
        return Err("exploratory evidence does not equal the exact trusted schedule".to_owned());
    }
    let mut schedule = BTreeSet::new();
    let mut referenced_observations = BTreeSet::new();
    let mut mismatch_digests = Vec::new();
    for member in &manifest.exploratory_records {
        let path = evidence_archive_path(&member.path, "conformance-evidence", "records")?;
        let bytes = evidence
            .files
            .get(&path)
            .ok_or_else(|| "exploratory evidence record is absent".to_owned())?;
        let value = json::parse_canonical(bytes)?;
        let fields = value.object()?;
        validate_exploratory_record_bindings(fields, platform, manifest, plan, conformance)?;
        let id = json::member(fields, "recordId")?.string()?;
        let mut without = fields.clone();
        without.remove("recordId");
        if id
            != format!(
                "gx-{}",
                digest::sha256_hex(&json::canonical(&Value::Object(without))?)
            )
            || member.id.as_deref() != Some(id)
        {
            return Err("exploratory record content-derived ID differs".to_owned());
        }
        let candidate_id = json::member(fields, "candidateObservationSha256")?.string()?;
        let oracle_id = json::member(fields, "oracleObservationSha256")?.string()?;
        for observation in [candidate_id, oracle_id] {
            if !observations.contains_key(observation) {
                return Err("exploratory record references a missing observation".to_owned());
            }
            referenced_observations.insert(observation.to_owned());
        }
        let generated_case_id = json::member(fields, "generatedCaseId")?.string()?;
        let index = generated_case_id
            .rsplit_once('-')
            .and_then(|(_, index)| index.parse::<usize>().ok())
            .filter(|index| *index < expected_count)
            .ok_or_else(|| "exploratory generated case ID is not reproducible".to_owned())?;
        let seed = json::member(fields, "seed")?.number()?;
        let generated = regenerate_case(seed, index)?;
        if conformance.generator_version != "typed-generator-v1"
            || json::member(fields, "generatorVersion")?.string()? != conformance.generator_version
            || seed != conformance.generator_seed
            || generated.id != generated_case_id
            || digest::sha256_hex(generated.source.as_bytes())
                != json::member(fields, "sourceSha256")?.string()?
            || generated.ast_sha256 != json::member(fields, "astSha256")?.string()?
        {
            return Err("exploratory generated case differs from trusted regeneration".to_owned());
        }
        let schedule_key = (
            generated_case_id.to_owned(),
            seed,
            json::member(fields, "sourceSha256")?.string()?.to_owned(),
            json::member(fields, "astSha256")?.string()?.to_owned(),
        );
        if !schedule.insert(schedule_key) {
            return Err("exploratory evidence schedule is duplicated".to_owned());
        }
        let candidate = observations
            .get(candidate_id)
            .ok_or_else(|| "exploratory candidate observation is missing".to_owned())?;
        let oracle = observations
            .get(oracle_id)
            .ok_or_else(|| "exploratory oracle observation is missing".to_owned())?;
        if let Verdict::Mismatch { sha256 } = compare_observations(candidate, oracle, &[])? {
            mismatch_digests.push(sha256);
        }
    }
    for index in 0..expected_count {
        let generated = regenerate_case(conformance.generator_seed, index)?;
        let key = (
            generated.id,
            conformance.generator_seed,
            digest::sha256_hex(generated.source.as_bytes()),
            generated.ast_sha256,
        );
        if !schedule.contains(&key) {
            return Err(
                "exploratory evidence schedule differs from trusted regeneration".to_owned(),
            );
        }
    }
    Ok(ExploratoryValidation {
        referenced_observations,
        mismatch_digests,
    })
}

fn validate_exploratory_record_bindings(
    fields: &BTreeMap<String, Value>,
    platform: &str,
    manifest: &Manifest,
    plan: &ReleasePlan,
    conformance: &ConformancePlan,
) -> Result<(), String> {
    json::exact_keys(
        fields,
        &[
            "astSha256",
            "candidateBuildInfoSchemaVersion",
            "candidateCompatTracing",
            "candidateExecutableSha256",
            "candidateObservationSha256",
            "candidateSha",
            "conformancePlanSha256",
            "generatedCaseId",
            "generatorVersion",
            "oracle",
            "oracleObservationSha256",
            "platform",
            "recordId",
            "releasePlanSha256",
            "schemaVersion",
            "seed",
            "sourceInventorySha256",
            "sourceSha256",
        ],
    )?;
    if json::member(fields, "schemaVersion")?.number()? != 2
        || json::member(fields, "candidateBuildInfoSchemaVersion")?.number()? != 2
        || !json::member(fields, "candidateCompatTracing")?.boolean()?
        || json::member(fields, "candidateSha")?.string()? != plan.candidate_sha
        || json::member(fields, "releasePlanSha256")?.string()? != plan.plan_sha256
        || json::member(fields, "conformancePlanSha256")?.string()? != conformance.plan_sha256
        || json::member(fields, "sourceInventorySha256")?.string()? != plan.source_inventory_sha256
        || json::member(fields, "platform")?.string()? != platform
        || json::member(fields, "candidateExecutableSha256")?.string()?
            != manifest.candidate_executable_sha256
        || json::member(fields, "oracle")? != &manifest.oracle.value
    {
        return Err("exploratory evidence binding differs".to_owned());
    }
    Ok(())
}

struct GeneratedCase {
    id: String,
    source: String,
    ast_sha256: String,
}

fn regenerate_case(seed: u64, index: usize) -> Result<GeneratedCase, String> {
    let word = split_mix(
        seed.wrapping_add(u64::try_from(index).map_err(|_| "generator index overflow".to_owned())?),
    );
    let small = word % 10_000;
    let alternative = (word >> 16) % 10_000;
    let (family, result_type, source) = match index % 10 {
        0 => (
            "int-boundary",
            "Int",
            format!("main = IO.print $ Int.plus {small} {alternative}\n"),
        ),
        1 => (
            "nested-maybe-list",
            "List(Maybe(Int))",
            format!("main = IO.print [Maybe.Just {small}, Maybe.Nothing]\n"),
        ),
        2 => (
            "either-tuple",
            "Tuple2(Either(Int, Text), Bool)",
            format!("main = IO.print ((Either.Left {small} :: Either Int Text), Bool.True)\n"),
        ),
        3 => (
            "short-circuit-unused-error",
            "Int",
            format!(
                "main = IO.print $ Bool.bool {small} (Error.error \"unused\" :: Int) Bool.False\n"
            ),
        ),
        4 => (
            "record-field",
            "Record",
            format!(
                "data GeneratedRecord = GeneratedRecord {{ value :: Int, other :: Int }}\n\nmain = IO.print $ Record.get @\"value\" @Int Main.GeneratedRecord {{ value = {small}, other = {alternative} }}\n"
            ),
        ),
        5 => (
            "variant-case",
            "Variant",
            format!(
                "data Choice = First Int | Second Text\n\nmain = case Main.First {small} of\n  First value -> IO.print value\n  Second text -> Text.putStrLn text\n"
            ),
        ),
        6 => {
            let take = word % 8 + 1;
            (
                "productive-list",
                "List(Int)",
                format!(
                    "main = IO.print $ List.take {take} $ List.iterate' (Int.plus 1) {small}\n"
                ),
            )
        }
        7 => (
            "stable-ordering",
            "List(Tuple2(Int, Text))",
            format!(
                "main = IO.print $ List.sortOn (\\(key, value) -> key) [(2, \"{small}\"), (1, \"{alternative}\"), (2, \"tail\")]\n"
            ),
        ),
        8 => (
            "text-roundtrip",
            "Text",
            format!(
                "main = Text.putStrLn $ Text.decodeUtf8 $ Text.encodeUtf8 \"generated-{small}-{alternative}\"\n"
            ),
        ),
        _ => (
            "json-object",
            "Json",
            format!(
                "main = ByteString.hPutStr IO.stdout $ Json.encode $ Json.Object $ Map.fromList [(\"n\", Json.Number {small}.0), (\"ok\", Json.Bool Bool.True)]\n"
            ),
        ),
    };
    let id = format!("generated-{family}-{index:04}");
    let ast = format!("{family}\0{result_type}\0{source}");
    Ok(GeneratedCase {
        id,
        source,
        ast_sha256: digest::sha256_hex(ast.as_bytes()),
    })
}

fn split_mix(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn validate_observation(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("observation exceeds its retained evidence limit".to_owned());
    }
    let value = json::parse_canonical(bytes)?;
    let fields = value.object()?;
    json::exact_keys(
        fields,
        &[
            "diagnostic",
            "exit",
            "filesystem",
            "mode",
            "normalizerContext",
            "rawStderr",
            "resourceAudit",
            "schemaVersion",
            "semanticTrace",
            "stderr",
            "statusSuccess",
            "stdout",
            "termination",
        ],
    )?;
    if json::member(fields, "schemaVersion")?.number()? != 4 {
        return Err("unsupported observation schema".to_owned());
    }
    let context = json::member(fields, "normalizerContext")?.object()?;
    json::exact_keys(context, &["executable", "sandbox", "script"])?;
    for field in ["executable", "sandbox", "script"] {
        let value = json::member(context, field)?.string()?;
        if value.is_empty() || value.contains('\0') {
            return Err("observation normalizer context is invalid".to_owned());
        }
    }
    for field in ["diagnostic", "filesystem", "mode", "resourceAudit"] {
        if json::member(fields, field)?.string()?.contains('\0') {
            return Err("observation structured field contains NUL".to_owned());
        }
    }
    for field in ["rawStderr", "stderr", "stdout"] {
        validate_base64(json::member(fields, field)?)?;
    }
    let exit = json::member(fields, "exit")?.object()?;
    json::exact_keys(exit, &["kind", "value"])?;
    let success = json::member(fields, "statusSuccess")?.boolean()?;
    let termination = json::member(fields, "termination")?.string()?;
    match json::member(exit, "kind")?.string()? {
        "code" => {
            let code = json::member(exit, "value")?.number()?;
            if termination != "exited" || success != (code == 0) {
                return Err("observation exit status is contradictory".to_owned());
            }
        }
        "signal" => {
            if json::member(exit, "value")?.string()?.is_empty()
                || termination != "signaled"
                || success
            {
                return Err("observation signal status is contradictory".to_owned());
            }
        }
        _ => return Err("unknown observation exit kind".to_owned()),
    }
    if json::member(fields, "semanticTrace")?.array()?.len() != 1 {
        return Err("observation must contain one semantic trace document".to_owned());
    }
    Ok(())
}

fn validate_base64(value: &Value) -> Result<(), String> {
    let fields = value.object()?;
    json::exact_keys(fields, &["encoding", "value"])?;
    if json::member(fields, "encoding")?.string()? != "base64" {
        return Err("observation byte field is not base64".to_owned());
    }
    let value = json::member(fields, "value")?.string()?.as_bytes();
    if !value.len().is_multiple_of(4) {
        return Err("observation base64 length is not canonical".to_owned());
    }
    for (index, chunk) in value.chunks_exact(4).enumerate() {
        let last = index + 1 == value.len() / 4;
        let padding = usize::from(chunk[3] == b'=') + usize::from(chunk[2] == b'=');
        if (!last && padding != 0)
            || padding > 2
            || (chunk[2] == b'=' && chunk[3] != b'=')
            || chunk[..4 - padding].iter().any(|byte| !base64_byte(*byte))
        {
            return Err("observation base64 is not canonical".to_owned());
        }
        if padding == 2 && base64_value(chunk[1])? & 0x0f != 0
            || padding == 1 && base64_value(chunk[2])? & 0x03 != 0
        {
            return Err("observation base64 has nonzero unused bits".to_owned());
        }
    }
    Ok(())
}

fn base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/')
}

fn decode_base64(value: &Value) -> Result<Vec<u8>, String> {
    validate_base64(value)?;
    let fields = value.object()?;
    let encoded = json::member(fields, "value")?.string()?.as_bytes();
    let mut output = Vec::with_capacity(encoded.len() / 4 * 3);
    for chunk in encoded.chunks_exact(4) {
        let first = base64_value(chunk[0])?;
        let second = base64_value(chunk[1])?;
        output.push((first << 2) | (second >> 4));
        if chunk[2] != b'=' {
            let third = base64_value(chunk[2])?;
            output.push((second << 4) | (third >> 2));
            if chunk[3] != b'=' {
                let fourth = base64_value(chunk[3])?;
                output.push((third << 6) | fourth);
            }
        }
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err("base64 payload contains an invalid character".to_owned()),
    }
}

fn encode_base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(TABLE[usize::from(first >> 2)]));
        output.push(char::from(
            TABLE[usize::from(((first & 3) << 4) | (second >> 4))],
        ));
        output.push(if chunk.len() > 1 {
            char::from(TABLE[usize::from(((second & 15) << 2) | (third >> 6))])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(TABLE[usize::from(third & 63)])
        } else {
            '='
        });
    }
    output
}

fn validate_obligation_semantics(
    candidate: &[u8],
    oracle: &[u8],
    cell: &CellKey,
    obligation: &str,
    trusted: &TrustedInputs,
) -> Result<(), String> {
    validate_one_semantic_observation(candidate, cell, obligation, &trusted.builtin_ids)
        .map_err(|error| format!("candidate semantic obligation is invalid: {error}"))?;
    validate_one_semantic_observation(oracle, cell, obligation, &trusted.builtin_ids)
        .map_err(|error| format!("oracle semantic obligation is invalid: {error}"))
}

pub(crate) fn validate_semantic_obligation_observation(
    bytes: &[u8],
    builtin_name: &str,
    builtin_id: u64,
    obligation: &str,
) -> Result<(), String> {
    let cell = CellKey {
        builtin: builtin_name.to_owned(),
        dimension: "pure-runtime".to_owned(),
        profile: "upstream".to_owned(),
        platform: "linux-x86_64".to_owned(),
    };
    validate_one_semantic_observation(
        bytes,
        &cell,
        obligation,
        &BTreeMap::from([(builtin_name.to_owned(), builtin_id)]),
    )
}

fn validate_one_semantic_observation(
    bytes: &[u8],
    cell: &CellKey,
    obligation: &str,
    builtin_ids: &BTreeMap<String, u64>,
) -> Result<(), String> {
    let outer = json::parse_canonical(bytes)?;
    let outer = outer.object()?;
    let trace = json::member(outer, "semanticTrace")?.array()?;
    let [trace] = trace else {
        return Err("semantic trace does not contain one document".to_owned());
    };
    let document = trace.string()?;
    if !document.ends_with('\n') {
        return Err("semantic document has no trailing LF".to_owned());
    }
    let document = json::parse(document.as_bytes())?;
    let fields = document.object()?;
    let target = *builtin_ids
        .get(&cell.builtin)
        .ok_or_else(|| "semantic cell builtin is absent from the trusted registry".to_owned())?;
    validate_semantic_document_header(fields, outer, target)?;
    let target_coverage = target_semantic_coverage(fields, target)?;
    let obligation_trace = json::member(fields, "semanticObligationTrace")?.array()?;
    let mut target_obligations = 0_u64;
    let mut sequences = BTreeSet::new();
    let mut semantic_obligations = Vec::with_capacity(obligation_trace.len());
    for event in obligation_trace {
        let event = event.object()?;
        json::exact_keys(
            event,
            &[
                "builtinId",
                "callbackInvocations",
                "comparatorInvocations",
                "instancePremises",
                "instanceTarget",
                "materializedAfter",
                "materializedBefore",
                "nestedAdapters",
                "outcome",
                "ownerTaskId",
                "parentSequence",
                "sequence",
            ],
        )?;
        let sequence = json::member(event, "sequence")?.number()?;
        if sequence == 0 || !sequences.insert(sequence) {
            return Err("semantic obligation sequence is zero or duplicated".to_owned());
        }
        if let Value::Number(parent) = json::member(event, "parentSequence")?
            && (*parent == 0 || *parent >= sequence)
        {
            return Err("semantic obligation parent does not precede its child".to_owned());
        }
        let materialized_before = json::member(event, "materializedBefore")?.number()?;
        let materialized_after = json::member(event, "materializedAfter")?.number()?;
        if materialized_after < materialized_before {
            return Err("semantic materialization moved backwards".to_owned());
        }
        let outcome = json::member(event, "outcome")?.string()?;
        if !matches!(outcome, "alias" | "error" | "io-action" | "value") {
            return Err("semantic obligation outcome is unknown".to_owned());
        }
        validate_instance_evidence(event)?;
        let callback_count = validate_callback_invocations(event)?;
        validate_comparator_invocations(event)?;
        let builtin = json::member(event, "builtinId")?.number()?;
        if builtin == target {
            target_obligations = target_obligations
                .checked_add(1)
                .ok_or_else(|| "semantic obligation count overflow".to_owned())?;
        }
        semantic_obligations.push(SemanticObligationEvent {
            builtin,
            outcome: outcome.to_owned(),
            materialized_before,
            materialized_after,
            callback_count,
        });
    }
    if target_coverage.is_empty()
        || target_obligations == 0 && obligation != "whnf-failure-boundary"
    {
        return Err("semantic document lacks causal evidence for the exact builtin".to_owned());
    }
    validate_semantic_event_order(fields)?;
    let boundaries = parse_semantic_boundaries(fields)?;
    validate_obligation_class(
        fields,
        obligation,
        &cell.builtin,
        target,
        &target_coverage,
        &boundaries,
        &semantic_obligations,
    )
}

fn target_semantic_coverage(
    fields: &BTreeMap<String, Value>,
    target: u64,
) -> Result<BTreeSet<&str>, String> {
    let mut target_coverage = BTreeSet::new();
    for event in json::member(fields, "semanticCoverage")?.array()? {
        let event = event.object()?;
        let expected = match event.len() {
            2 => &["builtinId", "kind"][..],
            3 => &["builtinId", "detail", "kind"][..],
            _ => return Err("semantic coverage event shape is invalid".to_owned()),
        };
        json::exact_keys(event, expected)?;
        if json::member(event, "builtinId")?.number()? == target {
            target_coverage.insert(json::member(event, "kind")?.string()?);
        }
    }
    Ok(target_coverage)
}

fn validate_semantic_document_header(
    fields: &BTreeMap<String, Value>,
    outer: &BTreeMap<String, Value>,
    target: u64,
) -> Result<(), String> {
    json::exact_keys(
        fields,
        &[
            "diagnostic",
            "normalizedPresentationLineEndingsSha256",
            "rawPresentationSha256",
            "resourceAuditFailures",
            "schemaVersion",
            "semanticBoundaries",
            "semanticCoverage",
            "semanticEffectTrace",
            "semanticEventOrder",
            "semanticObligationTrace",
            "semanticResourceTrace",
            "semanticTaskTrace",
            "semanticTypedResultBuiltinId",
            "semanticTypedResultHex",
            "semanticTypedResultSha256",
            "status",
            "timedOut",
        ],
    )?;
    if json::member(fields, "schemaVersion")?.number()? != 1
        || json::member(fields, "timedOut")?.boolean()?
        || json::member(fields, "resourceAuditFailures")?.number()? != 0
    {
        return Err("semantic document status or resource audit is invalid".to_owned());
    }
    let status = json::member(fields, "status")?.object()?;
    json::exact_keys(status, &["code", "success"])?;
    if json::member(status, "success")?.boolean()?
        != json::member(outer, "statusSuccess")?.boolean()?
    {
        return Err("semantic and retained process status disagree".to_owned());
    }
    validate_semantic_typed_result(fields, target)?;
    validate_raw_presentation(fields, outer)?;
    Ok(())
}

fn validate_instance_evidence(event: &BTreeMap<String, Value>) -> Result<(), String> {
    match json::member(event, "instanceTarget")? {
        Value::Null => {}
        Value::String(value) if !value.is_empty() => {}
        _ => return Err("semantic instance target is invalid".to_owned()),
    }
    let mut previous = None::<String>;
    for premise in json::member(event, "instancePremises")?.array()? {
        let premise = premise.object()?;
        json::exact_keys(premise, &["premiseCount", "target"])?;
        let target = json::member(premise, "target")?.string()?.to_owned();
        if target.is_empty()
            || json::member(premise, "premiseCount")?.number()? == 0
            || previous
                .as_ref()
                .is_some_and(|previous| previous >= &target)
        {
            return Err("semantic instance premises are invalid or unsorted".to_owned());
        }
        previous = Some(target);
    }
    Ok(())
}

fn validate_callback_invocations(event: &BTreeMap<String, Value>) -> Result<usize, String> {
    let callbacks = json::member(event, "callbackInvocations")?.array()?;
    for (index, callback) in callbacks.iter().enumerate() {
        let callback = callback.object()?;
        json::exact_keys(
            callback,
            &[
                "branch",
                "callbackArgument",
                "canonicalArgumentHex",
                "canonicalResultHex",
                "invocation",
                "outcome",
            ],
        )?;
        let expected = u64::try_from(index)
            .map_err(|_| "semantic callback count exceeds u64".to_owned())?
            .checked_add(1)
            .ok_or_else(|| "semantic callback invocation overflow".to_owned())?;
        if json::member(callback, "invocation")?.number()? != expected
            || u16::try_from(json::member(callback, "callbackArgument")?.number()?).is_err()
        {
            return Err("semantic callback identity is invalid".to_owned());
        }
        let branch = json::member(callback, "branch")?.string()?;
        if branch.is_empty()
            || !branch
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
        {
            return Err("semantic callback branch is invalid".to_owned());
        }
        for argument in json::member(callback, "canonicalArgumentHex")?.array()? {
            validate_canonical_hex_json(argument.string()?)?;
        }
        let result =
            validate_canonical_hex_json(json::member(callback, "canonicalResultHex")?.string()?)?;
        let outcome = json::member(callback, "outcome")?.string()?;
        let expected_outcome = if result
            .starts_with("{\"type\":\"ForceBoundary\",\"outcome\":\"error\",\"code\":\"")
        {
            "error"
        } else {
            "value"
        };
        if outcome != expected_outcome {
            return Err("semantic callback outcome differs from its canonical result".to_owned());
        }
    }
    Ok(callbacks.len())
}

fn validate_comparator_invocations(event: &BTreeMap<String, Value>) -> Result<(), String> {
    for (index, comparator) in json::member(event, "comparatorInvocations")?
        .array()?
        .iter()
        .enumerate()
    {
        let comparator = comparator.object()?;
        json::exact_keys(
            comparator,
            &[
                "canonicalLeftHex",
                "canonicalResultHex",
                "canonicalRightHex",
                "comparatorBuiltinId",
                "directChildOrdinal",
                "invocation",
                "outcome",
            ],
        )?;
        let expected = u64::try_from(index)
            .map_err(|_| "semantic comparator count exceeds u64".to_owned())?
            .checked_add(1)
            .ok_or_else(|| "semantic comparator invocation overflow".to_owned())?;
        if json::member(comparator, "invocation")?.number()? != expected
            || json::member(comparator, "directChildOrdinal")?.number()? == 0
        {
            return Err("semantic comparator identity is invalid".to_owned());
        }
        let left =
            validate_canonical_hex_json(json::member(comparator, "canonicalLeftHex")?.string()?)?;
        let right =
            validate_canonical_hex_json(json::member(comparator, "canonicalRightHex")?.string()?)?;
        let result =
            validate_canonical_hex_json(json::member(comparator, "canonicalResultHex")?.string()?)?;
        if left.is_empty() || right.is_empty() || result.is_empty() {
            return Err("semantic comparator canonical values are empty".to_owned());
        }
        let outcome = json::member(comparator, "outcome")?.string()?;
        if !matches!(outcome, "equal" | "greater" | "less") {
            return Err("semantic comparator outcome is unknown".to_owned());
        }
    }
    Ok(())
}

fn validate_canonical_hex_json(encoded: &str) -> Result<String, String> {
    if !encoded.len().is_multiple_of(2) {
        return Err("semantic canonical hex has odd length".to_owned());
    }
    let bytes = decode_hex(encoded)?;
    json::parse(&bytes)?;
    require_compact_json(&bytes)?;
    String::from_utf8(bytes).map_err(|_| "semantic canonical hex is not UTF-8".to_owned())
}

fn require_compact_json(bytes: &[u8]) -> Result<(), String> {
    let mut quoted = false;
    let mut escaped = false;
    for byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else if *byte == b'"' {
            quoted = true;
        } else if byte.is_ascii_whitespace() {
            return Err("semantic canonical hex contains insignificant whitespace".to_owned());
        }
    }
    Ok(())
}

fn parse_semantic_boundaries(
    fields: &BTreeMap<String, Value>,
) -> Result<Vec<SemanticBoundary>, String> {
    let values = json::member(fields, "semanticBoundaries")?.array()?;
    let mut boundaries = Vec::with_capacity(values.len());
    for value in values {
        let fields = value.object()?;
        let expected = if fields.contains_key("errorCode") {
            &["argument", "builtinId", "class", "errorCode", "outcome"][..]
        } else {
            &["argument", "builtinId", "class", "outcome"][..]
        };
        json::exact_keys(fields, expected)?;
        let class = json::member(fields, "class")?.string()?;
        if !matches!(
            class,
            "conditional-branch"
                | "conditional-force-complete"
                | "deep-force-complete"
                | "io-execution-complete"
                | "lazy-adapter-entry"
                | "whnf-force-complete"
                | "whnf-force-failed"
        ) {
            return Err("semantic boundary class is unknown".to_owned());
        }
        let outcome = json::member(fields, "outcome")?.string()?;
        let error_code = fields
            .get("errorCode")
            .map(Value::string)
            .transpose()?
            .map(str::to_owned);
        let valid_outcome = match class {
            "lazy-adapter-entry" => outcome == "not-forced" && error_code.is_none(),
            "conditional-branch" => {
                matches!(outcome, "not-forced" | "value") && error_code.is_none()
            }
            "whnf-force-failed" => {
                outcome == "error" && error_code.as_ref().is_some_and(|code| !code.is_empty())
            }
            _ => {
                matches!(outcome, "error" | "value")
                    && (outcome == "error")
                        == error_code.as_ref().is_some_and(|code| !code.is_empty())
            }
        };
        if !valid_outcome {
            return Err("semantic boundary outcome or error code is contradictory".to_owned());
        }
        boundaries.push(SemanticBoundary {
            builtin: json::member(fields, "builtinId")?.number()?,
            argument: json::member(fields, "argument")?.number()?,
            class: class.to_owned(),
            outcome: outcome.to_owned(),
            error_code,
        });
    }
    Ok(boundaries)
}

fn validate_semantic_typed_result(
    fields: &BTreeMap<String, Value>,
    target: u64,
) -> Result<(), String> {
    match (
        json::member(fields, "semanticTypedResultSha256")?,
        json::member(fields, "semanticTypedResultBuiltinId")?,
        json::member(fields, "semanticTypedResultHex")?,
    ) {
        (Value::Null, Value::Null, Value::Null) => Ok(()),
        (Value::String(stated), Value::Number(builtin), Value::String(hex)) => {
            model::require_digest(stated, "semantic typed-result digest")?;
            if *builtin != target || !hex.len().is_multiple_of(2) {
                return Err("semantic typed-result identity differs".to_owned());
            }
            let bytes = decode_hex(hex)?;
            std::str::from_utf8(&bytes)
                .map_err(|_| "semantic typed result is not UTF-8".to_owned())?;
            if digest::sha256_hex(&bytes) != *stated {
                return Err("semantic typed-result digest does not bind retained bytes".to_owned());
            }
            Ok(())
        }
        _ => Err("semantic typed-result identity is incomplete".to_owned()),
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("hex value has odd length".to_owned());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err("hex value is not canonical lowercase".to_owned()),
    }
}

fn validate_raw_presentation(
    semantic: &BTreeMap<String, Value>,
    outer: &BTreeMap<String, Value>,
) -> Result<(), String> {
    let stdout = decode_base64(json::member(outer, "stdout")?)?;
    let stderr = decode_base64(json::member(outer, "rawStderr")?)?;
    let mut framed = b"hell-runtime-presentation-v1\0".to_vec();
    for bytes in [&stdout, &stderr] {
        framed.extend_from_slice(
            &u64::try_from(bytes.len())
                .map_err(|_| "presentation length overflow".to_owned())?
                .to_be_bytes(),
        );
        framed.extend_from_slice(bytes);
    }
    let stated = json::member(semantic, "rawPresentationSha256")?.string()?;
    model::require_digest(stated, "raw presentation digest")?;
    if digest::sha256_hex(&framed) != stated {
        return Err("raw presentation digest differs from retained bytes".to_owned());
    }
    Ok(())
}

fn validate_semantic_event_order(fields: &BTreeMap<String, Value>) -> Result<(), String> {
    const KINDS: [&str; 11] = [
        "parsed-builtin",
        "resolved-builtin",
        "specialized-builtin",
        "entered-adapter",
        "forced-argument",
        "typed-result",
        "effect-event",
        "task-event",
        "presentation-field",
        "resource-event",
        "obligation-event",
    ];
    let events = json::member(fields, "semanticEventOrder")?.array()?;
    if events.is_empty() {
        return Err("semantic event order is empty".to_owned());
    }
    let mut observed = [0_usize; KINDS.len()];
    let mut causal_phase = 0_usize;
    for (index, event) in events.iter().enumerate() {
        let event = event.object()?;
        json::exact_keys(event, &["eventId", "kind"])?;
        let id = json::member(event, "eventId")?.number()?;
        let expected_id = u64::try_from(index)
            .map_err(|_| "semantic event order exceeds u64".to_owned())?
            .checked_add(1)
            .ok_or_else(|| "semantic event ID overflow".to_owned())?;
        let kind = json::member(event, "kind")?.string()?;
        let kind_index = KINDS
            .iter()
            .position(|candidate| *candidate == kind)
            .ok_or_else(|| "semantic event order contains an unknown kind".to_owned())?;
        if id != expected_id {
            return Err("semantic event IDs are not the exact sequence 1..n".to_owned());
        }
        if kind_index <= 3 {
            if kind_index != causal_phase {
                return Err("semantic causal phases are out of order".to_owned());
            }
            causal_phase = causal_phase
                .checked_add(1)
                .ok_or_else(|| "semantic causal phase overflow".to_owned())?;
        } else if causal_phase < 4 {
            return Err("semantic event precedes adapter entry".to_owned());
        }
        observed[kind_index] = observed[kind_index]
            .checked_add(1)
            .ok_or_else(|| "semantic event-kind count overflow".to_owned())?;
    }
    let mut expected = [0_usize; KINDS.len()];
    for event in json::member(fields, "semanticCoverage")?.array()? {
        let event = event.object()?;
        let kind = json::member(event, "kind")?.string()?;
        let index = match kind {
            "parsed-builtin" => 0,
            "resolved-builtin" => 1,
            "specialized-builtin" => 2,
            "entered-adapter" => 3,
            "forced-argument" => 4,
            "executed-effect" => 6,
            "task-event" => 7,
            "presented-field" => 8,
            "acquired-resource" => 9,
            _ => return Err("semantic coverage contains an unknown kind".to_owned()),
        };
        expected[index] = expected[index]
            .checked_add(1)
            .ok_or_else(|| "semantic coverage count overflow".to_owned())?;
    }
    expected[4] = json::member(fields, "semanticBoundaries")?.array()?.len();
    expected[5] = usize::from(!matches!(
        json::member(fields, "semanticTypedResultSha256")?,
        Value::Null
    ));
    expected[10] = json::member(fields, "semanticObligationTrace")?
        .array()?
        .len();
    if observed != expected {
        return Err("semantic event order does not exactly cover retained evidence".to_owned());
    }
    Ok(())
}

fn validate_obligation_class(
    fields: &BTreeMap<String, Value>,
    obligation: &str,
    builtin_name: &str,
    target: u64,
    coverage: &BTreeSet<&str>,
    boundaries: &[SemanticBoundary],
    obligation_events: &[SemanticObligationEvent],
) -> Result<(), String> {
    let effects = validate_effect_trace(fields, target)?;
    let tasks = validate_task_trace(fields, target)?;
    let resources = validate_resource_trace(fields, target)?;
    let target_events = obligation_events
        .iter()
        .filter(|event| event.builtin == target)
        .collect::<Vec<_>>();
    let entered = coverage.contains("entered-adapter");
    let success = json::member(json::member(fields, "status")?.object()?, "success")?.boolean()?;
    let valid = match obligation {
        "typed-result" => !matches!(
            json::member(fields, "semanticTypedResultSha256")?,
            Value::Null
        ),
        "effect-success" => effects.contains(&"completed"),
        "effect-failure" => effects.contains(&"failed"),
        "effect-cancellation" => effects.contains(&"cancelled"),
        "effect-ordering" => effects.len() >= 2,
        "task-lifecycle" => {
            tasks.contains(&"started")
                && tasks
                    .iter()
                    .any(|event| matches!(*event, "completed" | "failed" | "cancelled"))
        }
        "race-cancellation" => tasks.contains(&"cancelled"),
        "scope-cleanup" => tasks
            .iter()
            .any(|event| matches!(*event, "completed" | "failed" | "cancelled")),
        "resource-audit" | "cleanup-trace" => {
            resources.contains(&"acquire")
                && resources
                    .iter()
                    .any(|event| matches!(*event, "close" | "cancel" | "cleanup-failure"))
        }
        "callback-order" => target_events.iter().any(|event| event.callback_count != 0),
        "raw-observation" | "normalized-shadow-diff" | "three-platform-observation" => {
            coverage.contains("presented-field")
        }
        "bounded-materialization" => {
            let materialized = if matches!(builtin_name, "Map.singleton" | "Set.singleton") {
                target_events
                    .iter()
                    .any(|event| event.materialized_before == 0 && event.materialized_after == 0)
            } else {
                target_events
                    .iter()
                    .any(|event| event.materialized_after >= event.materialized_before)
            };
            success && entered && materialized
        }
        "adapter-success" => entered && target_events.iter().any(|event| event.outcome != "error"),
        "adapter-failure" => {
            !success
                && entered
                && (effects.contains(&"failed")
                    || target_events.iter().any(|event| event.outcome == "error"))
        }
        "result-force-failure" => {
            !success
                && entered
                && typed_result_is_force_error(fields, target)?
                && target_events.len() == 1
                && target_events[0].outcome == "alias"
        }
        "lazy-boundary" => exact_lazy_boundaries(target, boundaries, target_events.len()),
        "whnf-boundary" => exact_completed_boundaries(target, boundaries, "whnf-force-complete"),
        "whnf-failure-boundary" => {
            !success
                && !entered
                && target_events.is_empty()
                && exact_failed_whnf_boundary(target, boundaries)
        }
        "deep-boundary" => exact_completed_boundaries(target, boundaries, "deep-force-complete"),
        "conditional-selected" | "conditional-unselected" => {
            exact_conditional_boundaries(target, boundaries)
        }
        "io-execution-boundary" => {
            effects.contains(&"started")
                && exact_completed_boundaries(target, boundaries, "io-execution-complete")
        }
        "collection-interaction"
        | "constructor-eliminator"
        | "numeric-boundary"
        | "parser-composition" => success && entered && !target_events.is_empty(),
        "encoding-boundary" => entered && !target_events.is_empty(),
        _ => return Err(format!("unknown semantic obligation {obligation:?}")),
    };
    if !valid {
        return Err(format!(
            "semantic document does not satisfy obligation {obligation:?}"
        ));
    }
    Ok(())
}

fn typed_result_is_force_error(
    fields: &BTreeMap<String, Value>,
    target: u64,
) -> Result<bool, String> {
    if json::member(fields, "semanticTypedResultBuiltinId")? != &Value::Number(target) {
        return Ok(false);
    }
    let Value::String(encoded) = json::member(fields, "semanticTypedResultHex")? else {
        return Ok(false);
    };
    let canonical = validate_canonical_hex_json(encoded)?;
    Ok(canonical.starts_with(concat!(
        "{\"type\":\"TypedResult\",\"argument\":0,",
        "\"boundary\":\"adapter-result\",\"value\":",
        "{\"type\":\"ForceBoundary\",\"outcome\":\"error\",\"code\":\""
    )))
}

fn exact_lazy_boundaries(
    target: u64,
    boundaries: &[SemanticBoundary],
    invocation_count: usize,
) -> bool {
    let matching = boundaries
        .iter()
        .filter(|boundary| boundary.builtin == target && boundary.class == "lazy-adapter-entry")
        .collect::<Vec<_>>();
    let arguments = matching
        .iter()
        .map(|boundary| boundary.argument)
        .collect::<BTreeSet<_>>();
    invocation_count != 0
        && !arguments.is_empty()
        && matching.len() == arguments.len().saturating_mul(invocation_count)
        && arguments.iter().all(|argument| {
            matching
                .iter()
                .filter(|boundary| boundary.argument == *argument)
                .count()
                == invocation_count
        })
        && matching
            .iter()
            .all(|boundary| boundary.outcome == "not-forced" && boundary.error_code.is_none())
}

fn exact_completed_boundaries(target: u64, boundaries: &[SemanticBoundary], class: &str) -> bool {
    let matching = boundaries
        .iter()
        .filter(|boundary| boundary.builtin == target && boundary.class == class)
        .collect::<Vec<_>>();
    let arguments = matching
        .iter()
        .map(|boundary| boundary.argument)
        .collect::<BTreeSet<_>>();
    !matching.is_empty()
        && matching.len() == arguments.len()
        && matching
            .iter()
            .all(|boundary| matches!(boundary.outcome.as_str(), "error" | "value"))
}

fn exact_failed_whnf_boundary(target: u64, boundaries: &[SemanticBoundary]) -> bool {
    let matching = boundaries
        .iter()
        .filter(|boundary| boundary.builtin == target && boundary.class == "whnf-force-failed")
        .collect::<Vec<_>>();
    matching.len() == 1
        && matching[0].outcome == "error"
        && matching[0]
            .error_code
            .as_ref()
            .is_some_and(|code| !code.is_empty())
}

fn exact_conditional_boundaries(target: u64, boundaries: &[SemanticBoundary]) -> bool {
    let matching = boundaries
        .iter()
        .filter(|boundary| boundary.builtin == target && boundary.class == "conditional-branch")
        .collect::<Vec<_>>();
    let arguments = matching
        .iter()
        .map(|boundary| boundary.argument)
        .collect::<BTreeSet<_>>();
    matching.len() == 2
        && arguments.len() == 2
        && matching
            .iter()
            .filter(|boundary| boundary.outcome == "value")
            .count()
            == 1
        && matching
            .iter()
            .filter(|boundary| boundary.outcome == "not-forced")
            .count()
            == 1
}

fn validate_effect_trace(
    fields: &BTreeMap<String, Value>,
    target: u64,
) -> Result<Vec<&str>, String> {
    let mut target_events = Vec::new();
    let mut sequences = BTreeSet::new();
    for value in json::member(fields, "semanticEffectTrace")?.array()? {
        let event = value.object()?;
        json::exact_keys(
            event,
            &[
                "builtinId",
                "effect",
                "ownerTaskId",
                "parentSequence",
                "sequence",
            ],
        )?;
        let sequence = json::member(event, "sequence")?.number()?;
        if sequence == 0 || !sequences.insert(sequence) {
            return Err("semantic effect sequence is zero or duplicated".to_owned());
        }
        if let Value::Number(parent) = json::member(event, "parentSequence")?
            && (*parent == 0 || *parent >= sequence)
        {
            return Err("semantic effect parent does not precede its child".to_owned());
        }
        if !matches!(
            json::member(event, "ownerTaskId")?,
            Value::Null | Value::Number(1..)
        ) {
            return Err("semantic effect owner task is invalid".to_owned());
        }
        let lifecycle = json::member(event, "effect")?.string()?;
        if !matches!(lifecycle, "started" | "completed" | "failed" | "cancelled") {
            return Err("semantic effect lifecycle is unknown".to_owned());
        }
        if json::member(event, "builtinId")?.number()? == target {
            target_events.push(lifecycle);
        }
    }
    Ok(target_events)
}

fn validate_task_trace(fields: &BTreeMap<String, Value>, target: u64) -> Result<Vec<&str>, String> {
    let mut lifecycle_by_task = BTreeMap::<u64, Vec<&str>>::new();
    let mut target_events = Vec::new();
    for value in json::member(fields, "semanticTaskTrace")?.array()? {
        let event = value.object()?;
        json::exact_keys(event, &["builtinId", "event", "taskId"])?;
        let task = json::member(event, "taskId")?.number()?;
        if task == 0 {
            return Err("semantic task ID is zero".to_owned());
        }
        let lifecycle = json::member(event, "event")?.string()?;
        if !matches!(lifecycle, "started" | "completed" | "failed" | "cancelled") {
            return Err("semantic task lifecycle is unknown".to_owned());
        }
        lifecycle_by_task.entry(task).or_default().push(lifecycle);
        if json::member(event, "builtinId")?.number()? == target {
            target_events.push(lifecycle);
        }
    }
    for lifecycle in lifecycle_by_task.values() {
        if lifecycle.first() != Some(&"started")
            || lifecycle
                .iter()
                .filter(|event| matches!(**event, "completed" | "failed" | "cancelled"))
                .count()
                != 1
        {
            return Err("semantic task lifecycle is incomplete or duplicated".to_owned());
        }
    }
    Ok(target_events)
}

fn validate_resource_trace(
    fields: &BTreeMap<String, Value>,
    target: u64,
) -> Result<Vec<&str>, String> {
    let mut lifecycle_by_resource = BTreeMap::<u64, Vec<&str>>::new();
    let mut target_events = Vec::new();
    for value in json::member(fields, "semanticResourceTrace")?.array()? {
        let event = value.object()?;
        json::exact_keys(event, &["builtinId", "event", "ownerTaskId", "resourceId"])?;
        let resource = json::member(event, "resourceId")?.number()?;
        if resource == 0
            || !matches!(
                json::member(event, "ownerTaskId")?,
                Value::Null | Value::Number(1..)
            )
        {
            return Err("semantic resource identity or owner is invalid".to_owned());
        }
        let lifecycle = json::member(event, "event")?.string()?;
        if !matches!(
            lifecycle,
            "acquire" | "transfer" | "cancel" | "close" | "cleanup-failure"
        ) {
            return Err("semantic resource lifecycle is unknown".to_owned());
        }
        lifecycle_by_resource
            .entry(resource)
            .or_default()
            .push(lifecycle);
        if json::member(event, "builtinId")?.number()? == target {
            target_events.push(lifecycle);
        }
    }
    for lifecycle in lifecycle_by_resource.values() {
        if lifecycle.first() != Some(&"acquire")
            || lifecycle
                .iter()
                .filter(|event| matches!(**event, "cancel" | "close" | "cleanup-failure"))
                .count()
                != 1
        {
            return Err("semantic resource lifecycle is incomplete or duplicated".to_owned());
        }
    }
    Ok(target_events)
}

struct DerivedLedger {
    dispositions: BTreeMap<CellKey, Value>,
    counts: Counts,
    cells: usize,
    admitted: bool,
}

enum Verdict {
    Verified {
        mode: &'static str,
        evidence_ids: Vec<String>,
    },
    Missing,
    Mismatch {
        sha256: String,
    },
}

fn reconstruct_ledger(
    conformance: &ConformancePlan,
    records: &mut BTreeMap<EvidenceTarget, EvidenceRecord>,
    observations: &BTreeMap<String, Vec<u8>>,
    trusted: &TrustedInputs,
    obligation_rules: &ObligationRules,
) -> Result<DerivedLedger, String> {
    let mut dispositions = BTreeMap::new();
    let mut counts = Counts::default();
    let mut used_exemptions = BTreeSet::new();
    for cell in &conformance.cells {
        let disposition = match &cell.scope {
            Scope::NotApplicable => {
                counts.not_applicable = checked_increment(counts.not_applicable)?;
                json::object([
                    ("decisionId", json::string(&cell.decision_id)),
                    ("kind", json::string("not-applicable")),
                ])
            }
            Scope::Excluded => {
                counts.excluded = checked_increment(counts.excluded)?;
                json::object([
                    ("kind", json::string("excluded")),
                    ("scopeId", json::string(&cell.decision_id)),
                ])
            }
            Scope::Required => derive_required_cell(
                cell,
                records,
                observations,
                trusted,
                &mut used_exemptions,
                &mut counts,
            )?,
        };
        obligation_rules.require_cell(cell, &disposition, &conformance.evaluation_instant)?;
        if dispositions.insert(cell.key.clone(), disposition).is_some() {
            return Err("independent ledger produced a duplicate cell".to_owned());
        }
    }
    let expected_exemptions = conformance
        .cells
        .iter()
        .filter_map(|cell| {
            cell.exemption
                .as_ref()
                .map(|exemption| exemption.id.clone())
        })
        .collect::<BTreeSet<_>>();
    if used_exemptions != expected_exemptions {
        return Err("independent ledger contains an unused exemption".to_owned());
    }
    let admitted = counts.blocked()? == 0;
    Ok(DerivedLedger {
        dispositions,
        counts,
        cells: conformance.cells.len(),
        admitted,
    })
}

fn derive_required_cell(
    cell: &PlannedCell,
    records: &mut BTreeMap<EvidenceTarget, EvidenceRecord>,
    observations: &BTreeMap<String, Vec<u8>>,
    trusted: &TrustedInputs,
    used_exemptions: &mut BTreeSet<String>,
    counts: &mut Counts,
) -> Result<Value, String> {
    let verdicts = derive_obligation_verdicts(cell, records, observations, trusted)?;
    let failures = verdicts
        .iter()
        .filter(|(_, verdict)| !matches!(verdict, Verdict::Verified { .. }))
        .collect::<Vec<_>>();
    if failures.is_empty() {
        if cell.exemption.is_some() {
            return Err("verified cell has an unused exemption".to_owned());
        }
        return verified_cell_disposition(verdicts, counts);
    }
    if failures.len() == 1 {
        let (obligation_id, verdict) = failures[0];
        if let Some(exemption) = cell.exemption.as_ref().filter(|exemption| {
            exemption.obligation_id == **obligation_id
                && match verdict {
                    Verdict::Missing => exemption.kind == "evidence-gap",
                    Verdict::Mismatch { sha256 } => {
                        exemption.kind == "known-divergence"
                            && exemption.expected_mismatch_sha256.as_ref() == Some(sha256)
                    }
                    Verdict::Verified { .. } => false,
                }
        }) {
            if !used_exemptions.insert(exemption.id.clone()) {
                return Err("exemption was consumed more than once".to_owned());
            }
            counts.exempted = checked_increment(counts.exempted)?;
            return Ok(json::object([
                ("exemptionId", json::string(&exemption.id)),
                ("kind", json::string("exempted")),
                (
                    "underlying",
                    json::string(match verdict {
                        Verdict::Missing => "missing-evidence",
                        Verdict::Mismatch { .. } => "mismatch",
                        Verdict::Verified { .. } => {
                            return Err("verified evidence cannot be exempted".to_owned());
                        }
                    }),
                ),
            ]));
        }
    }
    blocked_cell_disposition(&failures, counts)
}

fn derive_obligation_verdicts<'a>(
    cell: &'a PlannedCell,
    records: &mut BTreeMap<EvidenceTarget, EvidenceRecord>,
    observations: &BTreeMap<String, Vec<u8>>,
    trusted: &TrustedInputs,
) -> Result<Vec<(&'a str, Verdict)>, String> {
    let mut verdicts = Vec::new();
    for obligation in &cell.obligations {
        let mut ids = Vec::new();
        let mut mode = "verified-exact";
        let mut missing = false;
        let mut mismatch = None;
        for case_id in &obligation.case_ids {
            let target = (cell.key.clone(), obligation.id.clone(), case_id.clone());
            let Some(record) = records.remove(&target) else {
                missing = true;
                continue;
            };
            let candidate = observations
                .get(&record.candidate_observation)
                .ok_or_else(|| "record candidate observation is absent".to_owned())?;
            let oracle = observations
                .get(&record.oracle_observation)
                .ok_or_else(|| "record oracle observation is absent".to_owned())?;
            validate_obligation_semantics(candidate, oracle, &cell.key, &obligation.id, trusted)?;
            match compare_observations(candidate, oracle, &record.requested_normalizers)? {
                Verdict::Verified {
                    mode: observed_mode,
                    ..
                } => {
                    let strategy_mode = match obligation.strategy.as_str() {
                        "native-oracle" | "committed-differential-corpus" => observed_mode,
                        "portable-static" | "structural-invariant" => {
                            if record.producer_platform != "linux-x86_64" {
                                return Err(
                                    "portable evidence did not originate on Linux".to_owned()
                                );
                            }
                            "verified-platform-equivalent"
                        }
                        "cross-platform-relation" => "verified-platform-equivalent",
                        _ => return Err("unknown obligation strategy during reduction".to_owned()),
                    };
                    if matches!(
                        strategy_mode,
                        "verified-normalized" | "verified-platform-equivalent"
                    ) {
                        mode = strongest_verification_mode(mode, strategy_mode)?;
                    }
                }
                Verdict::Mismatch { sha256 } => {
                    mismatch.get_or_insert(sha256);
                }
                Verdict::Missing => {
                    return Err("observation comparison returned missing".to_owned());
                }
            }
            ids.push(record.id);
        }
        let verdict = if let Some(sha256) = mismatch {
            Verdict::Mismatch { sha256 }
        } else if missing {
            Verdict::Missing
        } else {
            Verdict::Verified {
                mode,
                evidence_ids: ids,
            }
        };
        verdicts.push((obligation.id.as_str(), verdict));
    }
    Ok(verdicts)
}

fn verified_cell_disposition(
    verdicts: Vec<(&str, Verdict)>,
    counts: &mut Counts,
) -> Result<Value, String> {
    let mut mode = "verified-exact";
    let mut ids = Vec::new();
    for (_, verdict) in verdicts {
        let Verdict::Verified {
            mode: observed_mode,
            evidence_ids,
        } = verdict
        else {
            return Err("verified reduction contains a failure".to_owned());
        };
        mode = strongest_verification_mode(mode, observed_mode)?;
        ids.extend(evidence_ids);
    }
    match mode {
        "verified-exact" => counts.verified_exact = checked_increment(counts.verified_exact)?,
        "verified-normalized" => {
            counts.verified_normalized = checked_increment(counts.verified_normalized)?;
        }
        "verified-platform-equivalent" => {
            counts.verified_platform_equivalent =
                checked_increment(counts.verified_platform_equivalent)?;
        }
        _ => return Err("independent verifier derived an unknown mode".to_owned()),
    }
    Ok(json::object([
        (
            "evidenceIds",
            Value::Array(ids.iter().map(|id| json::string(id)).collect()),
        ),
        ("kind", json::string(mode)),
    ]))
}

fn blocked_cell_disposition(
    failures: &[&(&str, Verdict)],
    counts: &mut Counts,
) -> Result<Value, String> {
    let (obligation_id, failure) = failures
        .iter()
        .find(|(_, verdict)| matches!(verdict, Verdict::Mismatch { .. }))
        .copied()
        .unwrap_or(failures[0]);
    match failure {
        Verdict::Missing => {
            counts.blocked_missing = checked_increment(counts.blocked_missing)?;
            Ok(json::object([
                (
                    "blocker",
                    json::object([
                        ("kind", json::string("missing-evidence")),
                        ("obligationId", json::string(obligation_id)),
                    ]),
                ),
                ("kind", json::string("blocked")),
            ]))
        }
        Verdict::Mismatch { sha256 } => {
            counts.blocked_mismatch = checked_increment(counts.blocked_mismatch)?;
            Ok(json::object([
                (
                    "blocker",
                    json::object([
                        ("kind", json::string("mismatch")),
                        ("mismatchSha256", json::string(sha256)),
                        ("obligationId", json::string(obligation_id)),
                    ]),
                ),
                ("kind", json::string("blocked")),
            ]))
        }
        Verdict::Verified { .. } => Err("failure reduction selected verified evidence".to_owned()),
    }
}

fn strongest_verification_mode(
    left: &'static str,
    right: &'static str,
) -> Result<&'static str, String> {
    match (left, right) {
        ("verified-platform-equivalent", _) | (_, "verified-platform-equivalent") => {
            Ok("verified-platform-equivalent")
        }
        ("verified-normalized", _) | (_, "verified-normalized") => Ok("verified-normalized"),
        ("verified-exact", "verified-exact") => Ok("verified-exact"),
        _ => Err("unknown verification mode".to_owned()),
    }
}

fn compare_observations(
    candidate: &[u8],
    oracle: &[u8],
    normalizers: &[String],
) -> Result<Verdict, String> {
    if candidate == oracle {
        return Ok(Verdict::Verified {
            mode: "verified-exact",
            evidence_ids: Vec::new(),
        });
    }
    if !normalizers.is_empty() {
        let candidate = normalized_observation(candidate, normalizers)?;
        let oracle = normalized_observation(oracle, normalizers)?;
        if candidate == oracle {
            return Ok(Verdict::Verified {
                mode: "verified-normalized",
                evidence_ids: Vec::new(),
            });
        }
    }
    let mut framed = Vec::new();
    for bytes in [candidate, oracle] {
        framed.extend_from_slice(
            &u64::try_from(bytes.len())
                .map_err(|_| "observation length does not fit digest frame".to_owned())?
                .to_be_bytes(),
        );
        framed.extend_from_slice(bytes);
    }
    Ok(Verdict::Mismatch {
        sha256: digest::sha256_hex(&framed),
    })
}

fn normalized_observation(bytes: &[u8], normalizers: &[String]) -> Result<Vec<u8>, String> {
    let value = json::parse_canonical(bytes)?;
    let mut fields = value.object()?.clone();
    let context = json::member(&fields, "normalizerContext")?.object()?;
    let executable = json::member(context, "executable")?.string()?.as_bytes();
    let script = json::member(context, "script")?.string()?.as_bytes();
    let raw = decode_base64(json::member(&fields, "rawStderr")?)?;
    let retained = decode_base64(json::member(&fields, "stderr")?)?;
    let program = Path::new(
        std::str::from_utf8(executable)
            .map_err(|_| "normalizer executable path is not UTF-8".to_owned())?,
    )
    .file_name()
    .and_then(std::ffi::OsStr::to_str)
    .unwrap_or_default()
    .as_bytes();
    let mut replayed = raw;
    for normalizer in normalizers {
        let first = match normalizer.as_str() {
            "diagnostic-sandbox-path-v1" => scrub_diagnostic_paths(&replayed, script, program),
            "diagnostic-path-separator-v1" => normalize_path_separators(&replayed),
            _ => return Err("observation requests an unauthorized normalizer".to_owned()),
        };
        let second = match normalizer.as_str() {
            "diagnostic-sandbox-path-v1" => scrub_diagnostic_paths(&first, script, program),
            "diagnostic-path-separator-v1" => normalize_path_separators(&first),
            _ => return Err("observation requests an unauthorized normalizer".to_owned()),
        };
        if first != second {
            return Err("observation normalizer replay is not idempotent".to_owned());
        }
        replayed = first;
    }
    if replayed != retained {
        return Err("retained stderr differs from independent normalizer replay".to_owned());
    }
    fields.remove("normalizerContext");
    fields.remove("rawStderr");
    fields.insert(
        "stderr".to_owned(),
        json::object([
            ("encoding", json::string("base64")),
            ("value", json::string(&encode_base64(&replayed))),
        ]),
    );
    json::canonical(&Value::Object(fields))
}

fn scrub_diagnostic_paths(stderr: &[u8], script: &[u8], program: &[u8]) -> Vec<u8> {
    let marker: &[u8] = if script.contains(&b'\\') {
        b"<SANDBOX>\\main.hell"
    } else {
        b"<SANDBOX>/main.hell"
    };
    let mut quoted_script = b"SrcSpan \"".to_vec();
    quoted_script.extend(haskell_show_path(script));
    quoted_script.push(b'"');
    let mut quoted_marker = b"SrcSpan \"".to_vec();
    quoted_marker.extend_from_slice(marker);
    quoted_marker.push(b'"');
    let scrubbed = replace_bytes(stderr, &quoted_script, &quoted_marker);
    let mut output = Vec::with_capacity(scrubbed.len());
    let mut parse_frame = 0_u8;
    for line in scrubbed.split_inclusive(|byte| *byte == b'\n') {
        if let Some((prefix, suffix)) = diagnostic_path(line, script, program) {
            output.extend_from_slice(prefix);
            output.extend_from_slice(marker);
            output.extend_from_slice(suffix);
            parse_frame = 0;
        } else if parse_frame == 2
            && let Some((prefix, suffix)) = separate_parse_path(line, script)
        {
            output.extend_from_slice(prefix);
            output.extend_from_slice(marker);
            output.extend_from_slice(suffix);
            parse_frame = 0;
        } else {
            output.extend_from_slice(line);
            parse_frame = if oracle_exception_frame(line, program) {
                1
            } else if parse_frame == 1 && matches!(line, b"\n" | b"\r\n") {
                2
            } else {
                0
            };
        }
    }
    output
}

fn diagnostic_path<'a>(
    line: &'a [u8],
    script: &[u8],
    program: &[u8],
) -> Option<(&'a [u8], &'a [u8])> {
    const HELPER: &[u8] = b"unknown helper subcommand ";
    const ORACLE: &[u8] = b": Parse error: ";
    if let Some(suffix) = line
        .strip_prefix(script)
        .filter(|suffix| path_suffix(suffix))
    {
        return Some((&line[..0], suffix));
    }
    if let Some(suffix) = line
        .strip_prefix(HELPER)
        .and_then(|line| line.strip_prefix(script))
        .filter(|suffix| path_suffix(suffix))
    {
        return Some((&line[..HELPER.len()], suffix));
    }
    if !program.is_empty()
        && let Some(suffix) = line
            .strip_prefix(program)
            .and_then(|line| line.strip_prefix(ORACLE))
            .and_then(|line| line.strip_prefix(script))
            .filter(|suffix| path_suffix(suffix))
    {
        return Some((&line[..program.len() + ORACLE.len()], suffix));
    }
    None
}

fn separate_parse_path<'a>(line: &'a [u8], script: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    const PREFIX: &[u8] = b"Parse error: ";
    line.strip_prefix(PREFIX)
        .and_then(|line| line.strip_prefix(script))
        .filter(|suffix| path_suffix(suffix))
        .map(|suffix| (&line[..PREFIX.len()], suffix))
}

fn oracle_exception_frame(line: &[u8], program: &[u8]) -> bool {
    const SUFFIX: &[u8] = b": Uncaught exception ghc-internal:GHC.Internal.Exception.ErrorCall:";
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    !program.is_empty() && line.strip_prefix(program) == Some(SUFFIX)
}

fn path_suffix(suffix: &[u8]) -> bool {
    suffix.is_empty() || suffix.first() == Some(&b':')
}

fn haskell_show_path(path: &[u8]) -> Vec<u8> {
    let mut escaped = Vec::with_capacity(path.len());
    for byte in path {
        if *byte == b'\\' {
            escaped.push(b'\\');
        }
        escaped.push(*byte);
    }
    escaped
}

fn normalize_path_separators(input: &[u8]) -> Vec<u8> {
    replace_bytes(input, b"<SANDBOX>\\main.hell", b"<SANDBOX>/main.hell")
}

fn replace_bytes(input: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    if from.is_empty() {
        return input.to_vec();
    }
    let mut output = Vec::with_capacity(input.len());
    let mut offset = 0;
    while let Some(relative) = input[offset..]
        .windows(from.len())
        .position(|window| window == from)
    {
        let found = offset + relative;
        output.extend_from_slice(&input[offset..found]);
        output.extend_from_slice(to);
        offset = found + from.len();
    }
    output.extend_from_slice(&input[offset..]);
    output
}

fn checked_increment(value: u64) -> Result<u64, String> {
    value
        .checked_add(1)
        .ok_or_else(|| "partition count overflow".to_owned())
}

fn validate_report_bindings(
    value: &Value,
    report: &ConformanceReport,
    plan: &ReleasePlan,
    conformance: &ConformancePlan,
    evidence_sha256: &str,
) -> Result<(), String> {
    let fields = value.object()?;
    if json::member(fields, "candidateSha")?.string()? != plan.candidate_sha
        || json::member(fields, "conformancePlanSha256")?.string()? != conformance.plan_sha256
        || json::member(fields, "evidenceArchiveSha256")?.string()? != evidence_sha256
        || json::member(fields, "standard")?.string()? != conformance.standard
        || json::member(fields, "trustedInputsSha256")?.string()?
            != conformance.trusted_inputs_sha256
        || report.cells.len() != conformance.cells.len()
    {
        return Err("conformance report binding differs from trusted inputs".to_owned());
    }
    Ok(())
}

fn validate_report_exemptions(
    planned: &PlannedCell,
    reported: &crate::model::ReportCell,
) -> Result<(), String> {
    match &planned.exemption {
        Some(exemption)
            if reported.disposition.object().ok().and_then(|fields| {
                json::member(fields, "kind")
                    .ok()
                    .and_then(|value| value.string().ok())
            }) == Some("exempted") =>
        {
            let [value] = reported.exemptions.as_slice() else {
                return Err("exempted report cell lacks exact metadata".to_owned());
            };
            let fields = value.object()?;
            json::exact_keys(
                fields,
                &[
                    "expiresOn",
                    "id",
                    "issue",
                    "obligationId",
                    "rationale",
                    "reviewGroup",
                ],
            )?;
            if json::member(fields, "expiresOn")?.string()? != exemption.expires_on
                || json::member(fields, "id")?.string()? != exemption.id
                || json::member(fields, "issue")?.string()? != exemption.issue
                || json::member(fields, "obligationId")?.string()? != exemption.obligation_id
                || json::member(fields, "rationale")?.string()? != exemption.rationale
                || json::member(fields, "reviewGroup")?.string()? != exemption.review_group
            {
                return Err("reported exemption metadata differs from plan".to_owned());
            }
        }
        _ if !reported.exemptions.is_empty() => {
            return Err("non-exempted report cell carries exemption metadata".to_owned());
        }
        _ => {}
    }
    Ok(())
}

fn verify_acceptance(
    bundle: &Path,
    plan: &ReleasePlan,
    conformance: &ConformancePlan,
    report: &ConformanceReport,
    evidence_sha256: &str,
) -> Result<(), String> {
    let bytes = read_bounded(
        &bundle.join("conformance-acceptance.json"),
        json::MAX_JSON_BYTES,
    )?;
    let value = json::parse_canonical(&bytes)?;
    let fields = value.object()?;
    json::exact_keys(
        fields,
        &[
            "admitted",
            "candidateSha",
            "conformancePlanSha256",
            "decisionSha256",
            "evidenceArchiveSha256",
            "partition",
            "reportSha256",
            "schemaVersion",
            "standard",
            "unclassifiedMismatchCount",
        ],
    )?;
    if json::member(fields, "schemaVersion")?.number()? != 1 {
        return Err("unsupported conformance acceptance schema".to_owned());
    }
    let stated = json::member(fields, "decisionSha256")?.string()?;
    let mut without = fields.clone();
    without.remove("decisionSha256");
    if digest::sha256_hex(&json::canonical(&Value::Object(without))?) != stated {
        return Err("conformance acceptance self-digest mismatch".to_owned());
    }
    let counts = Counts::parse(json::member(fields, "partition")?)?;
    if counts != report.counts
        || json::member(fields, "admitted")?.boolean()? != report.admitted
        || json::member(fields, "candidateSha")?.string()? != plan.candidate_sha
        || json::member(fields, "conformancePlanSha256")?.string()? != conformance.plan_sha256
        || json::member(fields, "evidenceArchiveSha256")?.string()? != evidence_sha256
        || json::member(fields, "reportSha256")?.string()? != report.report_sha256
        || json::member(fields, "standard")?.string()? != conformance.standard
        || json::member(fields, "unclassifiedMismatchCount")?.number()? != 0
    {
        return Err("producer acceptance differs from independent reconstruction".to_owned());
    }
    Ok(())
}

fn verify_release_gate(
    bundle: &Path,
    plan: &ReleasePlan,
    conformance: &ConformancePlan,
    report: &ConformanceReport,
    subjects_bytes: &[u8],
    evidence_sha256: &str,
    native_environment_set_sha256: &str,
) -> Result<String, Failure> {
    let bytes = read_bounded(&bundle.join("release-gate.json"), json::MAX_JSON_BYTES)?;
    let value = validate_release_gate_document(&bytes)
        .map_err(|message| Failure::new("release.binding.subject-manifest", message))?;
    let fields = value.object()?;
    let stated = json::member(fields, "releaseGateSha256")?
        .string()?
        .to_owned();
    let acceptance = json::parse_canonical(&read_bounded(
        &bundle.join("conformance-acceptance.json"),
        json::MAX_JSON_BYTES,
    )?)?;
    let acceptance_sha = json::member(acceptance.object()?, "decisionSha256")?.string()?;
    let gate_counts = gate_counts(&report.counts);
    if json::member(fields, "governanceProfileSha256")?.string()? != plan.governance_profile_sha256
    {
        return Err(Failure::new(
            "release.binding.governance-profile",
            "release gate governance profile differs from the release plan",
        ));
    }
    if json::member(fields, "nativeEnvironmentSetSha256")?.string()?
        != native_environment_set_sha256
    {
        return Err(Failure::new(
            "release.binding.native-environment",
            "release gate native environment set differs from the verified subject",
        ));
    }
    if json::member(fields, "state")?.string()? != "admitted"
        || json::member(fields, "repository")?.string()? != plan.repository
        || json::member(fields, "candidateSha")?.string()? != plan.candidate_sha
        || json::member(fields, "workflowSha")?.string()? != plan.workflow_sha
        || json::member(fields, "version")?.string()? != plan.version
        || json::member(fields, "tag")?.string()? != plan.tag
        || json::member(fields, "releasePlanSha256")?.string()? != plan.plan_sha256
        || json::member(fields, "conformanceStandard")?.string()? != conformance.standard
        || json::member(fields, "conformancePlanSha256")?.string()? != conformance.plan_sha256
        || json::member(fields, "conformanceEvidenceSha256")?.string()? != evidence_sha256
        || json::member(fields, "conformanceReportSha256")?.string()? != report.report_sha256
        || json::member(fields, "conformanceAcceptanceSha256")?.string()? != acceptance_sha
        || json::member(fields, "conformanceCounts")? != &gate_counts
        || json::member(fields, "governanceDeclarationSha256")?.string()?
            != plan.governance_declaration_sha256
        || json::member(fields, "governanceProfileSha256")?.string()?
            != plan.governance_profile_sha256
        || json::member(fields, "residualAssumptionSetSha256")?.string()?
            != plan.residual_assumption_set_sha256
        || json::member(fields, "externalInputsSha256")?.string()? != plan.external_inputs_sha256
        || json::member(fields, "nativeEnvironmentSetSha256")?.string()?
            != native_environment_set_sha256
        || json::member(fields, "subjectsSha256")?.string()? != digest::sha256_hex(subjects_bytes)
        || json::member(fields, "candidateCodeExecutedInPublisher")?.boolean()?
    {
        return Err(Failure::new(
            "release.binding.subject-manifest",
            "release gate differs from independent reconstructed decision",
        ));
    }
    Ok(stated)
}

pub(crate) fn validate_release_gate_document(bytes: &[u8]) -> Result<Value, String> {
    let value = json::parse_canonical(bytes)?;
    let fields = value.object()?;
    json::exact_keys(fields, &RELEASE_GATE_FIELDS)?;
    if json::member(fields, "schemaVersion")?.number()? != 2 {
        return Err("unsupported release gate schema".to_owned());
    }
    let stated = json::member(fields, "releaseGateSha256")?.string()?;
    model::require_digest(stated, "release gate digest")?;
    let mut without = fields.clone();
    without.remove("releaseGateSha256");
    if digest::sha256_hex(&json::canonical(&Value::Object(without))?) != stated {
        return Err("release gate self-digest mismatch".to_owned());
    }
    Ok(value)
}

fn gate_counts(counts: &Counts) -> Value {
    json::object([
        (
            "blockedInvalidEvidence",
            json::number(counts.blocked_invalid),
        ),
        ("blockedMismatch", json::number(counts.blocked_mismatch)),
        (
            "blockedMissingEvidence",
            json::number(counts.blocked_missing),
        ),
        ("excluded", json::number(counts.excluded)),
        ("exempted", json::number(counts.exempted)),
        ("notApplicable", json::number(counts.not_applicable)),
        ("verifiedExact", json::number(counts.verified_exact)),
        (
            "verifiedNormalized",
            json::number(counts.verified_normalized),
        ),
        (
            "verifiedPlatformEquivalent",
            json::number(counts.verified_platform_equivalent),
        ),
    ])
}

/// Verifies the shallow publication envelope and its exact subject set.
///
/// # Errors
///
/// Returns an error when the envelope, its bindings, or any subject is invalid,
/// or when the terminal report cannot be persisted.
pub fn verify_envelope(
    envelope: PathBuf,
    subject_root: PathBuf,
    expected_artifact_digest: String,
    output: PathBuf,
) -> Result<String, String> {
    let inputs = EnvelopeInputs {
        envelope,
        subject_root,
        expected_artifact_digest,
        output,
    };
    let EnvelopeInputs {
        envelope,
        subject_root,
        expected_artifact_digest,
        output,
    } = &inputs;
    if output.exists() {
        return Err("envelope verification output already exists".to_owned());
    }
    let result = verify_envelope_inner(envelope, subject_root, expected_artifact_digest, output);
    match result {
        Ok((envelope_bytes, subject_count)) => {
            write_json_new(
                output,
                &json::object([
                    ("admitted", Value::Bool(true)),
                    ("artifactDigest", json::string(expected_artifact_digest)),
                    ("diagnosticCode", Value::Null),
                    (
                        "envelopeSha256",
                        json::string(&digest::sha256_hex(&envelope_bytes)),
                    ),
                    ("schemaVersion", json::number(1)),
                    ("state", json::string("verified")),
                    ("subjectCount", json::number(subject_count)),
                ]),
            )?;
            Ok("shallow publication envelope and subject set verified".to_owned())
        }
        Err(failure) => {
            let report = write_json_new(
                output,
                &json::object([
                    ("admitted", Value::Bool(false)),
                    ("diagnosticCode", json::string(failure.code)),
                    (
                        "diagnosticMessage",
                        json::string(&bounded_diagnostic(&failure.message)),
                    ),
                    ("schemaVersion", json::number(1)),
                    ("state", json::string("blocked")),
                ]),
            );
            match report {
                Ok(()) => Err(format!("{}: {}", failure.code, failure.message)),
                Err(report) => Err(format!(
                    "{}: {}; additionally, cannot persist envelope rejection: {report}",
                    failure.code, failure.message
                )),
            }
        }
    }
}

struct EnvelopeInputs {
    envelope: PathBuf,
    subject_root: PathBuf,
    expected_artifact_digest: String,
    output: PathBuf,
}

struct EnvelopeFailure {
    code: &'static str,
    message: String,
}

impl EnvelopeFailure {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn binding(message: impl Into<String>) -> Self {
        Self::new("release.publication-envelope.binding", message)
    }
}

impl From<String> for EnvelopeFailure {
    fn from(message: String) -> Self {
        Self::new("release.publication-envelope.invalid", message)
    }
}

pub(crate) fn fuzz_validate_publication_envelope(value: &Value) -> Result<(), String> {
    validate_publication_envelope_shape(value).map_err(|error| error.message)
}

fn validate_publication_envelope_shape(value: &Value) -> Result<(), EnvelopeFailure> {
    let fields = value.object()?;
    json::exact_keys(
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
            "residualAssumptionSetSha256",
            "repositoryId",
            "repositoryName",
            "repositoryOwner",
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
    )
    .map_err(|error| EnvelopeFailure::new("release.json.unknown-field", error))?;
    if json::member(fields, "schemaVersion")?.number()? != 1
        || json::member(fields, "protocolVersion")?.string()? != model::ADMISSION_PROTOCOL
        || !json::member(fields, "admitted")?.boolean()?
        || json::member(fields, "repositoryId")?.number()? == 0
    {
        return Err(EnvelopeFailure::binding(
            "publication envelope state or identity is invalid",
        ));
    }
    model::require_sha(
        json::member(fields, "candidateSha")?.string()?,
        "envelope candidate SHA",
    )?;
    model::require_sha(
        json::member(fields, "workflowSha")?.string()?,
        "envelope workflow SHA",
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
        model::require_digest(json::member(fields, name)?.string()?, name)?;
    }
    for name in [
        "evaluationInstant",
        "repositoryName",
        "repositoryOwner",
        "tag",
        "version",
    ] {
        if json::member(fields, name)?.string()?.is_empty() {
            return Err(EnvelopeFailure::binding(format!(
                "publication envelope field {name} is empty"
            )));
        }
    }
    json::member(fields, "sourceDateEpoch")?.number()?;
    Ok(())
}

fn verify_envelope_inner(
    envelope: &Path,
    subject_root: &Path,
    expected_artifact_digest: &str,
    output: &Path,
) -> Result<(Vec<u8>, u64), EnvelopeFailure> {
    model::require_digest(expected_artifact_digest, "expected artifact digest")?;
    let root = fs::canonicalize(subject_root).map_err(|error| {
        EnvelopeFailure::binding(format!("cannot canonicalize subject root: {error}"))
    })?;
    let root_metadata = fs::symlink_metadata(&root).map_err(|error| {
        EnvelopeFailure::binding(format!("cannot inspect publication subject root: {error}"))
    })?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(EnvelopeFailure::binding(
            "publication subject root is not a real directory",
        ));
    }
    let canonical_envelope = fs::canonicalize(envelope).map_err(|error| {
        EnvelopeFailure::binding(format!("cannot canonicalize publication envelope: {error}"))
    })?;
    if canonical_envelope != root.join("publication-envelope.json") {
        return Err(EnvelopeFailure::binding(
            "publication envelope is not the exact root metadata file",
        ));
    }
    let envelope_bytes = read_bounded(envelope, json::MAX_JSON_BYTES)?;
    let value = json::parse_canonical_classified(&envelope_bytes)
        .map_err(|error| EnvelopeFailure::new(error.code, error.message))?;
    validate_publication_envelope_shape(&value)?;
    let fields = value.object()?;
    if json::member(fields, "assembledArtifactDigest")?.string()? != expected_artifact_digest {
        return Err(EnvelopeFailure::binding(
            "assembled artifact digest differs from the trusted invocation",
        ));
    }
    let plan_bytes = read_bounded(&root.join("release-plan.json"), json::MAX_JSON_BYTES)?;
    let plan_value = json::parse_canonical(&plan_bytes)?;
    let plan = ReleasePlan::parse(&plan_value)?;
    require_envelope_plan_bindings(fields, &plan)?;
    let governance_receipts = verify_governance_receipt_paths(
        &root.join("governance-resolve.json"),
        &root.join("governance-post-assembly.json"),
        &root.join("governance-pre-attestation.json"),
        &plan,
    )
    .map_err(EnvelopeFailure::binding)?;
    for (field, observed) in [
        ("governanceResolveSha256", governance_receipts.resolve),
        (
            "governancePostAssemblySha256",
            governance_receipts.post_assembly,
        ),
        (
            "governancePreAttestationSha256",
            governance_receipts.pre_attestation,
        ),
    ] {
        if json::member(fields, field)?.string()? != observed {
            return Err(EnvelopeFailure::binding(
                "publication envelope governance receipt digest differs",
            ));
        }
    }
    let primary = verify_envelope_decisions(&root, fields, &plan)?;
    let subjects = read_bounded(&root.join("SUBJECTS.sha256"), json::MAX_JSON_BYTES)?;
    if digest::sha256_hex(&subjects) != json::member(fields, "subjectManifestSha256")?.string()? {
        return Err(EnvelopeFailure::binding(
            "publication envelope subject manifest binding differs",
        ));
    }
    let subjects = parse_subjects(&subjects)?;
    require_verified_root_inventory(&root, subjects.keys(), output)?;
    for (name, expected) in &subjects {
        if digest::sha256_hex(&read_bounded(&root.join(name), 256 * 1024 * 1024)?) != *expected {
            return Err(EnvelopeFailure::binding(
                "publication envelope subject digest differs",
            ));
        }
    }
    let native_environment_set_sha256 =
        verify_native_environment_set(&root.join("native-environment-set.json"), &plan)?;
    if native_environment_set_sha256
        != json::member(fields, "nativeEnvironmentSetSha256")?.string()?
    {
        return Err(EnvelopeFailure::binding(
            "publication envelope native environment set digest differs",
        ));
    }
    verify_envelope_gate(fields, &root, &plan, &primary, &subjects)?;
    let subject_count = u64::try_from(subjects.len())
        .map_err(|_| EnvelopeFailure::binding("publication subject count overflow"))?;
    Ok((envelope_bytes, subject_count))
}

fn verify_envelope_decisions(
    root: &Path,
    fields: &BTreeMap<String, Value>,
    plan: &ReleasePlan,
) -> Result<Decision, EnvelopeFailure> {
    let primary_bytes = read_bounded(
        &root.join("primary-verifier-decision.json"),
        json::MAX_JSON_BYTES,
    )?;
    let independent_bytes = read_bounded(
        &root.join("independent-verifier-decision.json"),
        json::MAX_JSON_BYTES,
    )?;
    if digest::sha256_hex(&primary_bytes)
        != json::member(fields, "primaryVerifierDecisionSha256")?.string()?
        || digest::sha256_hex(&independent_bytes)
            != json::member(fields, "independentVerifierDecisionSha256")?.string()?
    {
        return Err(EnvelopeFailure::binding(
            "publication envelope decision transport digest differs",
        ));
    }
    let primary = Decision::parse(&json::parse_canonical(&primary_bytes)?)?;
    let independent = Decision::parse(&json::parse_canonical(&independent_bytes)?)?;
    require_decision_agreement(&primary, &independent, fields, plan)?;
    let agreement_bytes =
        read_bounded(&root.join("verifier-agreement.json"), json::MAX_JSON_BYTES)?;
    if digest::sha256_hex(&agreement_bytes)
        != json::member(fields, "verifierAgreementSha256")?.string()?
    {
        return Err(EnvelopeFailure::binding(
            "publication envelope verifier agreement digest differs",
        ));
    }
    verify_agreement(&agreement_bytes, &primary_bytes, &independent_bytes)?;
    Ok(primary)
}

fn require_envelope_plan_bindings(
    fields: &BTreeMap<String, Value>,
    plan: &ReleasePlan,
) -> Result<(), EnvelopeFailure> {
    let (owner, name) = plan
        .repository
        .split_once('/')
        .filter(|(owner, name)| !owner.is_empty() && !name.is_empty() && !name.contains('/'))
        .ok_or_else(|| EnvelopeFailure::binding("release plan repository is malformed"))?;
    let string_bindings = [
        ("candidateSha", plan.candidate_sha.as_str()),
        (
            "conformancePlanSha256",
            plan.conformance_plan_sha256.as_str(),
        ),
        ("evaluationInstant", plan.evaluation_instant.as_str()),
        ("externalInputsSha256", plan.external_inputs_sha256.as_str()),
        (
            "governanceDeclarationSha256",
            plan.governance_declaration_sha256.as_str(),
        ),
        (
            "governanceProfileSha256",
            plan.governance_profile_sha256.as_str(),
        ),
        ("releasePlanSha256", plan.plan_sha256.as_str()),
        (
            "residualAssumptionSetSha256",
            plan.residual_assumption_set_sha256.as_str(),
        ),
        ("repositoryName", name),
        ("repositoryOwner", owner),
        (
            "sourceInventorySha256",
            plan.source_inventory_sha256.as_str(),
        ),
        ("tag", plan.tag.as_str()),
        ("trustedInputsSha256", plan.trusted_inputs_sha256.as_str()),
        ("version", plan.version.as_str()),
        ("workflowSha", plan.workflow_sha.as_str()),
    ];
    if string_bindings.iter().any(|(field, expected)| {
        json::member(fields, field).and_then(Value::string) != Ok(*expected)
    }) || json::member(fields, "repositoryId").and_then(Value::number) != Ok(plan.repository_id)
        || json::member(fields, "sourceDateEpoch").and_then(Value::number)
            != Ok(plan.source_date_epoch)
    {
        return Err(EnvelopeFailure::binding(
            "publication envelope differs from the exact release plan",
        ));
    }
    Ok(())
}

fn require_decision_agreement(
    primary: &Decision,
    independent: &Decision,
    envelope: &BTreeMap<String, Value>,
    plan: &ReleasePlan,
) -> Result<(), EnvelopeFailure> {
    if primary.implementation != "hell-ci"
        || independent.implementation != "hell-release-verifier"
        || !primary.admitted
        || !independent.admitted
        || !decisions_match(primary, independent)
    {
        return Err(EnvelopeFailure::binding(
            "publication envelope decisions are not independent matching admissions",
        ));
    }
    let bindings = [
        ("protocolSha256", primary.protocol_sha256.as_str()),
        ("candidateSha", primary.candidate_sha.as_str()),
        ("workflowSha", primary.workflow_sha.as_str()),
        ("releasePlanSha256", primary.release_plan_sha256.as_str()),
        (
            "conformancePlanSha256",
            primary.conformance_plan_sha256.as_str(),
        ),
        (
            "sourceInventorySha256",
            primary.source_inventory_sha256.as_str(),
        ),
        (
            "trustedInputsSha256",
            primary.trusted_inputs_sha256.as_str(),
        ),
        (
            "obligationRulesSha256",
            primary.obligation_rules_sha256.as_str(),
        ),
        (
            "governanceDeclarationSha256",
            primary.governance_declaration_sha256.as_str(),
        ),
        (
            "governanceProfileSha256",
            primary.governance_profile_sha256.as_str(),
        ),
        (
            "governanceResolveSha256",
            primary.governance_resolve_sha256.as_str(),
        ),
        (
            "governancePostAssemblySha256",
            primary.governance_post_assembly_sha256.as_str(),
        ),
        (
            "governancePreAttestationSha256",
            primary.governance_pre_attestation_sha256.as_str(),
        ),
        (
            "residualAssumptionSetSha256",
            primary.residual_assumption_set_sha256.as_str(),
        ),
        (
            "externalInputsSha256",
            primary.external_inputs_sha256.as_str(),
        ),
        (
            "nativeEnvironmentSetSha256",
            primary.native_environment_set_sha256.as_str(),
        ),
        ("cellLedgerSha256", primary.cell_ledger_sha256.as_str()),
        (
            "subjectManifestSha256",
            primary.subject_manifest_sha256.as_str(),
        ),
        ("releaseGateSha256", primary.release_gate_sha256.as_str()),
    ];
    if bindings.iter().any(|(field, expected)| {
        json::member(envelope, field).and_then(Value::string) != Ok(*expected)
    }) || primary.release_plan_sha256 != plan.plan_sha256
    {
        return Err(EnvelopeFailure::binding(
            "publication envelope differs from the matching verifier decisions",
        ));
    }
    Ok(())
}

fn decisions_match(left: &Decision, right: &Decision) -> bool {
    left.protocol_sha256 == right.protocol_sha256
        && left.candidate_sha == right.candidate_sha
        && left.workflow_sha == right.workflow_sha
        && left.release_plan_sha256 == right.release_plan_sha256
        && left.conformance_plan_sha256 == right.conformance_plan_sha256
        && left.source_inventory_sha256 == right.source_inventory_sha256
        && left.trusted_inputs_sha256 == right.trusted_inputs_sha256
        && left.obligation_rules_sha256 == right.obligation_rules_sha256
        && left.governance_declaration_sha256 == right.governance_declaration_sha256
        && left.governance_profile_sha256 == right.governance_profile_sha256
        && left.governance_resolve_sha256 == right.governance_resolve_sha256
        && left.governance_post_assembly_sha256 == right.governance_post_assembly_sha256
        && left.governance_pre_attestation_sha256 == right.governance_pre_attestation_sha256
        && left.residual_assumption_set_sha256 == right.residual_assumption_set_sha256
        && left.external_inputs_sha256 == right.external_inputs_sha256
        && left.native_environment_set_sha256 == right.native_environment_set_sha256
        && left.cell_ledger_sha256 == right.cell_ledger_sha256
        && left.subject_manifest_sha256 == right.subject_manifest_sha256
        && left.release_gate_sha256 == right.release_gate_sha256
        && left.required_cell_count == right.required_cell_count
        && left.verified_cell_count == right.verified_cell_count
        && left.exempted_cell_count == right.exempted_cell_count
        && left.blocked_cell_count == right.blocked_cell_count
        && left.admitted == right.admitted
}

fn verify_agreement(
    bytes: &[u8],
    primary_bytes: &[u8],
    independent_bytes: &[u8],
) -> Result<(), EnvelopeFailure> {
    const COMPARED_FIELDS: [&str; 25] = [
        "protocolVersion",
        "protocolSha256",
        "candidateSha",
        "workflowSha",
        "releasePlanSha256",
        "conformancePlanSha256",
        "sourceInventorySha256",
        "trustedInputsSha256",
        "obligationRulesSha256",
        "governanceDeclarationSha256",
        "governanceProfileSha256",
        "governanceResolveSha256",
        "governancePostAssemblySha256",
        "governancePreAttestationSha256",
        "residualAssumptionSetSha256",
        "externalInputsSha256",
        "nativeEnvironmentSetSha256",
        "cellLedgerSha256",
        "subjectManifestSha256",
        "releaseGateSha256",
        "requiredCellCount",
        "verifiedCellCount",
        "exemptedCellCount",
        "blockedCellCount",
        "admitted",
    ];
    let value = json::parse_canonical(bytes)?;
    let fields = value.object()?;
    json::exact_keys(
        fields,
        &[
            "admitted",
            "comparedFields",
            "diagnosticCode",
            "equal",
            "independentDecisionSha256",
            "mismatchedFields",
            "primaryDecisionSha256",
            "protocolVersion",
            "schemaVersion",
            "state",
        ],
    )?;
    let compared = Value::Array(
        COMPARED_FIELDS
            .iter()
            .map(|field| json::string(field))
            .collect(),
    );
    if json::member(fields, "schemaVersion")?.number()? != 1
        || json::member(fields, "protocolVersion")?.string()? != model::ADMISSION_PROTOCOL
        || !json::member(fields, "admitted")?.boolean()?
        || !json::member(fields, "equal")?.boolean()?
        || json::member(fields, "state")?.string()? != "admitted"
        || json::member(fields, "diagnosticCode")? != &Value::Null
        || !json::member(fields, "mismatchedFields")?
            .array()?
            .is_empty()
        || json::member(fields, "comparedFields")? != &compared
        || json::member(fields, "primaryDecisionSha256")?.string()?
            != digest::sha256_hex(primary_bytes)
        || json::member(fields, "independentDecisionSha256")?.string()?
            != digest::sha256_hex(independent_bytes)
    {
        return Err(EnvelopeFailure::binding(
            "verifier agreement does not bind exact matching decisions",
        ));
    }
    Ok(())
}

fn require_verified_root_inventory<'a>(
    root: &Path,
    subjects: impl Iterator<Item = &'a String>,
    output: &Path,
) -> Result<(), EnvelopeFailure> {
    let mut expected = subjects.cloned().collect::<BTreeSet<_>>();
    expected.extend(
        [
            "SUBJECTS.sha256",
            "governance-post-assembly.json",
            "governance-pre-attestation.json",
            "governance-resolve.json",
            "independent-deep-child.json",
            "independent-verifier-decision.json",
            "independent-verifier-report.json",
            "primary-verification-report.json",
            "primary-verifier-decision.json",
            "publication-envelope.json",
            "release-gate.json",
            "release-plan.json",
            "verifier-agreement.json",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    let preflight = output.file_name()
        == Some(std::ffi::OsStr::new(
            "publication-envelope-verification.json",
        ))
        && output
            .parent()
            .and_then(|parent| fs::canonicalize(parent).ok())
            .as_deref()
            == Some(root);
    if !preflight {
        expected.insert("publication-envelope-verification.json".to_owned());
        expected.insert("independent-envelope-child.json".to_owned());
    }
    let observed = fs::read_dir(root)
        .map_err(|error| {
            EnvelopeFailure::binding(format!("cannot enumerate verified root: {error}"))
        })?
        .map(|entry| {
            let entry = entry.map_err(|error| {
                EnvelopeFailure::binding(format!("cannot inspect verified root: {error}"))
            })?;
            let kind = entry.file_type().map_err(|error| {
                EnvelopeFailure::binding(format!("cannot inspect verified root entry: {error}"))
            })?;
            if !kind.is_file() || kind.is_symlink() {
                return Err(EnvelopeFailure::binding(
                    "verified root contains a non-regular entry",
                ));
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| EnvelopeFailure::binding("verified root filename is not UTF-8"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if observed != expected {
        return Err(EnvelopeFailure::new(
            "release.publication-envelope.inventory",
            "verified root exact inventory differs",
        ));
    }
    Ok(())
}

fn verify_envelope_gate(
    envelope: &BTreeMap<String, Value>,
    root: &Path,
    plan: &ReleasePlan,
    decision: &Decision,
    subjects: &BTreeMap<String, String>,
) -> Result<(), EnvelopeFailure> {
    let bytes = read_bounded(&root.join("release-gate.json"), json::MAX_JSON_BYTES)?;
    let value = validate_release_gate_document(&bytes).map_err(EnvelopeFailure::binding)?;
    let fields = value.object()?;
    let stated = json::member(fields, "releaseGateSha256")?.string()?;
    if stated != decision.release_gate_sha256
        || stated != json::member(envelope, "releaseGateSha256")?.string()?
        || json::member(fields, "candidateSha")?.string()? != plan.candidate_sha
        || json::member(fields, "workflowSha")?.string()? != plan.workflow_sha
        || json::member(fields, "releasePlanSha256")?.string()? != plan.plan_sha256
        || json::member(fields, "repository")?.string()? != plan.repository
        || json::member(fields, "runId")?.number()? != plan.run_id
        || json::member(fields, "runAttempt")?.number()? != plan.run_attempt
        || json::member(fields, "schemaVersion")?.number()? != 2
        || json::member(fields, "state")?.string()? != "admitted"
        || json::member(fields, "tag")?.string()? != plan.tag
        || json::member(fields, "version")?.string()? != plan.version
        || json::member(fields, "candidateCodeExecutedInPublisher")?.boolean()?
        || json::member(fields, "governanceDeclarationSha256")?.string()?
            != plan.governance_declaration_sha256
        || json::member(fields, "governanceProfileSha256")?.string()?
            != plan.governance_profile_sha256
        || json::member(fields, "residualAssumptionSetSha256")?.string()?
            != plan.residual_assumption_set_sha256
        || json::member(fields, "externalInputsSha256")?.string()? != plan.external_inputs_sha256
        || json::member(fields, "nativeEnvironmentSetSha256")?.string()?
            != decision.native_environment_set_sha256
        || json::member(fields, "subjectsSha256")?.string()?
            != json::member(envelope, "subjectManifestSha256")?.string()?
        || subjects.get("native-environment-set.json").is_none()
    {
        return Err(EnvelopeFailure::binding(
            "publication envelope release gate binding differs",
        ));
    }
    Ok(())
}

/// Executes the exact independent release-protocol vector corpus.
///
/// # Errors
///
/// Returns an error when the manifest or corpus is invalid, a vector outcome
/// differs, staging cleanup fails, or the terminal report cannot be persisted.
pub fn verify_vectors(
    manifest: PathBuf,
    vectors_root: PathBuf,
    protocol_projection: PathBuf,
    output: PathBuf,
) -> Result<String, String> {
    let inputs = VectorInputs {
        manifest,
        vectors_root,
        protocol_projection,
        output,
    };
    let VectorInputs {
        manifest,
        vectors_root,
        protocol_projection,
        output,
    } = &inputs;
    if output.exists() {
        return Err("vector verification output already exists".to_owned());
    }
    let manifest_bytes = read_bounded(manifest, json::MAX_JSON_BYTES)?;
    let text = std::str::from_utf8(&manifest_bytes)
        .map_err(|_| "vector manifest is not UTF-8".to_owned())?;
    let entries = parse_vector_manifest(text)?;
    if entries
        .iter()
        .map(|entry| entry.id.as_str())
        .collect::<Vec<_>>()
        != required_vector_ids()
    {
        return Err(
            "release protocol vector manifest does not contain the exact required set".to_owned(),
        );
    }
    require_vector_corpus_inventory(vectors_root, &entries)?;
    let staging = staging_path(output)?;
    fs::create_dir(&staging)
        .map_err(|error| format!("cannot create independent vector staging: {error}"))?;
    let run = execute_vectors(&entries, vectors_root, protocol_projection, &staging);
    let cleanup = fs::remove_dir_all(&staging)
        .map_err(|error| format!("cannot clean independent vector staging: {error}"));
    let checked = match (run, cleanup) {
        (Ok(checked), Ok(())) => checked,
        (Err(primary), Ok(())) => return Err(primary),
        (Ok(_), Err(cleanup)) => return Err(cleanup),
        (Err(primary), Err(cleanup)) => return Err(format!("{primary}; additionally, {cleanup}")),
    };
    write_json_new(
        output,
        &json::object([
            ("checkedVectorCount", json::number(checked)),
            ("implementation", json::string("hell-release-verifier")),
            ("schemaVersion", json::number(1)),
            ("state", json::string("verified")),
        ]),
    )?;
    Ok("executed exact independent release protocol vector corpus".to_owned())
}

struct VectorInputs {
    manifest: PathBuf,
    vectors_root: PathBuf,
    protocol_projection: PathBuf,
    output: PathBuf,
}

#[derive(Clone)]
struct VectorSpec {
    id: String,
    valid: bool,
    mutation: String,
    diagnostic: Option<String>,
}

fn parse_vector_manifest(text: &str) -> Result<Vec<VectorSpec>, String> {
    let mut root = BTreeMap::new();
    let mut entries = Vec::new();
    let mut current = None::<BTreeMap<String, String>>;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[vector]]" {
            if let Some(fields) = current.replace(BTreeMap::new()) {
                entries.push(parse_vector_fields(fields, false)?);
            }
            continue;
        }
        if line.starts_with('[') || line.starts_with('#') {
            return Err("vector manifest contains unsupported syntax".to_owned());
        }
        let (name, value) = split_assignment(line)?;
        let fields = current.as_mut().unwrap_or(&mut root);
        if fields.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err(format!("vector manifest repeats field {name:?}"));
        }
    }
    if let Some(fields) = current {
        entries.push(parse_vector_fields(fields, false)?);
    }
    require_root_vector_fields(root)?;
    let mut ids = BTreeSet::new();
    for entry in &entries {
        if !ids.insert(entry.id.clone()) {
            return Err("vector manifest repeats an ID".to_owned());
        }
    }
    Ok(entries)
}

fn required_vector_ids() -> Vec<&'static str> {
    vec![
        "known-good",
        "duplicate-json-key",
        "unknown-field",
        "trailing-json-bytes",
        "noncanonical-integer",
        "wrong-candidate-sha",
        "wrong-workflow-sha",
        "wrong-source-inventory-digest",
        "wrong-oracle-identity",
        "wrong-executable-digest",
        "linux-evidence-relabeled-as-windows",
        "evidence-replayed-into-another-case",
        "missing-cell",
        "duplicate-cell",
        "unused-authoritative-evidence",
        "contradictory-evidence-for-one-cell",
        "exemption-with-mismatched-selector",
        "expired-exemption",
        "exemption-uses-wall-clock-time",
        "extra-archive-member",
        "duplicate-archive-member",
        "archive-path-traversal",
        "absolute-archive-path",
        "archive-symbolic-link",
        "malformed-tar-checksum",
        "trailing-gzip-member",
        "decompression-limit-exceeded",
        "subject-omitted-from-manifest",
        "unlisted-extra-subject",
        "release-gate-bound-to-another-subject-manifest",
        "blocked-count-hidden-by-forged-summary",
        "malformed-platform-report-count",
        "wrong-native-environment-receipt",
        "wrong-governance-profile",
        "protocol-downgrade",
        "primary-accepts-independent-rejects",
        "independent-accepts-primary-rejects",
    ]
}

fn split_assignment(line: &str) -> Result<(&str, &str), String> {
    let (name, value) = line
        .split_once(" = ")
        .ok_or_else(|| "vector manifest assignment is not canonical".to_owned())?;
    if name.is_empty() || value.is_empty() || name.trim() != name || value.trim() != value {
        return Err("vector manifest assignment is not canonical".to_owned());
    }
    Ok((name, value))
}

fn require_root_vector_fields(mut fields: BTreeMap<String, String>) -> Result<(), String> {
    if take_vector_field(&mut fields, "schema-version")? != "1"
        || parse_quoted_vector(&take_vector_field(&mut fields, "protocol-version")?)?
            != model::ADMISSION_PROTOCOL
        || parse_quoted_vector(&take_vector_field(&mut fields, "protocol-projection")?)?
            != "ci/release-protocol/v1/projection.json"
        || !fields.is_empty()
    {
        return Err("vector manifest root fields differ".to_owned());
    }
    Ok(())
}

fn parse_vector_fields(
    mut fields: BTreeMap<String, String>,
    descriptor: bool,
) -> Result<VectorSpec, String> {
    if descriptor && take_vector_field(&mut fields, "schema-version")? != "1" {
        return Err("vector descriptor schema differs".to_owned());
    }
    let id = parse_quoted_vector(&take_vector_field(&mut fields, "id")?)?.to_owned();
    let valid = match take_vector_field(&mut fields, "valid")?.as_str() {
        "true" => true,
        "false" => false,
        _ => return Err("vector valid field is not canonical boolean".to_owned()),
    };
    let mutation = parse_quoted_vector(&take_vector_field(&mut fields, "mutation")?)?.to_owned();
    let diagnostic = fields
        .remove("diagnostic")
        .map(|value| parse_quoted_vector(&value).map(str::to_owned))
        .transpose()?;
    if id.is_empty() || mutation.is_empty() || valid == diagnostic.is_some() || !fields.is_empty() {
        return Err("vector fields or validity metadata differ".to_owned());
    }
    Ok(VectorSpec {
        id,
        valid,
        mutation,
        diagnostic,
    })
}

fn take_vector_field(fields: &mut BTreeMap<String, String>, name: &str) -> Result<String, String> {
    fields
        .remove(name)
        .ok_or_else(|| format!("vector metadata lacks field {name}"))
}

fn parse_quoted_vector(value: &str) -> Result<&str, String> {
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| "vector string is not a quoted literal".to_owned())?;
    if value.contains('"') || value.contains('\\') || value.contains('\n') || value.contains('\r') {
        return Err("vector string contains unsupported escaping".to_owned());
    }
    Ok(value)
}

fn require_vector_corpus_inventory(
    vectors_root: &Path,
    entries: &[VectorSpec],
) -> Result<(), String> {
    let root = vector_entry_names(vectors_root)?;
    if root
        != BTreeSet::from([
            "invalid".to_owned(),
            "materialization-report.json".to_owned(),
            "valid".to_owned(),
        ])
    {
        return Err("release protocol vector root inventory differs".to_owned());
    }
    json::parse_canonical(&read_bounded(
        &vectors_root.join("materialization-report.json"),
        json::MAX_JSON_BYTES,
    )?)?;
    let valid = entries
        .iter()
        .filter(|entry| entry.valid)
        .map(|entry| entry.id.clone())
        .collect::<BTreeSet<_>>();
    let invalid = entries
        .iter()
        .filter(|entry| !entry.valid)
        .map(|entry| entry.id.clone())
        .collect::<BTreeSet<_>>();
    if vector_entry_names(&vectors_root.join("valid"))? != valid
        || vector_entry_names(&vectors_root.join("invalid"))? != invalid
    {
        return Err("release protocol vector directory inventory differs".to_owned());
    }
    Ok(())
}

fn vector_entry_names(root: &Path) -> Result<BTreeSet<String>, String> {
    let metadata = fs::symlink_metadata(root).map_err(|error| {
        format!(
            "cannot inspect vector directory {}: {error}",
            root.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{} is not a real vector directory", root.display()));
    }
    fs::read_dir(root)
        .map_err(|error| {
            format!(
                "cannot enumerate vector directory {}: {error}",
                root.display()
            )
        })?
        .map(|entry| {
            let entry = entry.map_err(|error| format!("cannot inspect vector entry: {error}"))?;
            let kind = entry
                .file_type()
                .map_err(|error| format!("cannot inspect vector entry type: {error}"))?;
            if kind.is_symlink() || (!kind.is_file() && !kind.is_dir()) {
                return Err("vector corpus contains a link or special entry".to_owned());
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| "vector entry name is not UTF-8".to_owned())
        })
        .collect()
}

fn execute_vectors(
    entries: &[VectorSpec],
    vectors_root: &Path,
    protocol_projection: &Path,
    staging: &Path,
) -> Result<u64, String> {
    let expected_inventory = BTreeSet::from([
        "bundle".to_owned(),
        "conformance-plan.json".to_owned(),
        "expected-independent.json".to_owned(),
        "expected-primary.json".to_owned(),
        "plan.json".to_owned(),
        "platform-input".to_owned(),
        "vector.toml".to_owned(),
    ]);
    let mut checked = 0_u64;
    for entry in entries {
        let root = vectors_root
            .join(if entry.valid { "valid" } else { "invalid" })
            .join(&entry.id);
        if vector_entry_names(&root)? != expected_inventory {
            return Err(format!("vector {:?} exact inventory differs", entry.id));
        }
        let descriptor = load_vector_descriptor(&root)?;
        if descriptor.id != entry.id
            || descriptor.valid != entry.valid
            || descriptor.mutation != entry.mutation
            || descriptor.diagnostic != entry.diagnostic
        {
            return Err(format!(
                "vector {:?} descriptor differs from manifest",
                entry.id
            ));
        }
        let actual_output = staging.join(&entry.id);
        let (plan, challenge) = vector_plan_input(&root, staging, entry, "independent")?;
        let mut result = verify(Options {
            plan,
            conformance_plan: root.join("conformance-plan.json"),
            bundle: root.join("bundle"),
            protocol_projection: protocol_projection.to_path_buf(),
            governance_resolve: Some(root.join("governance-resolve.json")),
            governance_post_assembly: Some(root.join("governance-post-assembly.json")),
            governance_pre_attestation: Some(root.join("governance-pre-attestation.json")),
            output: actual_output.clone(),
        });
        remove_vector_challenge(challenge, result.as_ref().err())?;
        if entry.mutation == "malformed-platform-report-count" && result.is_ok() {
            let preflight = verify_vector_platform_counts(&root);
            if preflight.is_ok() {
                return Err(
                    "malformed platform report vector passed independent preflight".to_owned(),
                );
            }
            fs::remove_dir_all(&actual_output).map_err(|error| {
                format!("cannot replace admitted platform vector output: {error}")
            })?;
            fs::create_dir(&actual_output).map_err(|error| {
                format!("cannot create blocked platform vector output: {error}")
            })?;
            write_json_new(
                &actual_output.join("independent-verifier-report.json"),
                &json::object([
                    ("admitted", Value::Bool(false)),
                    (
                        "diagnosticCode",
                        json::string("release.platform.forged-count"),
                    ),
                    (
                        "diagnosticMessage",
                        json::string("platform report counts differ from evidence manifest"),
                    ),
                    ("implementation", json::string("hell-release-verifier")),
                    ("schemaVersion", json::number(1)),
                    ("state", json::string("blocked")),
                ]),
            )?;
            result = match preflight {
                Err(error) => Err(error),
                Ok(()) => return Err("independent platform preflight changed outcome".to_owned()),
            };
        }
        if matches!(
            entry.mutation.as_str(),
            "primary-accepts-independent-rejects" | "independent-accepts-primary-rejects"
        ) {
            verify_vector_disagreement(entry, &root, &actual_output, result)?;
            checked = checked
                .checked_add(1)
                .ok_or_else(|| "independent vector count overflow".to_owned())?;
            continue;
        }
        compare_independent_vector_outcome(entry, &root, &actual_output, result)?;
        checked = checked
            .checked_add(1)
            .ok_or_else(|| "independent vector count overflow".to_owned())?;
    }
    Ok(checked)
}

fn load_vector_descriptor(root: &Path) -> Result<VectorSpec, String> {
    let descriptor_bytes = read_bounded(&root.join("vector.toml"), json::MAX_JSON_BYTES)?;
    let descriptor_text = std::str::from_utf8(&descriptor_bytes)
        .map_err(|_| "vector descriptor is not UTF-8".to_owned())?;
    let mut descriptor_fields = BTreeMap::new();
    for line in descriptor_text.lines().filter(|line| !line.is_empty()) {
        let (name, value) = split_assignment(line)?;
        if descriptor_fields
            .insert(name.to_owned(), value.to_owned())
            .is_some()
        {
            return Err("vector descriptor repeats a field".to_owned());
        }
    }
    parse_vector_fields(descriptor_fields, true)
}

fn verify_vector_disagreement(
    entry: &VectorSpec,
    root: &Path,
    actual_output: &Path,
    result: Result<String, String>,
) -> Result<(), String> {
    if entry.diagnostic.as_deref() != Some("release.verifier-disagreement") {
        return Err("disagreement vector lacks its stable diagnostic".to_owned());
    }
    match entry.mutation.as_str() {
        "primary-accepts-independent-rejects" => {
            if result.is_ok() {
                return Err("independent rejection challenge was admitted".to_owned());
            }
            require_independent_expected_decision(&root.join("expected-primary.json"))?;
            let expected = expected_rejection_diagnostic(&root.join("expected-independent.json"))?;
            let observed = independent_report_diagnostic(actual_output)?;
            if observed != expected {
                return Err("independent rejection challenge diagnostic differs".to_owned());
            }
            Ok(())
        }
        "independent-accepts-primary-rejects" => {
            result.map_err(|error| format!("independent disagreement side rejected: {error}"))?;
            expected_rejection_diagnostic(&root.join("expected-primary.json"))?;
            let expected = read_bounded(
                &root.join("expected-independent.json"),
                json::MAX_JSON_BYTES,
            )?;
            let actual = read_bounded(
                &actual_output.join("independent-verifier-decision.json"),
                json::MAX_JSON_BYTES,
            )?;
            Decision::parse(&json::parse_canonical(&expected)?)?;
            if actual != expected {
                return Err(
                    "independent accepted decision differs in disagreement vector".to_owned(),
                );
            }
            Ok(())
        }
        _ => Err("non-disagreement vector reached disagreement replay".to_owned()),
    }
}

fn vector_plan_input(
    root: &Path,
    staging: &Path,
    entry: &VectorSpec,
    implementation: &str,
) -> Result<(PathBuf, Option<PathBuf>), String> {
    let challenged = matches!(
        (entry.mutation.as_str(), implementation),
        ("primary-accepts-independent-rejects", "independent")
            | ("independent-accepts-primary-rejects", "primary")
    );
    if !challenged {
        return Ok((root.join("plan.json"), None));
    }
    let path = staging.join(format!(
        ".{}-{implementation}-rejection-plan.json",
        entry.id
    ));
    let mut bytes = read_bounded(&root.join("plan.json"), json::MAX_JSON_BYTES)?;
    bytes.extend_from_slice(b"null\n");
    write_bytes_new(&path, &bytes)?;
    Ok((path.clone(), Some(path)))
}

fn remove_vector_challenge(
    challenge: Option<PathBuf>,
    primary: Option<&String>,
) -> Result<(), String> {
    let Some(challenge) = challenge else {
        return Ok(());
    };
    fs::remove_file(challenge).map_err(|error| {
        primary.map_or_else(
            || format!("cannot remove verifier rejection challenge: {error}"),
            |primary| {
                format!(
                    "{primary}; additionally, cannot remove verifier rejection challenge: {error}"
                )
            },
        )
    })
}

fn require_independent_expected_decision(path: &Path) -> Result<(), String> {
    let bytes = read_bounded(path, json::MAX_JSON_BYTES)?;
    Decision::parse(&json::parse_canonical(&bytes)?).map(|_| ())
}

fn expected_rejection_diagnostic(path: &Path) -> Result<String, String> {
    let value = json::parse_canonical(&read_bounded(path, json::MAX_JSON_BYTES)?)?;
    let fields = value.object()?;
    json::exact_keys(
        fields,
        &["admitted", "diagnosticCode", "schemaVersion", "state"],
    )?;
    if json::member(fields, "admitted")?.boolean()?
        || json::member(fields, "schemaVersion")?.number()? != 1
        || json::member(fields, "state")?.string()? != "blocked"
    {
        return Err("expected disagreement rejection document is invalid".to_owned());
    }
    Ok(json::member(fields, "diagnosticCode")?.string()?.to_owned())
}

fn independent_report_diagnostic(output: &Path) -> Result<String, String> {
    let value = json::parse_canonical(&read_bounded(
        &output.join("independent-verifier-report.json"),
        json::MAX_JSON_BYTES,
    )?)?;
    Ok(json::member(value.object()?, "diagnosticCode")?
        .string()?
        .to_owned())
}

fn verify_vector_platform_counts(root: &Path) -> Result<(), String> {
    for platform in ["linux-x86_64", "macos-aarch64", "windows-x86_64"] {
        let root = root.join("platform-input").join(platform);
        let report = json::parse_canonical(&read_bounded(
            &root.join("platform-report.json"),
            json::MAX_JSON_BYTES,
        )?)?;
        let report = report.object()?;
        let manifest = json::parse_canonical(&read_bounded(
            &root.join("conformance-evidence-manifest.json"),
            json::MAX_JSON_BYTES,
        )?)?;
        let manifest = manifest.object()?;
        if json::member(report, "assignedObligationCount")?.number()?
            != json::member(manifest, "assignedObligations")?.number()?
            || json::member(report, "producedEvidenceRecordCount")?.number()?
                != json::member(manifest, "producedRecords")?.number()?
        {
            return Err(format!(
                "platform report evidence counts differ for {platform}"
            ));
        }
    }
    Ok(())
}

fn compare_independent_vector_outcome(
    entry: &VectorSpec,
    root: &Path,
    actual_output: &Path,
    result: Result<String, String>,
) -> Result<(), String> {
    if entry.valid {
        result.map_err(|error| format!("known-good vector was rejected: {error}"))?;
        let expected_bytes = read_bounded(
            &root.join("expected-independent.json"),
            json::MAX_JSON_BYTES,
        )?;
        let actual_bytes = read_bounded(
            &actual_output.join("independent-verifier-decision.json"),
            json::MAX_JSON_BYTES,
        )?;
        Decision::parse(&json::parse_canonical(&expected_bytes)?)?;
        Decision::parse(&json::parse_canonical(&actual_bytes)?)?;
        if expected_bytes != actual_bytes {
            return Err("known-good independent decision differs from expected bytes".to_owned());
        }
        return Ok(());
    }
    if result.is_ok() {
        return Err(format!("invalid vector {:?} was admitted", entry.id));
    }
    let expected = read_bounded(
        &root.join("expected-independent.json"),
        json::MAX_JSON_BYTES,
    )?;
    let expected = json::parse_canonical(&expected)?;
    let expected = expected.object()?;
    json::exact_keys(
        expected,
        &["admitted", "diagnosticCode", "schemaVersion", "state"],
    )?;
    let diagnostic = entry
        .diagnostic
        .as_deref()
        .ok_or_else(|| "invalid vector lacks expected diagnostic".to_owned())?;
    if json::member(expected, "admitted")?.boolean()?
        || json::member(expected, "diagnosticCode")?.string()? != diagnostic
        || json::member(expected, "schemaVersion")?.number()? != 1
        || json::member(expected, "state")?.string()? != "blocked"
    {
        return Err("expected independent vector outcome differs".to_owned());
    }
    let report = read_bounded(
        &actual_output.join("independent-verifier-report.json"),
        json::MAX_JSON_BYTES,
    )?;
    let report = json::parse_canonical(&report)?;
    let report = report.object()?;
    if json::member(report, "diagnosticCode")?.string()? != diagnostic {
        return Err(format!(
            "independent diagnostic differs for vector {:?}",
            entry.id
        ));
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || usize::try_from(metadata.len()).map_or(true, |size| size > maximum)
    {
        return Err(format!("{} is not a bounded regular file", path.display()));
    }
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(format!("{} changed while being read", path.display()));
    }
    Ok(bytes)
}

fn write_json_new(path: &Path, value: &Value) -> Result<(), String> {
    let bytes = json::canonical(value)?;
    write_bytes_new(path, &bytes)
}

fn write_bytes_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot write {}: {error}", path.display()))
}

fn bounded_diagnostic(error: &str) -> String {
    let mut output = String::new();
    for character in error.chars() {
        if output.len().saturating_add(character.len_utf8()) > MAX_DIAGNOSTIC_BYTES {
            output.push_str("...");
            break;
        }
        output.push(if character.is_control() && character != '\n' {
            '?'
        } else {
            character
        });
    }
    output
}
