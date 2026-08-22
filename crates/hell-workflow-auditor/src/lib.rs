mod mutation;
mod yaml;

pub mod fuzz {
    pub use super::Failure;

    use super::{
        MAX_INPUT_BYTES, expressions, lex_command, validate_command_expressions, validate_json,
        yaml,
    };

    /// A production parser surface exercised directly by the fuzz corpus.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Target {
        WorkflowYamlSubset,
        WorkflowExpression,
        WorkflowRunInvocation,
    }

    /// Exercises one bounded production parser without filesystem or CLI setup.
    ///
    /// # Errors
    ///
    /// Returns the same stable parser failure used by the workflow auditor when
    /// the bytes are outside the accepted language.
    pub fn exercise(target: Target, input: &[u8]) -> Result<(), Failure> {
        let limit = usize::try_from(MAX_INPUT_BYTES).map_err(|_| {
            Failure::new(
                "workflow.input.limit",
                "workflow parser byte limit exceeds the host address space",
            )
        })?;
        if input.len() > limit {
            return Err(Failure::new(
                "workflow.input.oversize",
                "fuzz input exceeds the workflow parser byte limit",
            ));
        }
        match target {
            Target::WorkflowYamlSubset => yaml::parse(input).map(|_| ()),
            Target::WorkflowExpression => {
                let text = std::str::from_utf8(input).map_err(|_| {
                    Failure::new(
                        "workflow.expression.utf8",
                        "workflow expression is not UTF-8",
                    )
                })?;
                expressions(text).map(|_| ())
            }
            Target::WorkflowRunInvocation => {
                validate_json(input, "workflow.run.frame")?;
                let frame: serde_json::Value = serde_json::from_slice(input).map_err(|error| {
                    Failure::new(
                        "workflow.run.frame",
                        format!("cannot parse invocation frame: {error}"),
                    )
                })?;
                let object = frame.as_object().ok_or_else(|| {
                    Failure::new("workflow.run.frame", "invocation frame is not an object")
                })?;
                if object.len() != 2
                    || object
                        .get("schemaVersion")
                        .and_then(serde_json::Value::as_u64)
                        != Some(1)
                    || !object.contains_key("invocation")
                {
                    return Err(Failure::new(
                        "workflow.run.frame",
                        "invocation frame has an unknown schema or key inventory",
                    ));
                }
                let mut canonical = serde_json::to_vec(&frame).map_err(|error| {
                    Failure::new(
                        "workflow.run.frame",
                        format!("cannot canonicalize invocation frame: {error}"),
                    )
                })?;
                canonical.push(b'\n');
                if canonical != input {
                    return Err(Failure::new(
                        "workflow.run.frame",
                        "invocation frame is not canonical JSON with one LF",
                    ));
                }
                let invocation = object
                    .get("invocation")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        Failure::new(
                            "workflow.run.frame",
                            "invocation frame value is not a string",
                        )
                    })?;
                let argv = lex_command(invocation)?;
                validate_command_expressions(&argv)
            }
        }
    }
}

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value as Json};
use yaml::Value as Yaml;

const MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 4096;
const SHA_LENGTH: usize = 40;
const DIGEST_LENGTH: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Failure {
    pub code: &'static str,
    pub message: String,
}

impl Failure {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        let mut message = message.into();
        if message.len() > MAX_DIAGNOSTIC_BYTES {
            message.truncate(MAX_DIAGNOSTIC_BYTES);
        }
        Self { code, message }
    }
}

#[derive(Clone)]
struct Action {
    commit: String,
    inputs: BTreeSet<String>,
    outputs: Vec<String>,
}

#[derive(Default)]
struct AuditCounts {
    workflows: usize,
    jobs: usize,
    steps: usize,
}

struct AuditContext<'a> {
    filename: &'a str,
    actions: &'a BTreeMap<String, Action>,
    approved: &'a BTreeSet<String>,
    permission_profiles: &'a Map<String, Json>,
    caches: &'a mut Vec<CacheUse>,
}

/// Dispatches the semantic workflow-auditor command-line interface.
///
/// # Errors
///
/// Returns a stable failure for invalid arguments or any rejected projection,
/// workflow, action-metadata, or vector input.
pub fn run(arguments: &[OsString]) -> Result<String, Failure> {
    let (command, arguments) = arguments
        .split_first()
        .ok_or_else(|| Failure::new("workflow.cli.usage", usage()))?;
    match command.to_str() {
        Some("audit") => audit_command(arguments),
        Some("verify-vectors") => vectors_command(arguments),
        _ => Err(Failure::new("workflow.cli.usage", usage())),
    }
}

fn audit_command(arguments: &[OsString]) -> Result<String, Failure> {
    let options = Options::parse(
        arguments,
        &[
            "--workflows",
            "--protocol-projection",
            "--action-metadata",
            "--output",
        ],
    )?;
    let workflows = options.path("--workflows")?;
    let projection_path = options.path("--protocol-projection")?;
    let metadata_path = options.path("--action-metadata")?;
    let output = options.path("--output")?;
    let result = audit_paths(
        &workflows,
        &projection_path,
        &metadata_path,
        &BTreeMap::new(),
    );
    let report = match &result {
        Ok(counts) => serde_json::json!({
            "admitted": true,
            "diagnostic": null,
            "jobCount": counts.jobs,
            "schemaVersion": 1,
            "state": "audited",
            "stepCount": counts.steps,
            "workflowCount": counts.workflows,
        }),
        Err(error) => rejection_report(error),
    };
    write_report(&output, &report)?;
    let counts = result?;
    Ok(format!(
        "audited {} workflows, {} jobs, and {} physical steps",
        counts.workflows, counts.jobs, counts.steps
    ))
}

fn vectors_command(arguments: &[OsString]) -> Result<String, Failure> {
    let options = Options::parse(
        arguments,
        &[
            "--manifest",
            "--workflows",
            "--protocol-projection",
            "--action-metadata",
            "--output",
        ],
    )?;
    let manifest_path = options.path("--manifest")?;
    let workflows = options.path("--workflows")?;
    let projection = options.path("--protocol-projection")?;
    let metadata = options.path("--action-metadata")?;
    let output = options.path("--output")?;
    let result = verify_vectors(&manifest_path, &workflows, &projection, &metadata);
    let report = match &result {
        Ok(results) => serde_json::json!({
            "admitted": true,
            "diagnostic": null,
            "schemaVersion": 1,
            "state": "vectors-verified",
            "vectors": results,
        }),
        Err(error) => rejection_report(error),
    };
    write_report(&output, &report)?;
    let results = result?;
    Ok(format!("executed {} typed workflow vectors", results.len()))
}

fn rejection_report(error: &Failure) -> Json {
    serde_json::json!({
        "admitted": false,
        "diagnostic": {"code": error.code, "message": error.message},
        "schemaVersion": 1,
        "state": "rejected",
    })
}

fn audit_paths(
    workflows: &Path,
    projection_path: &Path,
    metadata_path: &Path,
    overrides: &BTreeMap<String, Vec<u8>>,
) -> Result<AuditCounts, Failure> {
    let projection_bytes = read_regular(projection_path, "workflow.projection.input")?;
    let metadata_bytes = read_regular(metadata_path, "workflow.action-metadata.input")?;
    validate_json(&projection_bytes, "workflow.projection.json")?;
    validate_json(&metadata_bytes, "workflow.action-metadata.json")?;
    let projection: Json = serde_json::from_slice(&projection_bytes).map_err(|error| {
        Failure::new(
            "workflow.projection.json",
            format!("cannot parse protocol projection: {error}"),
        )
    })?;
    let metadata: Json = serde_json::from_slice(&metadata_bytes).map_err(|error| {
        Failure::new(
            "workflow.action-metadata.json",
            format!("cannot parse action metadata: {error}"),
        )
    })?;
    let actions = parse_actions(&metadata)?;
    validate_projection_root(&projection, &metadata_bytes, metadata_path)?;
    audit_workflows(workflows, &projection, &actions, overrides)
}

fn validate_projection_root(
    projection: &Json,
    metadata_bytes: &[u8],
    metadata_path: &Path,
) -> Result<(), Failure> {
    let root = object(projection, "workflow.projection.schema")?;
    exact_keys(
        root,
        &[
            "schemaVersion",
            "protocolId",
            "mergeQueue",
            "actionMetadata",
            "readinessSummary",
            "workflows",
            "permissions",
            "approvedCredentialCommands",
        ],
        "workflow.projection.schema",
    )?;
    if unsigned(root, "schemaVersion", "workflow.projection.schema")? != 1 {
        return Err(Failure::new(
            "workflow.projection.schema",
            "protocol projection schemaVersion must be 1",
        ));
    }
    string(root, "protocolId", "workflow.projection.schema")?;
    boolean(root, "mergeQueue", "workflow.projection.schema")?;
    let workflows = array(root, "workflows", "workflow.projection.schema")?;
    if workflows.iter().any(|workflow| {
        object(workflow, "workflow.projection.workflow")
            .ok()
            .and_then(|workflow| workflow.get("jobs"))
            .and_then(Json::as_array)
            .is_none_or(|jobs| {
                jobs.iter().any(|job| {
                    object(job, "workflow.projection.job")
                        .ok()
                        .is_none_or(|job| !job.contains_key("steps"))
                })
            })
    }) {
        return Err(Failure::new(
            "workflow.projection.incomplete",
            "projection does not contain ordered physical steps",
        ));
    }
    let credentials = array(
        root,
        "approvedCredentialCommands",
        "workflow.projection.schema",
    )?;
    if credentials.iter().any(|value| value.as_str().is_none()) {
        return Err(Failure::new(
            "workflow.projection.schema",
            "approved credential commands must be strings",
        ));
    }
    validate_permission_profiles(root)?;
    validate_action_metadata_binding(root, metadata_bytes, metadata_path)?;
    validate_readiness_summary(root)
}

fn validate_permission_profiles(root: &Map<String, Json>) -> Result<(), Failure> {
    let permissions = object_field(root, "permissions", "workflow.projection.schema")?;
    for profile in permissions.values() {
        let grants = object(profile, "workflow.projection.permissions")?;
        exact_keys(
            grants,
            &[
                "actions",
                "artifactMetadata",
                "attestations",
                "contents",
                "idToken",
            ],
            "workflow.projection.permissions",
        )?;
        for value in grants.values() {
            if !matches!(value.as_str(), Some("read" | "write" | "none")) {
                return Err(Failure::new(
                    "workflow.projection.permissions",
                    "permission value must be read, write, or none",
                ));
            }
        }
    }
    Ok(())
}

fn validate_action_metadata_binding(
    root: &Map<String, Json>,
    metadata_bytes: &[u8],
    metadata_path: &Path,
) -> Result<(), Failure> {
    let action = object_field(root, "actionMetadata", "workflow.projection.schema")?;
    exact_keys(
        action,
        &["path", "sha256"],
        "workflow.projection.action-metadata",
    )?;
    let expected_path = string(action, "path", "workflow.projection.action-metadata")?;
    if !metadata_path.ends_with(expected_path) {
        return Err(Failure::new(
            "workflow.action-metadata.path",
            "action metadata path differs from the projection",
        ));
    }
    let expected_digest = string(action, "sha256", "workflow.projection.action-metadata")?;
    require_digest(expected_digest, "workflow.projection.action-metadata")?;
    if protocol_sha256(metadata_bytes) != expected_digest {
        return Err(Failure::new(
            "workflow.action-metadata.digest",
            "action metadata digest differs from the projection",
        ));
    }
    Ok(())
}

fn validate_readiness_summary(root: &Map<String, Json>) -> Result<(), Failure> {
    let summary = object_field(root, "readinessSummary", "workflow.projection.schema")?;
    exact_keys(
        summary,
        &["jobs", "artifacts"],
        "workflow.projection.readiness-summary",
    )?;
    array(summary, "jobs", "workflow.projection.readiness-summary")?;
    for artifact in array(
        summary,
        "artifacts",
        "workflow.projection.readiness-summary",
    )? {
        let artifact = object(artifact, "workflow.projection.readiness-summary")?;
        exact_keys(
            artifact,
            &[
                "job",
                "platformId",
                "inputPath",
                "artifactIdOutput",
                "artifactDigestOutput",
            ],
            "workflow.projection.readiness-summary",
        )?;
        string(artifact, "job", "workflow.projection.readiness-summary")?;
        match artifact.get("platformId") {
            Some(Json::String(_) | Json::Null) => {}
            _ => {
                return Err(Failure::new(
                    "workflow.projection.readiness-summary",
                    "platformId must be a string or null",
                ));
            }
        }
        for key in ["inputPath", "artifactIdOutput", "artifactDigestOutput"] {
            string(artifact, key, "workflow.projection.readiness-summary")?;
        }
    }
    Ok(())
}

fn parse_actions(value: &Json) -> Result<BTreeMap<String, Action>, Failure> {
    let root = object(value, "workflow.action-metadata.schema")?;
    exact_keys(
        root,
        &["schemaVersion", "lockId", "normalization", "actions"],
        "workflow.action-metadata.schema",
    )?;
    if unsigned(root, "schemaVersion", "workflow.action-metadata.schema")? != 1 {
        return Err(Failure::new(
            "workflow.action-metadata.schema",
            "action metadata schemaVersion must be 1",
        ));
    }
    let mut actions = BTreeMap::new();
    for entry in array(root, "actions", "workflow.action-metadata.schema")? {
        let entry = object(entry, "workflow.action-metadata.schema")?;
        exact_keys(
            entry,
            &[
                "id",
                "repository",
                "commitSha",
                "reviewedVersion",
                "normalizedMetadataSha256",
                "inputs",
                "outputs",
                "runtime",
                "projectPermissionClass",
            ],
            "workflow.action-metadata.schema",
        )?;
        let repository = string(entry, "repository", "workflow.action-metadata.schema")?;
        let commit = string(entry, "commitSha", "workflow.action-metadata.schema")?;
        require_sha(commit, "workflow.action-metadata.schema")?;
        let inputs = string_array(entry, "inputs", "workflow.action-metadata.schema")?
            .into_iter()
            .collect();
        let outputs = string_array(entry, "outputs", "workflow.action-metadata.schema")?;
        if actions
            .insert(
                repository.to_owned(),
                Action {
                    commit: commit.to_owned(),
                    inputs,
                    outputs,
                },
            )
            .is_some()
        {
            return Err(Failure::new(
                "workflow.action-metadata.duplicate",
                "action repository is duplicated",
            ));
        }
    }
    Ok(actions)
}

fn audit_workflows(
    workflows_root: &Path,
    projection: &Json,
    actions: &BTreeMap<String, Action>,
    overrides: &BTreeMap<String, Vec<u8>>,
) -> Result<AuditCounts, Failure> {
    let root = object(projection, "workflow.projection.schema")?;
    let declared = array(root, "workflows", "workflow.projection.schema")?;
    let mut expected = BTreeSet::new();
    for workflow in declared {
        let workflow = object(workflow, "workflow.projection.workflow")?;
        exact_keys(
            workflow,
            &[
                "path",
                "name",
                "triggers",
                "concurrency",
                "permissionProfile",
                "jobs",
            ],
            "workflow.projection.workflow",
        )?;
        if !workflow.contains_key("jobs")
            || array(workflow, "jobs", "workflow.projection.workflow")?
                .iter()
                .any(|job| {
                    object(job, "workflow.projection.job").is_ok_and(|v| !v.contains_key("steps"))
                })
        {
            return Err(Failure::new(
                "workflow.projection.incomplete",
                "projection does not contain ordered physical steps",
            ));
        }
        let path = string(workflow, "path", "workflow.projection.workflow")?;
        let name = Path::new(path)
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| Failure::new("workflow.projection.path", "invalid workflow path"))?;
        if !expected.insert(name.to_owned()) {
            return Err(Failure::new(
                "workflow.projection.path",
                "workflow path is duplicated",
            ));
        }
    }
    let observed = workflow_inventory(workflows_root)?;
    if observed != expected {
        return Err(Failure::new(
            "workflow.inventory.exact",
            "workflow exact file inventory differs from the projection",
        ));
    }
    let approved = string_array(
        root,
        "approvedCredentialCommands",
        "workflow.projection.schema",
    )?
    .into_iter()
    .collect::<BTreeSet<_>>();
    let permission_profiles = object_field(root, "permissions", "workflow.projection.schema")?;
    let mut counts = AuditCounts::default();
    let mut caches = Vec::new();
    for workflow in declared {
        let projected = object(workflow, "workflow.projection.workflow")?;
        let path = string(projected, "path", "workflow.projection.workflow")?;
        let filename = Path::new(path)
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| Failure::new("workflow.projection.path", "invalid workflow path"))?;
        let bytes = if let Some(bytes) = overrides.get(filename) {
            bytes.clone()
        } else {
            read_regular(&workflows_root.join(filename), "workflow.input")?
        };
        let document = yaml::parse(&bytes)?;
        let mut context = AuditContext {
            filename,
            actions,
            approved: &approved,
            permission_profiles,
            caches: &mut caches,
        };
        let workflow_counts = audit_document(&document, projected, &mut context)?;
        counts.workflows += 1;
        counts.jobs += workflow_counts.0;
        counts.steps += workflow_counts.1;
    }
    validate_cache_pairs(&caches)?;
    Ok(counts)
}

fn workflow_inventory(root: &Path) -> Result<BTreeSet<String>, Failure> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(root).map_err(|error| {
        Failure::new(
            "workflow.inventory.read",
            format!("cannot enumerate workflow directory: {error}"),
        )
    })? {
        let entry = entry.map_err(|error| {
            Failure::new(
                "workflow.inventory.read",
                format!("cannot inspect workflow entry: {error}"),
            )
        })?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            Failure::new(
                "workflow.inventory.read",
                format!("cannot inspect workflow metadata: {error}"),
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Failure::new(
                "workflow.inventory.entry",
                "workflow directory contains a linked or non-regular entry",
            ));
        }
        let name = entry.file_name().into_string().map_err(|_| {
            Failure::new("workflow.inventory.utf8", "workflow filename is not UTF-8")
        })?;
        names.insert(name);
    }
    Ok(names)
}

fn audit_document(
    document: &Yaml,
    projected: &Map<String, Json>,
    context: &mut AuditContext<'_>,
) -> Result<(usize, usize), Failure> {
    let root = document.map("workflow.yaml.root")?;
    if root.contains_key("env") {
        return Err(Failure::new(
            "workflow.environment.custom",
            format!("{}: workflow-level env is forbidden", context.filename),
        ));
    }
    compare_scalar(root, "name", projected, "name", "workflow.generated.drift")?;
    validate_profile(
        root.get("permissions"),
        projected,
        context.permission_profiles,
        "workflow.permission.exact",
    )?;
    validate_concurrency(root, projected, context.filename)?;
    validate_triggers(root, projected, context.filename)?;
    let jobs = required_yaml_map(root, "jobs", "workflow.jobs")?;
    let projected_jobs = array(projected, "jobs", "workflow.projection.workflow")?;
    let projected_ids = projected_jobs
        .iter()
        .map(|job| {
            let job = object(job, "workflow.projection.job")?;
            Ok(string(job, "id", "workflow.projection.job")?.to_owned())
        })
        .collect::<Result<Vec<_>, Failure>>()?;
    if jobs.keys().cloned().collect::<BTreeSet<_>>()
        != projected_ids.iter().cloned().collect::<BTreeSet<_>>()
        || jobs.len() != projected_ids.len()
    {
        return Err(Failure::new(
            "workflow.job.inventory",
            format!(
                "{}: exact job ID inventory differs from projection",
                context.filename
            ),
        ));
    }
    validate_graph(jobs)?;
    let mut steps_count = 0;
    for projected_job in projected_jobs {
        let projected_job = object(projected_job, "workflow.projection.job")?;
        steps_count += audit_job(root, jobs, projected_job, context)?;
    }
    validate_privilege_split(context.filename, root, jobs)?;
    Ok((jobs.len(), steps_count))
}

fn audit_job(
    root: &BTreeMap<String, Yaml>,
    jobs: &BTreeMap<String, Yaml>,
    projected: &Map<String, Json>,
    context: &mut AuditContext<'_>,
) -> Result<usize, Failure> {
    exact_keys(
        projected,
        &[
            "id",
            "name",
            "needs",
            "runsOn",
            "timeoutMinutes",
            "condition",
            "permissionProfile",
            "outputs",
            "steps",
        ],
        "workflow.projection.job",
    )?;
    let id = string(projected, "id", "workflow.projection.job")?;
    let job = jobs
        .get(id)
        .ok_or_else(|| Failure::new("workflow.job.inventory", "projected job is absent"))?
        .map("workflow.job.schema")?;
    if job.contains_key("env") {
        return Err(Failure::new(
            "workflow.environment.custom",
            format!("{}/{id}: job-level env is forbidden", context.filename),
        ));
    }
    compare_scalar(job, "name", projected, "name", "workflow.job.name")?;
    compare_scalar(job, "runs-on", projected, "runsOn", "workflow.job.runner")?;
    compare_unsigned(
        job,
        "timeout-minutes",
        projected,
        "timeoutMinutes",
        "workflow.job.timeout",
    )?;
    compare_optional_scalar(
        job.get("if"),
        projected.get("condition"),
        if id == "summary" {
            "workflow.summary.cancellation"
        } else {
            "workflow.job.condition"
        },
    )?;
    compare_needs(
        job.get("needs"),
        projected,
        id,
        if id == "summary" {
            "workflow.summary.graph"
        } else {
            "workflow.graph.needs"
        },
    )?;
    compare_yaml_map_to_json(
        job.get("outputs"),
        projected.get("outputs"),
        "workflow.job.outputs",
    )?;
    validate_profile(
        job.get("permissions").or_else(|| root.get("permissions")),
        projected,
        context.permission_profiles,
        if context.filename == "release.yml" && id == "attest" {
            "workflow.permission.attest"
        } else if context.filename == "release.yml" && id == "publish" {
            "workflow.permission.publish"
        } else {
            "workflow.permission.exact"
        },
    )?;
    let steps = required_yaml_sequence(job, "steps", "workflow.step.inventory")?;
    let projected_steps = array(projected, "steps", "workflow.projection.job")?;
    if steps.len() != projected_steps.len() {
        return Err(Failure::new(
            "workflow.step.inventory",
            format!(
                "{}/{id}: physical step count differs from projection",
                context.filename
            ),
        ));
    }
    for (index, (step, projected_step)) in steps.iter().zip(projected_steps).enumerate() {
        audit_step(
            id,
            index,
            step.map("workflow.step.schema")?,
            object(projected_step, "workflow.projection.step")?,
            context,
        )?;
    }
    Ok(steps.len())
}

fn audit_step(
    job_id: &str,
    index: usize,
    step: &BTreeMap<String, Yaml>,
    projected: &Map<String, Json>,
    context: &mut AuditContext<'_>,
) -> Result<(), Failure> {
    if step.contains_key("shell") {
        return Err(Failure::new(
            "workflow.shell.explicit",
            format!(
                "{}/{job_id}/step-{index}: explicit shell is forbidden",
                context.filename
            ),
        ));
    }
    if step.contains_key("uses") == step.contains_key("run") {
        return Err(Failure::new(
            "workflow.step.kind",
            format!(
                "{}/{job_id}/step-{index}: step must have exactly one of uses or run",
                context.filename
            ),
        ));
    }
    compare_scalar(step, "name", projected, "name", "workflow.step.name")?;
    compare_nullable_yaml_scalar(step.get("id"), projected.get("stepId"), "workflow.step.id")?;
    compare_nullable_yaml_scalar(
        step.get("if"),
        projected.get("condition"),
        "workflow.step.condition",
    )?;
    if step.contains_key("run") {
        audit_command_step(job_id, step, projected, context.approved)?;
    } else {
        audit_action_step(step, projected, context)?;
    }
    Ok(())
}

fn audit_command_step(
    job_id: &str,
    step: &BTreeMap<String, Yaml>,
    projected: &Map<String, Json>,
    approved: &BTreeSet<String>,
) -> Result<(), Failure> {
    exact_keys(
        projected,
        &["name", "stepId", "condition", "kind", "ref", "command"],
        "workflow.projection.step",
    )?;
    if string(projected, "kind", "workflow.projection.step")? != "command" {
        return Err(Failure::new(
            "workflow.step.kind",
            "projected step kind differs from physical command step",
        ));
    }
    let run = required_yaml_scalar(step, "run", "workflow.run.scalar")?;
    let argv = lex_command(run)?;
    validate_command_expressions(&argv)?;
    if job_id == "publish"
        && (run.contains("release final-verify")
            || run.contains("verify-bundle")
            || run.contains("conformance"))
    {
        return Err(Failure::new(
            "workflow.privilege.deep-parser",
            "privileged publish job invokes a deep verifier",
        ));
    }
    let executable = argv
        .first()
        .ok_or_else(|| Failure::new("workflow.run.empty", "command step is empty"))?;
    if string(projected, "ref", "workflow.projection.step")? != executable {
        return Err(Failure::new(
            "workflow.command.executable",
            "command executable differs from projected ref",
        ));
    }
    let command = object_field(projected, "command", "workflow.projection.step")?;
    exact_keys(
        command,
        &[
            "executable",
            "argv",
            "credential",
            "environment",
            "workingDirectory",
        ],
        "workflow.projection.command",
    )?;
    if string(command, "executable", "workflow.projection.command")? != executable
        || string_array(command, "argv", "workflow.projection.command")? != argv
    {
        return Err(Failure::new(
            "workflow.command.argv",
            "command executable or typed argv differs from projection",
        ));
    }
    compare_nullable_yaml_scalar(
        step.get("working-directory"),
        command.get("workingDirectory"),
        "workflow.command.working-directory",
    )?;
    validate_environment(step.get("env"), command, executable, approved)
}

fn audit_action_step(
    step: &BTreeMap<String, Yaml>,
    projected: &Map<String, Json>,
    context: &mut AuditContext<'_>,
) -> Result<(), Failure> {
    exact_keys(
        projected,
        &[
            "name",
            "stepId",
            "condition",
            "kind",
            "ref",
            "action",
            "cache",
            "artifact",
            "attestation",
        ],
        "workflow.projection.step",
    )?;
    if string(projected, "kind", "workflow.projection.step")? != "action" {
        return Err(Failure::new(
            "workflow.step.kind",
            "projected step kind differs from physical action step",
        ));
    }
    if step.contains_key("env") {
        return Err(Failure::new(
            "workflow.environment.custom",
            "action steps may not define environment variables",
        ));
    }
    let uses = required_yaml_scalar(step, "uses", "workflow.action.uses")?;
    let step_id = step
        .get("id")
        .map(|value| value.scalar("workflow.step.id"))
        .transpose()?;
    validate_action(
        step,
        uses,
        step_id,
        context.filename,
        projected,
        context.actions,
        context.caches,
    )
}

fn validate_action(
    step: &BTreeMap<String, Yaml>,
    uses: &str,
    step_id: Option<&str>,
    filename: &str,
    projected: &Map<String, Json>,
    actions: &BTreeMap<String, Action>,
    caches: &mut Vec<CacheUse>,
) -> Result<(), Failure> {
    let (repository, commit) = uses.split_once('@').ok_or_else(|| {
        Failure::new(
            "workflow.action.unpinned",
            "action reference lacks a commit separator",
        )
    })?;
    require_sha(commit, "workflow.action.unpinned")?;
    let metadata = actions.get(repository).ok_or_else(|| {
        Failure::new(
            "workflow.action.unknown",
            format!("action {repository:?} is absent from reviewed metadata"),
        )
    })?;
    if metadata.commit != commit {
        return Err(Failure::new(
            "workflow.action.pin-mismatch",
            format!("action {repository:?} commit differs from reviewed metadata"),
        ));
    }
    if string(projected, "ref", "workflow.projection.step")? != uses {
        return Err(Failure::new(
            "workflow.action.ref",
            "action reference differs from projected ref",
        ));
    }
    let action = object_field(projected, "action", "workflow.projection.step")?;
    exact_keys(
        action,
        &["uses", "with", "outputs"],
        "workflow.projection.action",
    )?;
    if string(action, "uses", "workflow.projection.action")? != uses {
        return Err(Failure::new(
            "workflow.action.ref",
            "action reference differs from projection",
        ));
    }
    let with = optional_yaml_map(step.get("with"), "workflow.action.with")?;
    for key in with.keys() {
        if !metadata.inputs.contains(key) {
            return Err(Failure::new(
                "workflow.action.input",
                format!("action {repository:?} has unreviewed input {key:?}"),
            ));
        }
    }
    match repository {
        "actions/upload-artifact" => validate_upload(&with, step_id, filename, projected)?,
        "actions/download-artifact" => validate_download(&with, projected)?,
        _ => {}
    }
    compare_yaml_map_to_json(step.get("with"), action.get("with"), "workflow.action.with")?;
    if string_array(action, "outputs", "workflow.projection.action")? != metadata.outputs {
        return Err(Failure::new(
            "workflow.action.outputs",
            format!("action {repository:?} projected outputs differ from reviewed metadata"),
        ));
    }
    match repository {
        "actions/checkout" => {
            if yaml_map_scalar(&with, "persist-credentials") != Some("false") {
                return Err(Failure::new(
                    "workflow.credential.persistence",
                    "checkout must explicitly disable credential persistence",
                ));
            }
            require_no_action_semantics(projected)?;
        }
        "actions/upload-artifact" | "actions/download-artifact" => {}
        "actions/cache/restore" => {
            caches.push(cache_use("restore", &with)?);
            validate_cache_projection("restore", &with, projected)?;
        }
        "actions/cache/save" => {
            caches.push(cache_use("save", &with)?);
            validate_cache_projection("save", &with, projected)?;
        }
        "actions/attest" => validate_attestation(&with, step_id, projected)?,
        _ => require_no_action_semantics(projected)?,
    }
    Ok(())
}

fn require_no_action_semantics(projected: &Map<String, Json>) -> Result<(), Failure> {
    for key in ["cache", "artifact", "attestation"] {
        require_null(projected, key, "workflow.projection.action")?;
    }
    Ok(())
}

fn validate_upload(
    with: &BTreeMap<String, Yaml>,
    step_id: Option<&str>,
    filename: &str,
    projected: &Map<String, Json>,
) -> Result<(), Failure> {
    let missing_policy = yaml_map_scalar(with, "if-no-files-found");
    if (filename != "nightly.yml" && missing_policy != Some("error"))
        || (filename == "nightly.yml" && !matches!(missing_policy, Some("error" | "ignore")))
    {
        return Err(Failure::new(
            "workflow.artifact.missing-policy",
            "artifact upload must fail when files are missing",
        ));
    }
    let artifact =
        required_projected_object(projected, "artifact", "workflow.projection.artifact")?;
    exact_keys(
        artifact,
        &[
            "mode",
            "artifactId",
            "name",
            "path",
            "digest",
            "missingPolicy",
            "condition",
        ],
        "workflow.projection.artifact",
    )?;
    if string(artifact, "mode", "workflow.projection.artifact")? != "upload" {
        return Err(Failure::new(
            "workflow.projection.artifact",
            "upload step projection has the wrong artifact mode",
        ));
    }
    let digest =
        step_id.map(|step_id| format!("${{{{ steps.{step_id}.outputs.artifact-digest }}}}"));
    require_null(artifact, "artifactId", "workflow.projection.artifact")?;
    compare_yaml_semantic_string(
        with,
        "name",
        artifact,
        "name",
        "workflow.projection.artifact",
    )?;
    compare_yaml_semantic_string(
        with,
        "path",
        artifact,
        "path",
        "workflow.projection.artifact",
    )?;
    compare_nullable_string(
        digest.as_deref(),
        artifact.get("digest"),
        "workflow.projection.artifact",
    )?;
    compare_yaml_semantic_string(
        with,
        "if-no-files-found",
        artifact,
        "missingPolicy",
        "workflow.projection.artifact",
    )?;
    compare_json_fields(
        projected,
        "condition",
        artifact,
        "condition",
        "workflow.projection.artifact",
    )?;
    require_null(projected, "cache", "workflow.projection.action")?;
    require_null(projected, "attestation", "workflow.projection.action")
}

fn validate_download(
    with: &BTreeMap<String, Yaml>,
    projected: &Map<String, Json>,
) -> Result<(), Failure> {
    if with.contains_key("name")
        || with.contains_key("pattern")
        || !with.contains_key("artifact-ids")
    {
        return Err(Failure::new(
            "workflow.artifact.selection",
            "acceptance-critical downloads must select an artifact ID",
        ));
    }
    if yaml_map_scalar(with, "digest-mismatch") != Some("error") {
        return Err(Failure::new(
            "workflow.artifact.digest-policy",
            "artifact download must fail on a digest mismatch",
        ));
    }
    let artifact =
        required_projected_object(projected, "artifact", "workflow.projection.artifact")?;
    exact_keys(
        artifact,
        &[
            "mode",
            "artifactId",
            "name",
            "path",
            "digest",
            "missingPolicy",
            "condition",
        ],
        "workflow.projection.artifact",
    )?;
    if string(artifact, "mode", "workflow.projection.artifact")? != "download" {
        return Err(Failure::new(
            "workflow.projection.artifact",
            "download step projection has the wrong artifact mode",
        ));
    }
    let artifact_id = yaml_map_scalar(with, "artifact-ids").ok_or_else(|| {
        Failure::new(
            "workflow.artifact.selection",
            "artifact download lacks its exact artifact ID expression",
        )
    })?;
    let digest = artifact_id
        .strip_suffix("_id }}")
        .map(|prefix| {
            let mut digest = prefix.to_owned();
            digest.push_str("_digest }}");
            digest
        })
        .ok_or_else(|| {
            Failure::new(
                "workflow.artifact.digest-binding",
                "artifact ID expression has no paired digest output",
            )
        })?;
    compare_nullable_string(
        Some(artifact_id),
        artifact.get("artifactId"),
        "workflow.projection.artifact",
    )?;
    require_null(artifact, "name", "workflow.projection.artifact")?;
    compare_yaml_semantic_string(
        with,
        "path",
        artifact,
        "path",
        "workflow.projection.artifact",
    )?;
    compare_nullable_string(
        Some(digest.as_str()),
        artifact.get("digest"),
        "workflow.projection.artifact",
    )?;
    require_null(artifact, "missingPolicy", "workflow.projection.artifact")?;
    compare_json_fields(
        projected,
        "condition",
        artifact,
        "condition",
        "workflow.projection.artifact",
    )?;
    require_null(projected, "cache", "workflow.projection.action")?;
    require_null(projected, "attestation", "workflow.projection.action")
}

fn validate_attestation(
    with: &BTreeMap<String, Yaml>,
    step_id: Option<&str>,
    projected: &Map<String, Json>,
) -> Result<(), Failure> {
    if !with.contains_key("subject-checksums")
        || with.contains_key("predicate-path") != with.contains_key("predicate-type")
    {
        return Err(Failure::new(
            "workflow.attestation.inputs",
            "attestation must bind checksums and pair predicate path with predicate type",
        ));
    }
    let attestation =
        required_projected_object(projected, "attestation", "workflow.projection.attestation")?;
    exact_keys(
        attestation,
        &[
            "predicatePath",
            "predicateType",
            "subjectChecksums",
            "bundleOutput",
        ],
        "workflow.projection.attestation",
    )?;
    compare_yaml_optional_semantic_string(
        with,
        "predicate-path",
        attestation,
        "predicatePath",
        "workflow.projection.attestation",
    )?;
    compare_yaml_optional_semantic_string(
        with,
        "predicate-type",
        attestation,
        "predicateType",
        "workflow.projection.attestation",
    )?;
    compare_yaml_semantic_string(
        with,
        "subject-checksums",
        attestation,
        "subjectChecksums",
        "workflow.projection.attestation",
    )?;
    let step_id = step_id.ok_or_else(|| {
        Failure::new(
            "workflow.attestation.output",
            "attestation action must have a step ID for bundle provenance",
        )
    })?;
    let bundle = format!("${{{{ steps.{step_id}.outputs.bundle-path }}}}");
    compare_nullable_string(
        Some(bundle.as_str()),
        attestation.get("bundleOutput"),
        "workflow.projection.attestation",
    )?;
    require_null(projected, "cache", "workflow.projection.action")?;
    require_null(projected, "artifact", "workflow.projection.action")
}

fn validate_cache_projection(
    mode: &str,
    with: &BTreeMap<String, Yaml>,
    projected: &Map<String, Json>,
) -> Result<(), Failure> {
    let cache = required_projected_object(projected, "cache", "workflow.projection.cache")?;
    exact_keys(
        cache,
        &["mode", "paths", "key", "condition"],
        "workflow.projection.cache",
    )?;
    if string(cache, "mode", "workflow.projection.cache")? != mode
        || string(cache, "key", "workflow.projection.cache")?
            != yaml_map_scalar(with, "key").unwrap_or_default()
    {
        return Err(Failure::new(
            "workflow.cache.projection",
            "cache mode or key differs from projection",
        ));
    }
    let paths = yaml_map_scalar(with, "path")
        .ok_or_else(|| Failure::new("workflow.cache.path", "cache step lacks a path"))?
        .lines()
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if string_array(cache, "paths", "workflow.projection.cache")? != paths {
        return Err(Failure::new(
            "workflow.cache.projection",
            "cache paths differ from projection",
        ));
    }
    compare_json_fields(
        projected,
        "condition",
        cache,
        "condition",
        "workflow.projection.cache",
    )?;
    require_null(projected, "artifact", "workflow.projection.action")?;
    require_null(projected, "attestation", "workflow.projection.action")
}

#[derive(Clone)]
struct CacheUse {
    mode: &'static str,
    key: String,
    paths: String,
}

fn cache_use(mode: &'static str, with: &BTreeMap<String, Yaml>) -> Result<CacheUse, Failure> {
    let key = yaml_map_scalar(with, "key")
        .ok_or_else(|| Failure::new("workflow.cache.key", "cache step lacks a key"))?;
    let paths = yaml_map_scalar(with, "path")
        .ok_or_else(|| Failure::new("workflow.cache.path", "cache step lacks a path"))?;
    Ok(CacheUse {
        mode,
        key: key.to_owned(),
        paths: paths.to_owned(),
    })
}

fn validate_cache_pairs(caches: &[CacheUse]) -> Result<(), Failure> {
    for cache in caches {
        let opposite = if cache.mode == "restore" {
            "save"
        } else {
            "restore"
        };
        if !caches.iter().any(|candidate| {
            candidate.mode == opposite
                && candidate.key == cache.key
                && candidate.paths == cache.paths
        }) {
            return Err(Failure::new(
                "workflow.cache.pair",
                "cache restore/save key and path pairing is incomplete",
            ));
        }
    }
    Ok(())
}

fn validate_environment(
    environment: Option<&Yaml>,
    projected: &Map<String, Json>,
    executable: &str,
    approved: &BTreeSet<String>,
) -> Result<(), Failure> {
    let observed = optional_yaml_map(environment, "workflow.environment.custom")?;
    for (name, value) in &observed {
        if let Ok(value) = value.scalar("workflow.environment.custom")
            && (value.contains("${{ secrets.") || value.contains("${{ vars."))
            && !(name == "GITHUB_TOKEN" && value == "${{ github.token }}")
        {
            return Err(Failure::new(
                "workflow.expression.secret",
                "unapproved secret or variable expression appears in step environment",
            ));
        }
    }
    if !observed.is_empty()
        && (observed.len() != 1
            || yaml_map_scalar(&observed, "GITHUB_TOKEN") != Some("${{ github.token }}")
            || !approved.contains(executable))
    {
        return Err(Failure::new(
            "workflow.environment.custom",
            "only projected GITHUB_TOKEN on an approved executable is allowed",
        ));
    }
    let projected_environment =
        object_field(projected, "environment", "workflow.projection.command")?;
    compare_yaml_map_and_json_map(
        &observed,
        projected_environment,
        "workflow.environment.exact",
    )?;
    let credential = string(projected, "credential", "workflow.projection.command")?;
    if observed.is_empty() {
        if credential != "none" {
            return Err(Failure::new(
                "workflow.credential.projection",
                "credential projection differs from empty step environment",
            ));
        }
        return Ok(());
    }
    if credential != "github-token" {
        return Err(Failure::new(
            "workflow.credential.projection",
            "credential projection differs from the admitted GitHub token",
        ));
    }
    Ok(())
}

fn lex_command(command: &str) -> Result<Vec<String>, Failure> {
    if command.contains(['\n', '\r']) {
        return Err(Failure::new(
            "workflow.run.multiline",
            "run step must contain one physical line",
        ));
    }
    let characters = command.char_indices().collect::<Vec<_>>();
    let mut argv = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    let mut expression_depth = 0_u8;
    let mut index = 0;
    while index < characters.len() {
        let (position, character) = characters[index];
        let next = characters.get(index + 1).map(|entry| entry.1);
        if quote.is_none() && expression_depth == 0 && character == '$' && next == Some('{') {
            let after = characters.get(index + 2).map(|entry| entry.1);
            if after == Some('{') {
                expression_depth = 1;
                token.push_str("${{");
                index += 3;
                continue;
            }
        }
        if expression_depth == 1 && character == '}' && next == Some('}') {
            expression_depth = 0;
            token.push_str("}}");
            index += 2;
            continue;
        }
        if expression_depth == 0 {
            match quote {
                Some(delimiter) if character == delimiter => {
                    quote = None;
                    index += 1;
                    continue;
                }
                None if matches!(character, '\'' | '"') => {
                    quote = Some(character);
                    index += 1;
                    continue;
                }
                None if character.is_whitespace() => {
                    if !token.is_empty() {
                        argv.push(std::mem::take(&mut token));
                    }
                    index += 1;
                    continue;
                }
                None if matches!(character, ';' | '|' | '`')
                    || (quote.is_none() && character == '&' && next == Some('&'))
                    || (quote.is_none() && character == '$' && next == Some('(')) =>
                {
                    return Err(Failure::new(
                        "workflow.run.multiple-invocations",
                        format!("shell operator at byte {position} is forbidden"),
                    ));
                }
                _ => {}
            }
        }
        token.push(character);
        index += 1;
    }
    if quote.is_some() || expression_depth != 0 {
        return Err(Failure::new(
            "workflow.run.lexer",
            "command contains an unterminated quote or expression",
        ));
    }
    if !token.is_empty() {
        argv.push(token);
    }
    if argv.is_empty() {
        return Err(Failure::new(
            "workflow.run.empty",
            "command has no executable",
        ));
    }
    Ok(argv)
}

fn validate_command_expressions(argv: &[String]) -> Result<(), Failure> {
    for argument in argv {
        for expression in expressions(argument)? {
            if expression.starts_with("inputs.") || expression.contains(" inputs.") {
                return Err(Failure::new(
                    "workflow.expression.untrusted-input",
                    "untrusted workflow input appears in command argv",
                ));
            }
            if expression.starts_with("secrets.")
                || expression.starts_with("vars.")
                || expression.contains(" secrets.")
                || expression.contains(" vars.")
            {
                return Err(Failure::new(
                    "workflow.expression.secret",
                    "secret or variable expression appears in command argv",
                ));
            }
            if !(expression.starts_with("needs.")
                || expression.starts_with("steps.")
                || expression.starts_with("github.")
                || expression.starts_with("matrix."))
            {
                return Err(Failure::new(
                    "workflow.expression.unapproved",
                    "command expression is outside the approved output contexts",
                ));
            }
        }
    }
    Ok(())
}

fn expressions(text: &str) -> Result<Vec<&str>, Failure> {
    let mut values = Vec::new();
    let mut remainder = text;
    while let Some((_, after)) = remainder.split_once("${{") {
        let Some((expression, tail)) = after.split_once("}}") else {
            return Err(Failure::new(
                "workflow.expression.syntax",
                "expression lacks a closing delimiter",
            ));
        };
        values.push(expression.trim());
        remainder = tail;
    }
    Ok(values)
}

fn validate_triggers(
    root: &BTreeMap<String, Yaml>,
    projected: &Map<String, Json>,
    filename: &str,
) -> Result<(), Failure> {
    let observed = required_yaml_map(root, "on", "workflow.trigger.schema")?;
    let expected = array(projected, "triggers", "workflow.projection.workflow")?;
    let expected_events = expected
        .iter()
        .map(|entry| {
            let entry = object(entry, "workflow.projection.trigger")?;
            exact_keys(
                entry,
                &["event", "branches", "tags", "paths", "dispatchInputs"],
                "workflow.projection.trigger",
            )?;
            Ok(string(entry, "event", "workflow.projection.trigger")?.to_owned())
        })
        .collect::<Result<BTreeSet<_>, Failure>>()?;
    if observed.contains_key("merge_group") && !expected_events.contains("merge_group") {
        return Err(Failure::new(
            "workflow.trigger.merge-group",
            "merge_group trigger is present while merge queue is disabled",
        ));
    }
    if observed.keys().cloned().collect::<BTreeSet<_>>() != expected_events {
        return Err(Failure::new(
            "workflow.trigger.exact",
            format!("{filename}: trigger inventory differs from projection"),
        ));
    }
    for projected_trigger in expected {
        let projected_trigger = object(projected_trigger, "workflow.projection.trigger")?;
        let event = string(projected_trigger, "event", "workflow.projection.trigger")?;
        let configuration = observed
            .get(event)
            .ok_or_else(|| Failure::new("workflow.trigger.exact", "projected trigger is absent"))?;
        let mapping = match configuration {
            Yaml::Map(mapping) => mapping,
            Yaml::Scalar(value) if value == "null" => &BTreeMap::new(),
            _ => {
                return Err(Failure::new(
                    "workflow.trigger.schema",
                    "trigger configuration is not a mapping",
                ));
            }
        };
        for (yaml_key, json_key) in [
            ("branches", "branches"),
            ("tags", "tags"),
            ("paths", "paths"),
        ] {
            let observed_values = yaml_string_list(mapping.get(yaml_key))?;
            let expected_values =
                string_array(projected_trigger, json_key, "workflow.projection.trigger")?;
            if observed_values != expected_values {
                return Err(Failure::new(
                    "workflow.trigger.exact",
                    format!("{filename}: trigger {event:?} {yaml_key} differ from projection"),
                ));
            }
        }
        compare_yaml_map_to_json(
            mapping.get("inputs"),
            projected_trigger.get("dispatchInputs"),
            "workflow.trigger.dispatch-inputs",
        )?;
    }
    Ok(())
}

fn validate_concurrency(
    root: &BTreeMap<String, Yaml>,
    projected: &Map<String, Json>,
    filename: &str,
) -> Result<(), Failure> {
    let observed = required_yaml_map(root, "concurrency", "workflow.concurrency.schema")?;
    let expected = object_field(projected, "concurrency", "workflow.projection.workflow")?;
    exact_keys(
        expected,
        &["group", "cancelInProgress"],
        "workflow.projection.concurrency",
    )?;
    let observed_cancel = required_yaml_scalar(
        observed,
        "cancel-in-progress",
        "workflow.concurrency.cancel",
    )?;
    if filename == "release.yml" && observed_cancel != "false" {
        return Err(Failure::new(
            "workflow.concurrency.release",
            "release workflow must not cancel an in-flight release",
        ));
    }
    if filename.starts_with("regression-") {
        let group = required_yaml_scalar(observed, "group", "workflow.concurrency.scope")?;
        if !group.contains("github.ref") {
            return Err(Failure::new(
                "workflow.concurrency.scope",
                "regression concurrency must remain ref-scoped",
            ));
        }
    }
    if observed_cancel.parse::<bool>().ok()
        != expected.get("cancelInProgress").and_then(Json::as_bool)
    {
        return Err(Failure::new(
            "workflow.concurrency.exact",
            format!("{filename}: cancellation policy differs from projection"),
        ));
    }
    compare_scalar(
        observed,
        "group",
        expected,
        "group",
        "workflow.concurrency.group",
    )?;
    Ok(())
}

fn validate_graph(jobs: &BTreeMap<String, Yaml>) -> Result<(), Failure> {
    let ids = jobs.keys().cloned().collect::<BTreeSet<_>>();
    let mut dependencies = BTreeMap::<String, Vec<String>>::new();
    for (id, job) in jobs {
        let job = job.map("workflow.job.schema")?;
        let needs = yaml_string_list(job.get("needs"))?;
        if needs.iter().any(|need| !ids.contains(need)) {
            return Err(Failure::new(
                "workflow.graph.missing-need",
                format!("job {id:?} needs an unknown job"),
            ));
        }
        dependencies.insert(id.clone(), needs);
    }
    for id in jobs.keys() {
        let mut visiting = BTreeSet::new();
        visit_job(id, &dependencies, &mut visiting, &mut BTreeSet::new())?;
    }
    Ok(())
}

fn visit_job(
    id: &str,
    dependencies: &BTreeMap<String, Vec<String>>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
) -> Result<(), Failure> {
    if visited.contains(id) {
        return Ok(());
    }
    if !visiting.insert(id.to_owned()) {
        return Err(Failure::new(
            "workflow.graph.cycle",
            "workflow needs graph contains a cycle",
        ));
    }
    if let Some(needs) = dependencies.get(id) {
        for need in needs {
            visit_job(need, dependencies, visiting, visited)?;
        }
    }
    visiting.remove(id);
    visited.insert(id.to_owned());
    Ok(())
}

fn validate_privilege_split(
    filename: &str,
    root: &BTreeMap<String, Yaml>,
    jobs: &BTreeMap<String, Yaml>,
) -> Result<(), Failure> {
    if filename != "release.yml" {
        return Ok(());
    }
    for (id, value) in jobs {
        let job = value.map("workflow.job.schema")?;
        let permissions = job
            .get("permissions")
            .or_else(|| root.get("permissions"))
            .ok_or_else(|| {
                Failure::new(
                    "workflow.permission.release",
                    "release job lacks permissions",
                )
            })?
            .map("workflow.permission.release")?;
        let contents = yaml_map_scalar(permissions, "contents").unwrap_or("none");
        let attestations = yaml_map_scalar(permissions, "attestations").unwrap_or("none");
        let id_token = yaml_map_scalar(permissions, "id-token").unwrap_or("none");
        if id == "attest" {
            let exact_profile =
                contents == "read" && attestations == "write" && id_token == "write";
            let selected_mutant = contents == "write"
                && attestations == "write"
                && id_token == "write"
                && mutation::active(mutation::Mutant::GrantContentsWriteToAttest);
            if !exact_profile && !selected_mutant {
                return Err(Failure::new(
                    "workflow.permission.attest",
                    "attest job has permissions outside its exact privilege profile",
                ));
            }
        } else if id == "publish" {
            let exact_profile =
                contents == "write" && attestations != "write" && id_token != "write";
            let selected_mutant = contents == "write"
                && attestations != "write"
                && id_token == "write"
                && mutation::active(mutation::Mutant::GrantIdTokenWriteToPublish);
            if !exact_profile && !selected_mutant {
                return Err(Failure::new(
                    "workflow.permission.publish",
                    "publish job has permissions outside its exact privilege profile",
                ));
            }
        } else if contents == "write" || attestations == "write" || id_token == "write" {
            return Err(Failure::new(
                "workflow.permission.release",
                format!("release job {id:?} has privileged write permission"),
            ));
        }
        if matches!(id.as_str(), "attest" | "publish") {
            let steps = required_yaml_sequence(job, "steps", "workflow.step.inventory")?;
            for step in steps {
                let step = step.map("workflow.step.schema")?;
                if let Some(run) = step.get("run") {
                    let run = run.scalar("workflow.run.scalar")?;
                    if run.contains("hell-ci release final-verify")
                        || run.contains("readiness platform")
                        || run.contains("conformance")
                    {
                        return Err(Failure::new(
                            "workflow.privilege.deep-parser",
                            "privileged job invokes a deep candidate parser",
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_profile(
    observed: Option<&Yaml>,
    projected: &Map<String, Json>,
    profiles: &Map<String, Json>,
    code: &'static str,
) -> Result<(), Failure> {
    let profile = string(
        projected,
        "permissionProfile",
        "workflow.projection.permissions",
    )?;
    let expected = profiles.get(profile).ok_or_else(|| {
        Failure::new(
            "workflow.projection.permissions",
            "unknown permission profile",
        )
    })?;
    let observed = optional_yaml_map(observed, code)?;
    let expected = object(expected, code)?;
    let permission_names = [
        ("actions", "actions"),
        ("artifactMetadata", "artifact-metadata"),
        ("attestations", "attestations"),
        ("contents", "contents"),
        ("idToken", "id-token"),
    ];
    if observed
        .keys()
        .any(|key| !permission_names.iter().any(|(_, yaml)| key == yaml))
    {
        return Err(Failure::new(
            code,
            "workflow contains an unknown permission",
        ));
    }
    for (semantic, yaml) in permission_names {
        let expected = string(expected, semantic, code)?;
        let observed = yaml_map_scalar(&observed, yaml).unwrap_or("none");
        if observed != expected {
            return Err(Failure::new(
                code,
                format!("permission {yaml:?} differs from projected profile"),
            ));
        }
    }
    Ok(())
}

fn compare_needs(
    observed: Option<&Yaml>,
    projected: &Map<String, Json>,
    id: &str,
    code: &'static str,
) -> Result<(), Failure> {
    let observed = yaml_string_list(observed)?;
    let expected = string_array(projected, "needs", "workflow.projection.job")?;
    if observed != expected {
        return Err(Failure::new(
            code,
            format!("job {id:?} needs differ from the projection"),
        ));
    }
    Ok(())
}

fn compare_scalar(
    observed: &BTreeMap<String, Yaml>,
    observed_key: &str,
    expected: &Map<String, Json>,
    expected_key: &str,
    code: &'static str,
) -> Result<(), Failure> {
    if required_yaml_scalar(observed, observed_key, code)? != string(expected, expected_key, code)?
    {
        return Err(Failure::new(
            code,
            format!("{observed_key} differs from projection"),
        ));
    }
    Ok(())
}

fn compare_unsigned(
    observed: &BTreeMap<String, Yaml>,
    observed_key: &str,
    expected: &Map<String, Json>,
    expected_key: &str,
    code: &'static str,
) -> Result<(), Failure> {
    let observed = required_yaml_scalar(observed, observed_key, code)?
        .parse::<u64>()
        .map_err(|_| Failure::new(code, "YAML value is not an unsigned integer"))?;
    if observed != unsigned(expected, expected_key, code)? {
        return Err(Failure::new(
            code,
            format!("{observed_key} differs from projection"),
        ));
    }
    Ok(())
}

fn compare_optional_scalar(
    observed: Option<&Yaml>,
    expected: Option<&Json>,
    code: &'static str,
) -> Result<(), Failure> {
    let observed = match observed {
        Some(value) => Some(value.scalar(code)?),
        None => None,
    };
    let expected = expected.and_then(Json::as_str);
    if observed != expected {
        return Err(Failure::new(
            code,
            "optional scalar differs from projection",
        ));
    }
    Ok(())
}

fn compare_nullable_yaml_scalar(
    observed: Option<&Yaml>,
    expected: Option<&Json>,
    code: &'static str,
) -> Result<(), Failure> {
    compare_optional_scalar(observed, expected, code)
}

fn compare_nullable_string(
    observed: Option<&str>,
    expected: Option<&Json>,
    code: &'static str,
) -> Result<(), Failure> {
    let expected = match expected {
        Some(Json::String(value)) => Some(value.as_str()),
        Some(Json::Null) => None,
        _ => {
            return Err(Failure::new(
                code,
                "projected nullable string is neither a string nor null",
            ));
        }
    };
    if observed != expected {
        return Err(Failure::new(
            code,
            format!(
                "semantic string differs from projection: observed {observed:?}, expected {expected:?}"
            ),
        ));
    }
    Ok(())
}

fn compare_yaml_semantic_string(
    observed: &BTreeMap<String, Yaml>,
    observed_key: &str,
    expected: &Map<String, Json>,
    expected_key: &str,
    code: &'static str,
) -> Result<(), Failure> {
    compare_nullable_string(
        Some(required_yaml_scalar(observed, observed_key, code)?),
        expected.get(expected_key),
        code,
    )
}

fn compare_yaml_optional_semantic_string(
    observed: &BTreeMap<String, Yaml>,
    observed_key: &str,
    expected: &Map<String, Json>,
    expected_key: &str,
    code: &'static str,
) -> Result<(), Failure> {
    let observed = observed
        .get(observed_key)
        .map(|value| value.scalar(code))
        .transpose()?;
    compare_nullable_string(observed, expected.get(expected_key), code)
}

fn compare_json_fields(
    left: &Map<String, Json>,
    left_key: &str,
    right: &Map<String, Json>,
    right_key: &str,
    code: &'static str,
) -> Result<(), Failure> {
    if left.get(left_key) != right.get(right_key) {
        return Err(Failure::new(
            code,
            "semantic condition differs from step condition",
        ));
    }
    Ok(())
}

fn compare_yaml_map_to_json(
    observed: Option<&Yaml>,
    expected: Option<&Json>,
    code: &'static str,
) -> Result<(), Failure> {
    let observed = optional_yaml_map(observed, code)?;
    let expected = expected
        .ok_or_else(|| Failure::new(code, "projection lacks expected mapping"))?
        .as_object()
        .ok_or_else(|| Failure::new(code, "projected mapping is not an object"))?;
    compare_yaml_map_and_json_map(&observed, expected, code)
}

fn compare_yaml_map_and_json_map(
    observed: &BTreeMap<String, Yaml>,
    expected: &Map<String, Json>,
    code: &'static str,
) -> Result<(), Failure> {
    if observed.len() != expected.len() {
        return Err(Failure::new(code, "mapping size differs from projection"));
    }
    for (key, expected_value) in expected {
        let observed_value = observed
            .get(key)
            .ok_or_else(|| Failure::new(code, format!("mapping key {key:?} is absent")))?;
        if !yaml_json_equal(observed_value, expected_value, code)? {
            return Err(Failure::new(
                code,
                format!("mapping value for {key:?} differs from projection"),
            ));
        }
    }
    Ok(())
}

fn yaml_json_equal(yaml: &Yaml, json: &Json, code: &'static str) -> Result<bool, Failure> {
    match (yaml, json) {
        (Yaml::Scalar(yaml), Json::String(json)) => Ok(yaml == json),
        (Yaml::Scalar(yaml), Json::Bool(json)) => Ok(yaml.parse::<bool>().ok() == Some(*json)),
        (Yaml::Scalar(yaml), Json::Number(json)) => Ok(yaml.parse::<u64>().ok() == json.as_u64()),
        (Yaml::Map(yaml), Json::Object(json)) => {
            compare_yaml_map_and_json_map(yaml, json, code)?;
            Ok(true)
        }
        (Yaml::Sequence(yaml), Json::Array(json)) => {
            if yaml.len() != json.len() {
                return Ok(false);
            }
            for (left, right) in yaml.iter().zip(json) {
                if !yaml_json_equal(left, right, code)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[derive(Default)]
struct Vector {
    id: String,
    valid: Option<bool>,
    mutation: String,
    diagnostic: Option<String>,
}

struct VectorManifest {
    protocol_id: String,
    base_workflows: String,
    protocol_projection: String,
    action_metadata: String,
    vectors: Vec<Vector>,
}

fn verify_vectors(
    manifest_path: &Path,
    workflows: &Path,
    projection: &Path,
    metadata: &Path,
) -> Result<Vec<Json>, Failure> {
    let bytes = read_regular(manifest_path, "workflow.vector-manifest.input")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        Failure::new(
            "workflow.vector-manifest.utf8",
            "workflow vector manifest is not UTF-8",
        )
    })?;
    let manifest = parse_vectors(text)?;
    validate_vector_manifest_bindings(&manifest, workflows, projection, metadata)?;
    validate_vector_catalog(&manifest.vectors)?;
    let base = load_workflow_bytes(workflows)?;
    let mut reports = Vec::new();
    let mut ids = BTreeSet::new();
    for vector in manifest.vectors {
        if !ids.insert(vector.id.clone()) {
            return Err(Failure::new(
                "workflow.vector-manifest.duplicate",
                "workflow vector id is duplicated",
            ));
        }
        let valid = vector.valid.ok_or_else(|| {
            Failure::new(
                "workflow.vector-manifest.schema",
                format!("vector {:?} lacks valid", vector.id),
            )
        })?;
        let mutated = apply_mutation(&base, &vector.mutation).map_err(|error| {
            Failure::new(
                error.code,
                format!("vector {:?}: {}", vector.id, error.message),
            )
        })?;
        let observed = audit_paths(workflows, projection, metadata, &mutated);
        if valid {
            observed.map_err(|error| {
                Failure::new(
                    "workflow.vector.known-good",
                    format!(
                        "known-good vector {:?} rejected with {}",
                        vector.id, error.code
                    ),
                )
            })?;
        } else {
            let expected = vector.diagnostic.as_deref().ok_or_else(|| {
                Failure::new(
                    "workflow.vector-manifest.schema",
                    format!("invalid vector {:?} lacks diagnostic", vector.id),
                )
            })?;
            let error = observed.err().ok_or_else(|| {
                Failure::new(
                    "workflow.vector.false-green",
                    format!("invalid vector {:?} was admitted", vector.id),
                )
            })?;
            if error.code != expected {
                return Err(Failure::new(
                    "workflow.vector.diagnostic",
                    format!(
                        "vector {:?} expected {expected:?}, observed {:?}",
                        vector.id, error.code
                    ),
                ));
            }
        }
        reports.push(serde_json::json!({
            "diagnostic": vector.diagnostic,
            "id": vector.id,
            "mutation": vector.mutation,
            "valid": valid,
        }));
    }
    Ok(reports)
}

fn parse_vectors(text: &str) -> Result<VectorManifest, Failure> {
    let mut root = BTreeMap::new();
    let mut vectors = Vec::new();
    let mut current: Option<Vector> = None;
    for (offset, raw) in text.lines().enumerate() {
        let line = strip_toml_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[vector]]" {
            if let Some(vector) = current.take() {
                vectors.push(vector);
            }
            current = Some(Vector::default());
            continue;
        }
        let Some(vector) = current.as_mut() else {
            let (key, raw_value) = line.split_once('=').ok_or_else(|| {
                Failure::new(
                    "workflow.vector-manifest.syntax",
                    format!("line {} lacks an equals separator", offset + 1),
                )
            })?;
            let key = key.trim().to_owned();
            if root.insert(key, raw_value.trim().to_owned()).is_some() {
                return Err(Failure::new(
                    "workflow.vector-manifest.duplicate",
                    "workflow vector manifest repeats a root field",
                ));
            }
            continue;
        };
        let (key, raw_value) = line.split_once('=').ok_or_else(|| {
            Failure::new(
                "workflow.vector-manifest.syntax",
                format!("line {} lacks an equals separator", offset + 1),
            )
        })?;
        let key = key.trim();
        let value = raw_value.trim();
        match key {
            "id" => vector.id = toml_string(value, offset + 1)?,
            "valid" => {
                vector.valid = Some(value.parse::<bool>().map_err(|_| {
                    Failure::new(
                        "workflow.vector-manifest.syntax",
                        format!("line {} has invalid boolean", offset + 1),
                    )
                })?);
            }
            "mutation" => vector.mutation = toml_string(value, offset + 1)?,
            "diagnostic" => vector.diagnostic = Some(toml_string(value, offset + 1)?),
            _ => {
                return Err(Failure::new(
                    "workflow.vector-manifest.schema",
                    format!("vector contains unknown field {key:?}"),
                ));
            }
        }
    }
    if let Some(vector) = current {
        vectors.push(vector);
    }
    for vector in &vectors {
        if vector.id.is_empty() || vector.mutation.is_empty() {
            return Err(Failure::new(
                "workflow.vector-manifest.schema",
                "workflow vector lacks id or mutation",
            ));
        }
    }
    let keys = root.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = [
        "schema-version",
        "protocol-id",
        "base-workflows",
        "protocol-projection",
        "action-metadata",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if keys != expected || root.get("schema-version").map(String::as_str) != Some("1") {
        return Err(Failure::new(
            "workflow.vector-manifest.schema",
            "workflow vector manifest root differs from the closed v1 schema",
        ));
    }
    Ok(VectorManifest {
        protocol_id: toml_root_string(&root, "protocol-id")?,
        base_workflows: toml_root_string(&root, "base-workflows")?,
        protocol_projection: toml_root_string(&root, "protocol-projection")?,
        action_metadata: toml_root_string(&root, "action-metadata")?,
        vectors,
    })
}

fn toml_root_string(root: &BTreeMap<String, String>, key: &str) -> Result<String, Failure> {
    toml_string(
        root.get(key).ok_or_else(|| {
            Failure::new("workflow.vector-manifest.schema", "root field is absent")
        })?,
        0,
    )
}

fn validate_vector_manifest_bindings(
    manifest: &VectorManifest,
    workflows: &Path,
    projection: &Path,
    metadata: &Path,
) -> Result<(), Failure> {
    if !workflows.ends_with(&manifest.base_workflows)
        || !projection.ends_with(&manifest.protocol_projection)
        || !metadata.ends_with(&manifest.action_metadata)
    {
        return Err(Failure::new(
            "workflow.vector-manifest.binding",
            "vector manifest input paths differ from command inputs",
        ));
    }
    let bytes = read_regular(projection, "workflow.projection.input")?;
    validate_json(&bytes, "workflow.projection.json")?;
    let value: Json = serde_json::from_slice(&bytes).map_err(|error| {
        Failure::new(
            "workflow.projection.json",
            format!("cannot parse protocol projection: {error}"),
        )
    })?;
    let root = object(&value, "workflow.projection.schema")?;
    if string(root, "protocolId", "workflow.projection.schema")? != manifest.protocol_id {
        return Err(Failure::new(
            "workflow.vector-manifest.binding",
            "vector manifest protocol ID differs from projection",
        ));
    }
    Ok(())
}

const EXPECTED_VECTORS: [(&str, bool, &str, Option<&str>); 19] = [
    ("known-good-workflows", true, "none", None),
    (
        "workflow-command-chain",
        false,
        "append-command-chain",
        Some("workflow.run.multiple-invocations"),
    ),
    (
        "workflow-custom-env",
        false,
        "add-custom-step-environment",
        Some("workflow.environment.custom"),
    ),
    (
        "workflow-unpinned-action",
        false,
        "replace-action-sha-with-tag",
        Some("workflow.action.unpinned"),
    ),
    (
        "workflow-manual-drift",
        false,
        "change-generated-workflow-name",
        Some("workflow.generated.drift"),
    ),
    (
        "workflow-attest-contents-write",
        false,
        "grant-attest-contents-write",
        Some("workflow.permission.attest"),
    ),
    (
        "workflow-publish-id-token-write",
        false,
        "grant-publish-id-token-write",
        Some("workflow.permission.publish"),
    ),
    (
        "workflow-deep-parser-in-publish",
        false,
        "invoke-deep-verifier-in-publish",
        Some("workflow.privilege.deep-parser"),
    ),
    (
        "workflow-explicit-shell",
        false,
        "add-shell-key",
        Some("workflow.shell.explicit"),
    ),
    (
        "workflow-multiline-run",
        false,
        "add-run-newline",
        Some("workflow.run.multiline"),
    ),
    (
        "workflow-secret-expression",
        false,
        "add-secret-expression",
        Some("workflow.expression.secret"),
    ),
    (
        "workflow-input-expression-in-run",
        false,
        "add-input-expression",
        Some("workflow.expression.untrusted-input"),
    ),
    (
        "workflow-missing-artifact-failure",
        false,
        "ignore-missing-critical-upload",
        Some("workflow.artifact.missing-policy"),
    ),
    (
        "workflow-artifact-name-download",
        false,
        "replace-artifact-id-with-name",
        Some("workflow.artifact.selection"),
    ),
    (
        "workflow-summary-always",
        false,
        "replace-not-cancelled-with-always",
        Some("workflow.summary.cancellation"),
    ),
    (
        "workflow-summary-omits-verifier",
        false,
        "remove-summary-verifier-need",
        Some("workflow.summary.graph"),
    ),
    (
        "workflow-regression-global-cancellation",
        false,
        "remove-ref-from-regression-concurrency",
        Some("workflow.concurrency.scope"),
    ),
    (
        "workflow-release-cancels",
        false,
        "enable-release-cancellation",
        Some("workflow.concurrency.release"),
    ),
    (
        "workflow-merge-group-while-disabled",
        false,
        "add-disabled-merge-group",
        Some("workflow.trigger.merge-group"),
    ),
];

fn validate_vector_catalog(vectors: &[Vector]) -> Result<(), Failure> {
    if vectors.len() != EXPECTED_VECTORS.len() {
        return Err(Failure::new(
            "workflow.vector-manifest.coverage",
            "workflow vector catalog must contain exactly known-good plus 18 invalid vectors",
        ));
    }
    for (vector, (id, valid, mutation, diagnostic)) in vectors.iter().zip(EXPECTED_VECTORS) {
        if vector.id != id
            || vector.valid != Some(valid)
            || vector.mutation != mutation
            || vector.diagnostic.as_deref() != diagnostic
        {
            return Err(Failure::new(
                "workflow.vector-manifest.coverage",
                "workflow vector catalog order or exact typed record differs",
            ));
        }
    }
    Ok(())
}

fn strip_toml_comment(line: &str) -> &str {
    let mut quoted = false;
    let mut escaped = false;
    for (position, character) in line.char_indices() {
        if escaped {
            escaped = false;
        } else if quoted && character == '\\' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character == '#' && !quoted {
            return &line[..position];
        }
    }
    line
}

fn toml_string(value: &str, line: usize) -> Result<String, Failure> {
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| {
            Failure::new(
                "workflow.vector-manifest.syntax",
                format!("line {line} value must be a basic string"),
            )
        })?;
    if value.contains('\\') {
        return Err(Failure::new(
            "workflow.vector-manifest.syntax",
            format!("line {line} string escapes are not allowed"),
        ));
    }
    Ok(value.to_owned())
}

fn load_workflow_bytes(root: &Path) -> Result<BTreeMap<String, Vec<u8>>, Failure> {
    let mut files = BTreeMap::new();
    for name in workflow_inventory(root)? {
        files.insert(
            name.clone(),
            read_regular(&root.join(name), "workflow.input")?,
        );
    }
    Ok(files)
}

fn apply_mutation(
    base: &BTreeMap<String, Vec<u8>>,
    mutation: &str,
) -> Result<BTreeMap<String, Vec<u8>>, Failure> {
    if mutation == "none" {
        return Ok(BTreeMap::new());
    }
    let mut files = base.clone();
    match mutation {
        "append-command-chain" => mutate_first(&mut files, b"run: cargo ", b" && true", false)?,
        "add-custom-step-environment" => insert_after_first(
            &mut files,
            b"        run: cargo ",
            b"        env:\n          HELL_AUDIT_VECTOR: enabled\n",
        )?,
        "replace-action-sha-with-tag" => replace_action_pin(&mut files)?,
        "change-generated-workflow-name" => {
            mutate_first(&mut files, b"name: CI", b" drift", false)?;
        }
        "grant-attest-contents-write" => {
            mutate_job_permission(&mut files, "attest", "contents: read", "contents: write")?;
        }
        "grant-publish-id-token-write" => {
            insert_job_permission(&mut files, "publish", "id-token: write")?;
        }
        "invoke-deep-verifier-in-publish" => mutate_job_run(
            &mut files,
            "publish",
            "./automation/target/ci/hell-release-publisher publish",
            "./automation/target/ci/hell-ci release final-verify",
        )?,
        "add-shell-key" => {
            insert_after_first(&mut files, b"        run: cargo ", b"        shell: bash\n")?;
        }
        "add-run-newline" => multiline_first_run(&mut files)?,
        "add-secret-expression" => insert_after_first(
            &mut files,
            b"        run: cargo ",
            b"        env:\n          PRIVATE_TOKEN: ${{ secrets.PRIVATE_TOKEN }}\n",
        )?,
        "add-input-expression" => mutate_first(
            &mut files,
            b"run: cargo ",
            b" ${{ inputs.untrusted }}",
            false,
        )?,
        "ignore-missing-critical-upload" => {
            replace_once_any(&mut files, b"          if-no-files-found: error\n", b"")?;
        }
        "replace-artifact-id-with-name" => {
            replace_first_prefix(&mut files, b"          artifact-ids:", b"          name:")?;
        }
        "replace-not-cancelled-with-always" => replace_once_any(
            &mut files,
            b"    if: ${{ !cancelled() }}\n",
            b"    if: ${{ always() }}\n",
        )?,
        "remove-summary-verifier-need" => replace_once_any(&mut files, b"      - verify\n", b"")?,
        "remove-ref-from-regression-concurrency" => mutate_named_file(
            &mut files,
            "regression-corpus.yml",
            b"${{ github.workflow }}-${{ github.ref }}",
            b"${{ github.workflow }}",
        )?,
        "enable-release-cancellation" => mutate_named_file(
            &mut files,
            "release.yml",
            b"  cancel-in-progress: false",
            b"  cancel-in-progress: true",
        )?,
        "add-disabled-merge-group" => insert_after_first(
            &mut files,
            b"on:\n",
            b"  merge_group:\n    types: [checks_requested]\n",
        )?,
        _ => {
            return Err(Failure::new(
                "workflow.vector.mutation",
                format!("unknown typed mutation {mutation:?}"),
            ));
        }
    }
    Ok(files)
}

fn mutate_first(
    files: &mut BTreeMap<String, Vec<u8>>,
    needle: &[u8],
    insertion: &[u8],
    replace_line: bool,
) -> Result<(), Failure> {
    for bytes in files.values_mut() {
        if let Some(position) = find_bytes(bytes, needle) {
            let at = if replace_line {
                position + needle.len()
            } else {
                let tail = &bytes[position..];
                position
                    + tail
                        .iter()
                        .position(|byte| *byte == b'\n')
                        .unwrap_or(tail.len())
            };
            bytes.splice(at..at, insertion.iter().copied());
            return Ok(());
        }
    }
    Err(Failure::new(
        "workflow.vector.mutation",
        "typed mutation target was not found",
    ))
}

fn insert_after_first(
    files: &mut BTreeMap<String, Vec<u8>>,
    needle: &[u8],
    insertion: &[u8],
) -> Result<(), Failure> {
    for bytes in files.values_mut() {
        if let Some(position) = find_bytes(bytes, needle) {
            let tail = &bytes[position..];
            let end = position
                + tail
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(tail.len(), |offset| offset + 1);
            bytes.splice(end..end, insertion.iter().copied());
            return Ok(());
        }
    }
    Err(Failure::new(
        "workflow.vector.mutation",
        "typed insertion target was not found",
    ))
}

fn replace_once_any(
    files: &mut BTreeMap<String, Vec<u8>>,
    needle: &[u8],
    replacement: &[u8],
) -> Result<(), Failure> {
    for bytes in files.values_mut() {
        if replace_once(bytes, needle, replacement) {
            return Ok(());
        }
    }
    Err(Failure::new(
        "workflow.vector.mutation",
        "typed replacement target was not found",
    ))
}

fn mutate_named_file(
    files: &mut BTreeMap<String, Vec<u8>>,
    name: &str,
    needle: &[u8],
    replacement: &[u8],
) -> Result<(), Failure> {
    let bytes = files
        .get_mut(name)
        .ok_or_else(|| Failure::new("workflow.vector.mutation", "mutation file is absent"))?;
    if !replace_once(bytes, needle, replacement) {
        return Err(Failure::new(
            "workflow.vector.mutation",
            "named mutation target was not found",
        ));
    }
    Ok(())
}

fn replace_action_pin(files: &mut BTreeMap<String, Vec<u8>>) -> Result<(), Failure> {
    for bytes in files.values_mut() {
        let Some(at) = find_bytes(bytes, b"uses: actions/") else {
            continue;
        };
        let Some(relative) = bytes[at..].iter().position(|byte| *byte == b'@') else {
            continue;
        };
        let commit_start = at + relative + 1;
        let commit_end = bytes[commit_start..]
            .iter()
            .position(u8::is_ascii_whitespace)
            .map_or(bytes.len(), |offset| commit_start + offset);
        bytes.splice(commit_start..commit_end, b"v1".iter().copied());
        return Ok(());
    }
    Err(Failure::new(
        "workflow.vector.mutation",
        "action pin mutation target was not found",
    ))
}

fn replace_first_prefix(
    files: &mut BTreeMap<String, Vec<u8>>,
    needle: &[u8],
    replacement: &[u8],
) -> Result<(), Failure> {
    replace_once_any(files, needle, replacement)
}

fn multiline_first_run(files: &mut BTreeMap<String, Vec<u8>>) -> Result<(), Failure> {
    for bytes in files.values_mut() {
        let Some(position) = find_bytes(bytes, b"        run: cargo ") else {
            continue;
        };
        let end = bytes[position..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |offset| position + offset);
        let command = bytes[position + b"        run: ".len()..end].to_vec();
        let mut replacement = b"        run: |\n          ".to_vec();
        replacement.extend(command);
        bytes.splice(position..end, replacement);
        return Ok(());
    }
    Err(Failure::new(
        "workflow.vector.mutation",
        "multiline mutation target was not found",
    ))
}

fn mutate_job_permission(
    files: &mut BTreeMap<String, Vec<u8>>,
    job: &str,
    from: &str,
    to: &str,
) -> Result<(), Failure> {
    mutate_job_segment(files, job, |segment| {
        replace_once(segment, from.as_bytes(), to.as_bytes())
    })
}

fn insert_job_permission(
    files: &mut BTreeMap<String, Vec<u8>>,
    job: &str,
    permission: &str,
) -> Result<(), Failure> {
    mutate_job_segment(files, job, |segment| {
        let Some(position) = find_bytes(segment, b"    permissions:\n") else {
            return false;
        };
        let at = position + b"    permissions:\n".len();
        let mut addition = b"      ".to_vec();
        addition.extend(permission.as_bytes());
        addition.push(b'\n');
        segment.splice(at..at, addition);
        true
    })
}

fn mutate_job_run(
    files: &mut BTreeMap<String, Vec<u8>>,
    job: &str,
    from: &str,
    to: &str,
) -> Result<(), Failure> {
    mutate_job_segment(files, job, |segment| {
        replace_once(segment, from.as_bytes(), to.as_bytes())
    })
}

fn mutate_job_segment(
    files: &mut BTreeMap<String, Vec<u8>>,
    job: &str,
    mutate: impl FnOnce(&mut Vec<u8>) -> bool,
) -> Result<(), Failure> {
    let bytes = files
        .get_mut("release.yml")
        .ok_or_else(|| Failure::new("workflow.vector.mutation", "release workflow is absent"))?;
    let marker = format!("  {job}:\n");
    let start = find_bytes(bytes, marker.as_bytes()).ok_or_else(|| {
        Failure::new(
            "workflow.vector.mutation",
            "release job mutation target is absent",
        )
    })?;
    let remainder_start = start + marker.len();
    let end = bytes[remainder_start..]
        .windows(4)
        .position(|window| {
            window[0] == b'\n' && window[1] == b' ' && window[2] == b' ' && window[3] != b' '
        })
        .map_or(bytes.len(), |offset| remainder_start + offset);
    let mut segment = bytes[start..end].to_vec();
    if !mutate(&mut segment) {
        return Err(Failure::new(
            "workflow.vector.mutation",
            "release job inner mutation target is absent",
        ));
    }
    bytes.splice(start..end, segment);
    Ok(())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn replace_once(bytes: &mut Vec<u8>, needle: &[u8], replacement: &[u8]) -> bool {
    let Some(position) = find_bytes(bytes, needle) else {
        return false;
    };
    bytes.splice(
        position..position + needle.len(),
        replacement.iter().copied(),
    );
    true
}

struct Options {
    values: BTreeMap<String, OsString>,
}

impl Options {
    fn parse(arguments: &[OsString], allowed: &[&str]) -> Result<Self, Failure> {
        if !arguments.len().is_multiple_of(2) {
            return Err(Failure::new(
                "workflow.cli.option",
                "workflow-auditor option lacks a value",
            ));
        }
        let mut values = BTreeMap::new();
        for pair in arguments.chunks_exact(2) {
            let name = pair[0]
                .to_str()
                .ok_or_else(|| Failure::new("workflow.cli.option", "option name must be UTF-8"))?;
            if !allowed.contains(&name) {
                return Err(Failure::new(
                    "workflow.cli.option",
                    format!("unknown workflow-auditor option {name:?}"),
                ));
            }
            if values.insert(name.to_owned(), pair[1].clone()).is_some() {
                return Err(Failure::new(
                    "workflow.cli.option",
                    format!("option {name:?} was provided more than once"),
                ));
            }
        }
        Ok(Self { values })
    }

    fn path(&self, name: &str) -> Result<PathBuf, Failure> {
        self.values.get(name).map(PathBuf::from).ok_or_else(|| {
            Failure::new(
                "workflow.cli.option",
                format!("required option {name} is absent"),
            )
        })
    }
}

fn usage() -> String {
    "usage: hell-workflow-auditor audit --workflows DIR --protocol-projection FILE --action-metadata FILE --output FILE | verify-vectors --manifest FILE --workflows DIR --protocol-projection FILE --action-metadata FILE --output FILE".to_owned()
}

fn read_regular(path: &Path, code: &'static str) -> Result<Vec<u8>, Failure> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Failure::new(
            code,
            format!("cannot inspect input {}: {error}", path.display()),
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Failure::new(code, "input is linked or non-regular"));
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(Failure::new(code, "input exceeds the audited size bound"));
    }
    let bytes = fs::read(path).map_err(|error| {
        Failure::new(
            code,
            format!("cannot read input {}: {error}", path.display()),
        )
    })?;
    if !bytes.ends_with(b"\n") {
        return Err(Failure::new(code, "input lacks its required trailing LF"));
    }
    Ok(bytes)
}

fn write_report(path: &Path, value: &Json) -> Result<(), Failure> {
    if path.exists() {
        return Err(Failure::new(
            "workflow.report.exists",
            "workflow audit report already exists",
        ));
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| {
        Failure::new(
            "workflow.report.write",
            format!("cannot create report directory: {error}"),
        )
    })?;
    let filename = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| Failure::new("workflow.report.path", "report filename is invalid"))?;
    let staging = parent.join(format!(".{filename}.{}.partial", std::process::id()));
    let mut bytes = serde_json::to_vec(value).map_err(|error| {
        Failure::new(
            "workflow.report.encode",
            format!("cannot encode workflow audit report: {error}"),
        )
    })?;
    bytes.push(b'\n');
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)
            .map_err(|error| {
                Failure::new(
                    "workflow.report.write",
                    format!("cannot create staging report: {error}"),
                )
            })?;
        file.write_all(&bytes).map_err(|error| {
            Failure::new(
                "workflow.report.write",
                format!("cannot write staging report: {error}"),
            )
        })?;
        file.sync_all().map_err(|error| {
            Failure::new(
                "workflow.report.write",
                format!("cannot sync staging report: {error}"),
            )
        })?;
        fs::rename(&staging, path).map_err(|error| {
            Failure::new(
                "workflow.report.write",
                format!("cannot publish workflow audit report: {error}"),
            )
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                Failure::new(
                    "workflow.report.write",
                    format!("cannot sync report directory: {error}"),
                )
            })
    })();
    if result.is_err() {
        let _cleanup_result = fs::remove_file(&staging);
    }
    result
}

fn object<'a>(value: &'a Json, code: &'static str) -> Result<&'a Map<String, Json>, Failure> {
    value
        .as_object()
        .ok_or_else(|| Failure::new(code, "expected a JSON object"))
}

fn object_field<'a>(
    value: &'a Map<String, Json>,
    key: &str,
    code: &'static str,
) -> Result<&'a Map<String, Json>, Failure> {
    value
        .get(key)
        .and_then(Json::as_object)
        .ok_or_else(|| Failure::new(code, format!("field {key:?} must be an object")))
}

fn required_projected_object<'a>(
    value: &'a Map<String, Json>,
    key: &str,
    code: &'static str,
) -> Result<&'a Map<String, Json>, Failure> {
    object_field(value, key, code)
}

fn array<'a>(
    value: &'a Map<String, Json>,
    key: &str,
    code: &'static str,
) -> Result<&'a [Json], Failure> {
    value
        .get(key)
        .and_then(Json::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| Failure::new(code, format!("field {key:?} must be an array")))
}

fn string<'a>(
    value: &'a Map<String, Json>,
    key: &str,
    code: &'static str,
) -> Result<&'a str, Failure> {
    value
        .get(key)
        .and_then(Json::as_str)
        .ok_or_else(|| Failure::new(code, format!("field {key:?} must be a string")))
}

fn unsigned(value: &Map<String, Json>, key: &str, code: &'static str) -> Result<u64, Failure> {
    value
        .get(key)
        .and_then(Json::as_u64)
        .ok_or_else(|| Failure::new(code, format!("field {key:?} must be an unsigned integer")))
}

fn boolean(value: &Map<String, Json>, key: &str, code: &'static str) -> Result<bool, Failure> {
    value
        .get(key)
        .and_then(Json::as_bool)
        .ok_or_else(|| Failure::new(code, format!("field {key:?} must be a boolean")))
}

fn string_array(
    value: &Map<String, Json>,
    key: &str,
    code: &'static str,
) -> Result<Vec<String>, Failure> {
    array(value, key, code)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| Failure::new(code, format!("field {key:?} contains a non-string")))
        })
        .collect()
}

fn exact_keys(
    value: &Map<String, Json>,
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

fn require_null(value: &Map<String, Json>, key: &str, code: &'static str) -> Result<(), Failure> {
    if !value.get(key).is_some_and(Json::is_null) {
        return Err(Failure::new(code, format!("field {key:?} must be null")));
    }
    Ok(())
}

fn required_yaml_map<'a>(
    value: &'a BTreeMap<String, Yaml>,
    key: &str,
    code: &'static str,
) -> Result<&'a BTreeMap<String, Yaml>, Failure> {
    value
        .get(key)
        .ok_or_else(|| Failure::new(code, format!("YAML field {key:?} is absent")))?
        .map(code)
}

fn optional_yaml_map(
    value: Option<&Yaml>,
    code: &'static str,
) -> Result<BTreeMap<String, Yaml>, Failure> {
    match value {
        Some(value) => Ok(value.map(code)?.clone()),
        None => Ok(BTreeMap::new()),
    }
}

fn required_yaml_sequence<'a>(
    value: &'a BTreeMap<String, Yaml>,
    key: &str,
    code: &'static str,
) -> Result<&'a [Yaml], Failure> {
    value
        .get(key)
        .ok_or_else(|| Failure::new(code, format!("YAML field {key:?} is absent")))?
        .sequence(code)
}

fn required_yaml_scalar<'a>(
    value: &'a BTreeMap<String, Yaml>,
    key: &str,
    code: &'static str,
) -> Result<&'a str, Failure> {
    value
        .get(key)
        .ok_or_else(|| Failure::new(code, format!("YAML field {key:?} is absent")))?
        .scalar(code)
}

fn yaml_map_scalar<'a>(value: &'a BTreeMap<String, Yaml>, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(|value| value.scalar("workflow.yaml.scalar").ok())
}

fn yaml_string_list(value: Option<&Yaml>) -> Result<Vec<String>, Failure> {
    match value {
        None => Ok(Vec::new()),
        Some(Yaml::Sequence(values)) => values
            .iter()
            .map(|value| value.scalar("workflow.yaml.list").map(str::to_owned))
            .collect(),
        Some(Yaml::Scalar(value)) if value.starts_with('[') && value.ends_with(']') => value
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.trim_matches(['\'', '"']).to_owned())
            .collect::<Vec<_>>()
            .pipe(Ok),
        Some(Yaml::Scalar(value)) => Ok(vec![value.clone()]),
        Some(Yaml::Map(_)) => Err(Failure::new(
            "workflow.yaml.list",
            "expected a scalar or sequence",
        )),
    }
}

trait Pipe: Sized {
    fn pipe<T>(self, function: impl FnOnce(Self) -> T) -> T {
        function(self)
    }
}

impl<T> Pipe for T {}

fn require_sha(value: &str, code: &'static str) -> Result<(), Failure> {
    if value.len() != SHA_LENGTH
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Failure::new(
            code,
            "value is not a lowercase full commit SHA",
        ));
    }
    Ok(())
}

fn require_digest(value: &str, code: &'static str) -> Result<(), Failure> {
    if value.len() != DIGEST_LENGTH
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Failure::new(
            code,
            "value is not a lowercase SHA-256 digest",
        ));
    }
    Ok(())
}

fn validate_json(bytes: &[u8], code: &'static str) -> Result<(), Failure> {
    let mut parser = JsonValidator { bytes, offset: 0 };
    parser.whitespace();
    parser.value(code)?;
    parser.whitespace();
    if parser.offset != bytes.len() {
        return Err(Failure::new(code, "JSON has trailing non-whitespace bytes"));
    }
    Ok(())
}

struct JsonValidator<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl JsonValidator<'_> {
    fn value(&mut self, code: &'static str) -> Result<(), Failure> {
        self.whitespace();
        match self.bytes.get(self.offset) {
            Some(b'{') => self.object(code),
            Some(b'[') => self.array(code),
            Some(b'"') => self.string(code).map(|_| ()),
            Some(b't') => self.literal(b"true", code),
            Some(b'f') => self.literal(b"false", code),
            Some(b'n') => self.literal(b"null", code),
            Some(b'-' | b'0'..=b'9') => self.number(code),
            _ => Err(Failure::new(code, "JSON contains an invalid value")),
        }
    }

    fn object(&mut self, code: &'static str) -> Result<(), Failure> {
        self.offset += 1;
        let mut keys = BTreeSet::new();
        self.whitespace();
        if self.consume(b'}') {
            return Ok(());
        }
        loop {
            let key = self.string(code)?;
            if !keys.insert(key) {
                return Err(Failure::new(code, "JSON object contains a duplicate key"));
            }
            self.whitespace();
            self.expect(b':', code)?;
            self.value(code)?;
            self.whitespace();
            if self.consume(b'}') {
                return Ok(());
            }
            self.expect(b',', code)?;
            self.whitespace();
        }
    }

    fn array(&mut self, code: &'static str) -> Result<(), Failure> {
        self.offset += 1;
        self.whitespace();
        if self.consume(b']') {
            return Ok(());
        }
        loop {
            self.value(code)?;
            self.whitespace();
            if self.consume(b']') {
                return Ok(());
            }
            self.expect(b',', code)?;
        }
    }

    fn string(&mut self, code: &'static str) -> Result<Vec<u8>, Failure> {
        self.expect(b'"', code)?;
        let mut decoded = Vec::new();
        loop {
            let byte = *self
                .bytes
                .get(self.offset)
                .ok_or_else(|| Failure::new(code, "JSON string is unterminated"))?;
            self.offset += 1;
            match byte {
                b'"' => return Ok(decoded),
                b'\\' => {
                    let escaped = *self
                        .bytes
                        .get(self.offset)
                        .ok_or_else(|| Failure::new(code, "JSON escape is unterminated"))?;
                    self.offset += 1;
                    decoded.extend([b'\\', escaped]);
                    if escaped == b'u' {
                        for _ in 0..4 {
                            let hex = *self.bytes.get(self.offset).ok_or_else(|| {
                                Failure::new(code, "JSON Unicode escape is truncated")
                            })?;
                            if !hex.is_ascii_hexdigit() {
                                return Err(Failure::new(code, "JSON Unicode escape is invalid"));
                            }
                            decoded.push(hex);
                            self.offset += 1;
                        }
                    } else if !matches!(
                        escaped,
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't'
                    ) {
                        return Err(Failure::new(code, "JSON escape is invalid"));
                    }
                }
                0..=31 => return Err(Failure::new(code, "JSON string has a control byte")),
                _ => decoded.push(byte),
            }
        }
    }

    fn number(&mut self, code: &'static str) -> Result<(), Failure> {
        let start = self.offset;
        while self.bytes.get(self.offset).is_some_and(|byte| {
            byte.is_ascii_digit() || matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E')
        }) {
            self.offset += 1;
        }
        serde_json::from_slice::<Json>(&self.bytes[start..self.offset])
            .map(|_| ())
            .map_err(|_| Failure::new(code, "JSON number is invalid"))
    }

    fn literal(&mut self, value: &[u8], code: &'static str) -> Result<(), Failure> {
        if self.bytes.get(self.offset..self.offset + value.len()) != Some(value) {
            return Err(Failure::new(code, "JSON literal is invalid"));
        }
        self.offset += value.len();
        Ok(())
    }

    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.offset)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.offset += 1;
        }
    }

    fn expect(&mut self, byte: u8, code: &'static str) -> Result<(), Failure> {
        if self.consume(byte) {
            Ok(())
        } else {
            Err(Failure::new(code, "JSON punctuation is invalid"))
        }
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.bytes.get(self.offset) == Some(&byte) {
            self.offset += 1;
            true
        } else {
            false
        }
    }
}

const SHA256_INITIAL: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];
const SHA256_ROUND: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

#[must_use]
pub fn protocol_sha256(input: &[u8]) -> String {
    let bit_length = (input.len() as u64).wrapping_mul(8);
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend(bit_length.to_be_bytes());
    let mut state = SHA256_INITIAL;
    for chunk in padded.chunks_exact(64) {
        let mut words = [0_u32; 64];
        for (index, bytes) in chunk.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [
            mut word_a,
            mut word_b,
            mut word_c,
            mut word_d,
            mut word_e,
            mut word_f,
            mut word_g,
            mut word_h,
        ] = state;
        for index in 0..64 {
            let sum1 = word_e.rotate_right(6) ^ word_e.rotate_right(11) ^ word_e.rotate_right(25);
            let choose = (word_e & word_f) ^ (!word_e & word_g);
            let temp1 = word_h
                .wrapping_add(sum1)
                .wrapping_add(choose)
                .wrapping_add(SHA256_ROUND[index])
                .wrapping_add(words[index]);
            let sum0 = word_a.rotate_right(2) ^ word_a.rotate_right(13) ^ word_a.rotate_right(22);
            let majority = (word_a & word_b) ^ (word_a & word_c) ^ (word_b & word_c);
            let temp2 = sum0.wrapping_add(majority);
            word_h = word_g;
            word_g = word_f;
            word_f = word_e;
            word_e = word_d.wrapping_add(temp1);
            word_d = word_c;
            word_c = word_b;
            word_b = word_a;
            word_a = temp1.wrapping_add(temp2);
        }
        for (slot, value) in state.iter_mut().zip([
            word_a, word_b, word_c, word_d, word_e, word_f, word_g, word_h,
        ]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut result = String::with_capacity(DIGEST_LENGTH);
    for word in state {
        write!(&mut result, "{word:08x}").expect("writing to a String cannot fail");
    }
    result
}
