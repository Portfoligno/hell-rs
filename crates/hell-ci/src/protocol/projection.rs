use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::model::{
    Access, Credential, Manifest, MergeGroup, Operation, Permission, Step, Workflow,
};
use crate::json::JsonValue;
use crate::release::manifest::{read_regular, write_json};

pub(super) fn write(
    manifest_path: &Path,
    repository_root: &Path,
    output: &Path,
) -> Result<String, String> {
    let manifest = Manifest::read(manifest_path).map_err(|diagnostic| diagnostic.message)?;
    let metadata_path = repository_root.join(&manifest.action_metadata);
    let metadata = read_regular(&metadata_path)?;
    let value = projection(&manifest, &metadata)?;
    write_json(output, &value)?;
    Ok(format!(
        "projected complete physical workflow protocol to {}",
        output.display()
    ))
}

fn projection(manifest: &Manifest, metadata: &[u8]) -> Result<JsonValue, String> {
    let workflows = manifest
        .workflows
        .values()
        .map(|workflow| project_workflow(manifest, workflow))
        .collect::<Result<Vec<_>, _>>()?;
    let permissions = JsonValue::Object(
        manifest
            .permissions
            .iter()
            .map(|(id, permission)| (id.clone(), project_permission(permission)))
            .collect(),
    );
    let approved = approved_credential_executables(manifest)
        .into_iter()
        .map(JsonValue::String)
        .collect();
    Ok(object([
        (
            "actionMetadata",
            object([
                ("path", string(&manifest.action_metadata.to_string_lossy())),
                (
                    "sha256",
                    string(&hell_testkit::sha256_bytes(metadata).hex()),
                ),
            ]),
        ),
        ("approvedCredentialCommands", JsonValue::Array(approved)),
        ("mergeQueue", JsonValue::Bool(manifest.merge_queue)),
        ("permissions", permissions),
        ("protocolId", string("hell-rs-ci-v1")),
        ("readinessSummary", project_readiness(manifest)),
        ("schemaVersion", JsonValue::Number(1)),
        ("workflows", JsonValue::Array(workflows)),
    ]))
}

fn project_readiness(manifest: &Manifest) -> JsonValue {
    object([
        (
            "artifacts",
            JsonValue::Array(
                manifest
                    .readiness
                    .artifacts
                    .iter()
                    .map(|artifact| {
                        object([
                            (
                                "artifactDigestOutput",
                                string(&artifact.artifact_digest_output),
                            ),
                            ("artifactIdOutput", string(&artifact.artifact_id_output)),
                            ("inputPath", string(&artifact.input_path)),
                            ("job", string(&artifact.job)),
                            (
                                "platformId",
                                artifact
                                    .platform_id
                                    .as_deref()
                                    .map_or(JsonValue::Null, string),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "jobs",
            JsonValue::Array(
                manifest
                    .readiness
                    .jobs
                    .iter()
                    .map(|job| string(job))
                    .collect(),
            ),
        ),
    ])
}

fn project_workflow(manifest: &Manifest, workflow: &Workflow) -> Result<JsonValue, String> {
    let triggers = project_triggers(manifest, workflow);
    let jobs = workflow
        .jobs
        .iter()
        .map(|id| {
            let job = workflow.job_specs.get(id).expect("exact job inventory");
            validate_declared_artifact(id, job)?;
            let steps = job
                .steps
                .iter()
                .map(|step| project_step(manifest, step))
                .collect();
            Ok(object([
                (
                    "condition",
                    job.condition.as_deref().map_or(JsonValue::Null, string),
                ),
                ("id", string(id)),
                ("name", string(&job.physical_name)),
                (
                    "needs",
                    JsonValue::Array(job.needs.iter().map(|need| string(need)).collect()),
                ),
                (
                    "outputs",
                    JsonValue::Object(
                        job.outputs
                            .iter()
                            .cloned()
                            .map(|(name, value)| (name, string(&value)))
                            .collect(),
                    ),
                ),
                ("permissionProfile", string(&job.permission)),
                ("runsOn", string(&job.runner)),
                ("steps", JsonValue::Array(steps)),
                ("timeoutMinutes", JsonValue::Number(job.timeout_minutes)),
            ]))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(object([
        (
            "concurrency",
            object([
                (
                    "cancelInProgress",
                    JsonValue::Bool(workflow.concurrency.cancel_in_progress),
                ),
                ("group", string(&workflow.concurrency.group)),
            ]),
        ),
        ("jobs", JsonValue::Array(jobs)),
        ("name", string(&workflow.name)),
        ("path", string(&workflow.path.to_string_lossy())),
        ("permissionProfile", string(&workflow.physical.permission)),
        ("triggers", JsonValue::Array(triggers)),
    ]))
}

fn validate_declared_artifact(job_id: &str, job: &super::model::Job) -> Result<(), String> {
    let declared = &job.artifact_output;
    let observed = job
        .steps
        .iter()
        .filter_map(|step| match &step.operation {
            Operation::Action { action, inputs } if action == "upload-artifact" => {
                input(inputs, "name")
            }
            _ => None,
        })
        .count();
    let valid = if declared == "none" {
        observed == 0
    } else {
        observed > 0
    };
    if !valid {
        return Err(format!(
            "job {job_id} declares artifact output {declared}, but {observed} upload steps were found"
        ));
    }
    Ok(())
}

fn project_triggers(manifest: &Manifest, workflow: &Workflow) -> Vec<JsonValue> {
    let mut result = Vec::new();
    if workflow.trigger.push.branches {
        result.push(trigger(
            "push",
            vec!["**".to_owned()],
            Vec::new(),
            workflow.trigger.paths.clone(),
            JsonValue::Object(BTreeMap::new()),
        ));
    }
    if workflow.trigger.pull_request {
        result.push(trigger(
            "pull_request",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            JsonValue::Object(BTreeMap::new()),
        ));
    }
    if workflow.trigger.workflow_dispatch {
        let inputs = workflow
            .physical
            .dispatch_inputs
            .iter()
            .map(|input| {
                (
                    input.id.clone(),
                    object([
                        ("description", string(&input.description)),
                        ("required", JsonValue::Bool(input.required)),
                        ("type", string(&input.kind)),
                    ]),
                )
            })
            .collect();
        result.push(trigger(
            "workflow_dispatch",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            JsonValue::Object(inputs),
        ));
    }
    let merge = match workflow.trigger.merge_group {
        MergeGroup::Always => true,
        MergeGroup::Conditional => manifest.merge_queue,
        MergeGroup::Never => false,
    };
    if merge {
        result.push(trigger(
            "merge_group",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            JsonValue::Object(BTreeMap::new()),
        ));
    }
    result
}

fn trigger(
    event: &str,
    branches: Vec<String>,
    tags: Vec<String>,
    paths: Vec<String>,
    dispatch_inputs: JsonValue,
) -> JsonValue {
    object([
        (
            "branches",
            JsonValue::Array(branches.into_iter().map(JsonValue::String).collect()),
        ),
        ("dispatchInputs", dispatch_inputs),
        ("event", string(event)),
        (
            "paths",
            JsonValue::Array(paths.into_iter().map(JsonValue::String).collect()),
        ),
        (
            "tags",
            JsonValue::Array(tags.into_iter().map(JsonValue::String).collect()),
        ),
    ])
}

fn project_step(manifest: &Manifest, step: &Step) -> JsonValue {
    let common_name = string(&step.name);
    let step_id = step.id.as_deref().map_or(JsonValue::Null, string);
    let condition = step.condition.as_deref().map_or(JsonValue::Null, string);
    match &step.operation {
        Operation::Run(invocation) => {
            let argv = std::iter::once(invocation.executable.clone())
                .chain(
                    invocation
                        .arguments
                        .iter()
                        .map(|argument| super::render::render_argument(argument)),
                )
                .map(JsonValue::String)
                .collect();
            let environment = match invocation.credential {
                Credential::None => JsonValue::Object(BTreeMap::new()),
                Credential::GithubToken => JsonValue::Object(BTreeMap::from([(
                    "GITHUB_TOKEN".to_owned(),
                    string("${{ github.token }}"),
                )])),
            };
            object([
                (
                    "command",
                    object([
                        ("argv", JsonValue::Array(argv)),
                        (
                            "credential",
                            string(match invocation.credential {
                                Credential::None => "none",
                                Credential::GithubToken => "github-token",
                            }),
                        ),
                        ("environment", environment),
                        ("executable", string(&invocation.executable)),
                        (
                            "workingDirectory",
                            step.working_directory
                                .as_deref()
                                .map_or(JsonValue::Null, string),
                        ),
                    ]),
                ),
                ("condition", condition),
                ("kind", string("command")),
                ("name", common_name),
                ("ref", string(&invocation.executable)),
                ("stepId", step_id),
            ])
        }
        Operation::Action { action, inputs } => {
            let action_definition = manifest
                .actions
                .get(action)
                .expect("action reference checked");
            let uses = format!(
                "{}@{}",
                action_definition.repository, action_definition.revision
            );
            let with = JsonValue::Object(
                inputs
                    .iter()
                    .cloned()
                    .map(|(name, value)| (name, string(&value)))
                    .collect(),
            );
            let (cache, artifact, attestation) = action_semantics(action, step, inputs);
            object([
                (
                    "action",
                    object([
                        (
                            "outputs",
                            JsonValue::Array(
                                action_definition
                                    .outputs
                                    .iter()
                                    .map(|output| string(output))
                                    .collect(),
                            ),
                        ),
                        ("uses", string(&uses)),
                        ("with", with),
                    ]),
                ),
                ("artifact", artifact),
                ("attestation", attestation),
                ("cache", cache),
                ("condition", condition),
                ("kind", string("action")),
                ("name", common_name),
                ("ref", string(&uses)),
                ("stepId", step_id),
            ])
        }
    }
}

fn action_semantics(
    action: &str,
    step: &Step,
    inputs: &[(String, String)],
) -> (JsonValue, JsonValue, JsonValue) {
    let condition = step.condition.as_deref().map_or(JsonValue::Null, string);
    match action {
        "cache-restore" | "cache-save" => (
            object([
                ("condition", condition),
                ("key", optional_input(inputs, "key")),
                (
                    "mode",
                    string(if action == "cache-restore" {
                        "restore"
                    } else {
                        "save"
                    }),
                ),
                ("paths", path_input(inputs, "path")),
            ]),
            JsonValue::Null,
            JsonValue::Null,
        ),
        "upload-artifact" => {
            let digest = step.id.as_deref().map_or(JsonValue::Null, |id| {
                string(&format!("${{{{ steps.{id}.outputs.artifact-digest }}}}"))
            });
            (
                JsonValue::Null,
                object([
                    ("artifactId", JsonValue::Null),
                    ("condition", condition),
                    ("digest", digest),
                    ("missingPolicy", optional_input(inputs, "if-no-files-found")),
                    ("mode", string("upload")),
                    ("name", optional_input(inputs, "name")),
                    ("path", optional_input(inputs, "path")),
                ]),
                JsonValue::Null,
            )
        }
        "download-artifact" => {
            let artifact_id = input(inputs, "artifact-ids");
            let digest = artifact_id
                .and_then(paired_artifact_digest)
                .map_or(JsonValue::Null, |value| string(&value));
            (
                JsonValue::Null,
                object([
                    ("artifactId", artifact_id.map_or(JsonValue::Null, string)),
                    ("condition", condition),
                    ("digest", digest),
                    ("missingPolicy", JsonValue::Null),
                    ("mode", string("download")),
                    ("name", JsonValue::Null),
                    ("path", optional_input(inputs, "path")),
                ]),
                JsonValue::Null,
            )
        }
        "attest" => (
            JsonValue::Null,
            JsonValue::Null,
            object([
                (
                    "bundleOutput",
                    step.id.as_deref().map_or(JsonValue::Null, |id| {
                        string(&format!("${{{{ steps.{id}.outputs.bundle-path }}}}"))
                    }),
                ),
                ("predicatePath", optional_input(inputs, "predicate-path")),
                ("predicateType", optional_input(inputs, "predicate-type")),
                (
                    "subjectChecksums",
                    optional_input(inputs, "subject-checksums"),
                ),
            ]),
        ),
        _ => (JsonValue::Null, JsonValue::Null, JsonValue::Null),
    }
}

fn paired_artifact_digest(artifact_id: &str) -> Option<String> {
    artifact_id
        .strip_suffix("artifact_id }}")
        .map(|prefix| format!("{prefix}artifact_digest }}}}"))
}

fn optional_input(inputs: &[(String, String)], name: &str) -> JsonValue {
    input(inputs, name).map_or(JsonValue::Null, string)
}

fn path_input(inputs: &[(String, String)], name: &str) -> JsonValue {
    input(inputs, name).map_or(JsonValue::Null, |value| {
        JsonValue::Array(value.lines().map(string).collect())
    })
}

fn input<'a>(inputs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    inputs
        .iter()
        .find_map(|(key, value)| (key == name).then_some(value.as_str()))
}

fn approved_credential_executables(manifest: &Manifest) -> BTreeSet<String> {
    manifest
        .workflows
        .values()
        .flat_map(|workflow| workflow.job_specs.values())
        .flat_map(|job| job.steps.iter())
        .filter_map(|step| match &step.operation {
            Operation::Run(invocation) if invocation.credential == Credential::GithubToken => {
                Some(invocation.executable.clone())
            }
            _ => None,
        })
        .collect()
}

fn project_permission(permission: &Permission) -> JsonValue {
    object([
        ("actions", string(access(permission.actions))),
        (
            "artifactMetadata",
            string(access(permission.artifact_metadata)),
        ),
        ("attestations", string(access(permission.attestations))),
        ("contents", string(access(permission.contents))),
        ("idToken", string(access(permission.id_token))),
    ])
}

fn access(access: Access) -> &'static str {
    match access {
        Access::None => "none",
        Access::Read => "read",
        Access::Write => "write",
    }
}

fn object<const N: usize>(fields: [(&str, JsonValue); N]) -> JsonValue {
    JsonValue::Object(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

fn string(value: &str) -> JsonValue {
    JsonValue::String(value.to_owned())
}
