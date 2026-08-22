use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use super::model::{
    Access, Action, Concurrency, Credential, DispatchInput, Invocation, Job, Manifest, MergeGroup,
    Operation, Permission, PhysicalWorkflow, PushTrigger, ReadinessArtifact, ReadinessSummary,
    Step, Trigger, Workflow,
};
use super::validate::Diagnostic;
use crate::strict_toml;

impl Manifest {
    pub(super) fn read(path: &Path) -> Result<Self, Diagnostic> {
        let (sha256, mut values) = read_manifest_values(path)?;
        let schema = integer(&take(&mut values, "schema-version")?)?;
        if schema != 1 {
            return Err(Diagnostic::manifest(format!(
                "unsupported protocol schema version {schema}"
            )));
        }
        let protocol_id = string(&take(&mut values, "protocol-id")?)?;
        if protocol_id != "hell-rs-ci-v1" {
            return Err(Diagnostic::manifest(format!(
                "unsupported protocol id {protocol_id}"
            )));
        }
        let release_protocol = string(&take(&mut values, "release-admission-protocol")?)?;
        if release_protocol != "release-admission-v1" {
            return Err(Diagnostic::manifest(format!(
                "unsupported release protocol {release_protocol}"
            )));
        }
        let merge_queue = boolean(&take(&mut values, "merge-queue")?)?;
        let action_metadata = PathBuf::from(string(&take(&mut values, "action-metadata")?)?);
        super::validate::validate_repository_path(&action_metadata, "action metadata")?;
        let readiness_jobs = string_array(&take(&mut values, "readiness-summary.jobs")?)?;
        unique(&readiness_jobs, "readiness-summary.jobs")?;
        let mut readiness_artifacts = Vec::new();
        for job in &readiness_jobs {
            let prefix = format!("readiness-summary.artifact.{job}");
            readiness_artifacts.push(ReadinessArtifact {
                job: job.clone(),
                platform_id: optional_string(&mut values, &format!("{prefix}.platform-id"))?,
                input_path: string(&take(&mut values, &format!("{prefix}.input-path"))?)?,
                artifact_id_output: string(&take(
                    &mut values,
                    &format!("{prefix}.artifact-id-output"),
                )?)?,
                artifact_digest_output: string(&take(
                    &mut values,
                    &format!("{prefix}.artifact-digest-output"),
                )?)?,
            });
        }
        let readiness = ReadinessSummary {
            jobs: readiness_jobs,
            artifacts: readiness_artifacts,
        };
        let workflow_ids = sections(&values, "workflow", 2);
        let expected = [
            "ci",
            "mutation",
            "nightly",
            "regression-corpus",
            "regression-subject",
            "release",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
        if workflow_ids != expected {
            return Err(Diagnostic::manifest(format!(
                "workflow inventory differs: expected {expected:?}, observed {workflow_ids:?}"
            )));
        }
        let actions = load_actions(&mut values)?;
        let permissions = load_permissions(&mut values)?;
        let commands = load_commands(&mut values)?;
        let workflows = load_workflows(&mut values, workflow_ids)?;
        validate_references(&workflows, &actions, &permissions, &commands)?;
        let unknown_physical = values
            .keys()
            .filter(|key| key.starts_with("physical."))
            .cloned()
            .collect::<Vec<_>>();
        if !unknown_physical.is_empty() {
            return Err(Diagnostic::manifest(format!(
                "unknown physical workflow keys {unknown_physical:?}"
            )));
        }
        Ok(Self {
            sha256,
            action_metadata,
            merge_queue,
            readiness,
            workflows,
            actions,
            permissions,
            commands,
        })
    }
}

fn read_manifest_values(path: &Path) -> Result<(String, BTreeMap<String, String>), Diagnostic> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Diagnostic::manifest(format!("cannot inspect {}: {error}", path.display()))
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 4 * 1024 * 1024
    {
        return Err(Diagnostic::manifest(format!(
            "{} must be a bounded regular protocol manifest",
            path.display()
        )));
    }
    let bytes = fs::read(path).map_err(|error| {
        Diagnostic::manifest(format!("cannot read {}: {error}", path.display()))
    })?;
    if !bytes.ends_with(b"\n") {
        return Err(Diagnostic::manifest(format!(
            "{} has no trailing newline",
            path.display()
        )));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Diagnostic::manifest(format!("{} is not UTF-8", path.display())))?;
    let values = strict_toml::assignments(text).map_err(Diagnostic::manifest)?;
    Ok((hell_testkit::sha256_bytes(&bytes).hex(), values))
}

fn load_workflows(
    values: &mut BTreeMap<String, String>,
    workflow_ids: BTreeSet<String>,
) -> Result<BTreeMap<String, Workflow>, Diagnostic> {
    workflow_ids
        .into_iter()
        .map(|id| load_workflow(values, id).map(|workflow| (workflow.id.clone(), workflow)))
        .collect()
}

fn load_workflow(
    values: &mut BTreeMap<String, String>,
    id: String,
) -> Result<Workflow, Diagnostic> {
    let prefix = format!("workflow.{id}");
    let path = string(&take(values, &format!("{prefix}.path"))?)?.into();
    let name = string(&take(values, &format!("{prefix}.name"))?)?;
    let jobs = string_array(&take(values, &format!("{prefix}.jobs"))?)?;
    unique(&jobs, &format!("{prefix}.jobs"))?;
    let trigger = load_trigger(values, &prefix)?;
    let concurrency = load_concurrency(values, &prefix)?;
    let physical = load_physical_workflow(values, &id)?;
    let job_specs = load_jobs(values, &id, &jobs)?;
    Ok(Workflow {
        id,
        path,
        name,
        jobs,
        trigger,
        concurrency,
        physical,
        job_specs,
    })
}

fn load_trigger(
    values: &mut BTreeMap<String, String>,
    workflow_prefix: &str,
) -> Result<Trigger, Diagnostic> {
    let prefix = format!("{workflow_prefix}.trigger");
    let merge_group = match string(&take(values, &format!("{prefix}.merge-group"))?)?.as_str() {
        "always" => MergeGroup::Always,
        "conditional" => MergeGroup::Conditional,
        "never" => MergeGroup::Never,
        other => return Err(Diagnostic::manifest(format!("invalid merge-group {other}"))),
    };
    let paths = values
        .remove(&format!("{prefix}.paths"))
        .map(|value| string_array(&value))
        .transpose()?
        .unwrap_or_default();
    Ok(Trigger {
        push: PushTrigger {
            branches: boolean(&take(values, &format!("{prefix}.push-branches"))?)?,
            tags: boolean(&take(values, &format!("{prefix}.push-tags"))?)?,
        },
        pull_request: boolean(&take(values, &format!("{prefix}.pull-request"))?)?,
        workflow_dispatch: boolean(&take(values, &format!("{prefix}.workflow-dispatch"))?)?,
        merge_group,
        paths,
    })
}

fn load_concurrency(
    values: &mut BTreeMap<String, String>,
    workflow_prefix: &str,
) -> Result<Concurrency, Diagnostic> {
    let prefix = format!("{workflow_prefix}.concurrency");
    Ok(Concurrency {
        group: string(&take(values, &format!("{prefix}.group"))?)?,
        cancel_in_progress: boolean(&take(values, &format!("{prefix}.cancel-in-progress"))?)?,
    })
}

fn load_physical_workflow(
    values: &mut BTreeMap<String, String>,
    workflow: &str,
) -> Result<PhysicalWorkflow, Diagnostic> {
    let prefix = format!("physical.workflow.{workflow}");
    let order = values
        .remove(&format!("{prefix}.dispatch-inputs"))
        .map(|value| string_array(&value))
        .transpose()?
        .unwrap_or_default();
    let mut dispatch_inputs = Vec::new();
    for id in order {
        let input_prefix = format!("{prefix}.dispatch-input.{id}");
        dispatch_inputs.push(DispatchInput {
            id,
            description: string(&take(values, &format!("{input_prefix}.description"))?)?,
            required: boolean(&take(values, &format!("{input_prefix}.required"))?)?,
            kind: string(&take(values, &format!("{input_prefix}.type"))?)?,
        });
    }
    Ok(PhysicalWorkflow {
        run_name: optional_string(values, &format!("{prefix}.run-name"))?,
        permission: string(&take(values, &format!("{prefix}.permission"))?)?,
        dispatch_inputs,
    })
}

fn load_jobs(
    values: &mut BTreeMap<String, String>,
    workflow: &str,
    jobs: &[String],
) -> Result<BTreeMap<String, Job>, Diagnostic> {
    jobs.iter()
        .map(|id| load_job(values, workflow, id).map(|job| (id.clone(), job)))
        .collect()
}

fn load_job(
    values: &mut BTreeMap<String, String>,
    workflow: &str,
    id: &str,
) -> Result<Job, Diagnostic> {
    let prefix = format!("job.{workflow}.{id}");
    let physical = format!("physical.job.{workflow}.{id}");
    let needs = string_array(&take(values, &format!("{prefix}.needs"))?)?;
    unique(&needs, &format!("{prefix}.needs"))?;
    let outputs = load_job_outputs(values, &physical)?;
    let steps = load_job_steps(values, workflow, id, &physical)?;
    let job = Job {
        needs,
        runner: string(&take(values, &format!("{prefix}.runner"))?)?,
        timeout_minutes: integer(&take(values, &format!("{prefix}.timeout-minutes"))?)?,
        permission: string(&take(values, &format!("{prefix}.permission"))?)?,
        command: string(&take(values, &format!("{prefix}.command"))?)?,
        artifact_output: string(&take(values, &format!("{prefix}.artifact-output"))?)?,
        physical_name: string(&take(values, &format!("{physical}.name"))?)?,
        condition: optional_string(values, &format!("{physical}.if"))?,
        outputs,
        steps,
    };
    values.remove(&format!("{prefix}.vector-artifact-output"));
    Ok(job)
}

fn load_job_outputs(
    values: &mut BTreeMap<String, String>,
    physical: &str,
) -> Result<Vec<(String, String)>, Diagnostic> {
    let order = values
        .remove(&format!("{physical}.outputs"))
        .map(|value| string_array(&value))
        .transpose()?
        .unwrap_or_default();
    unique(&order, &format!("{physical}.outputs"))?;
    order
        .into_iter()
        .map(|output| {
            let value = string(&take(values, &format!("{physical}.output.{output}"))?)?;
            Ok((output, value))
        })
        .collect()
}

fn load_job_steps(
    values: &mut BTreeMap<String, String>,
    workflow: &str,
    job: &str,
    physical: &str,
) -> Result<Vec<Step>, Diagnostic> {
    let order = string_array(&take(values, &format!("{physical}.steps"))?)?;
    unique(&order, &format!("{physical}.steps"))?;
    order
        .into_iter()
        .map(|step| load_step(values, workflow, job, &step))
        .collect()
}

fn load_step(
    values: &mut BTreeMap<String, String>,
    workflow: &str,
    job: &str,
    id: &str,
) -> Result<Step, Diagnostic> {
    let prefix = format!("physical.step.{workflow}.{job}.{id}");
    let name = string(&take(values, &format!("{prefix}.name"))?)?;
    let step_id = optional_string(values, &format!("{prefix}.id"))?;
    let condition = optional_string(values, &format!("{prefix}.if"))?;
    let working_directory = optional_string(values, &format!("{prefix}.working-directory"))?;
    let kind = string(&take(values, &format!("{prefix}.kind"))?)?;
    let operation = match kind.as_str() {
        "run" => {
            let executable = string(&take(values, &format!("{prefix}.executable"))?)?;
            let arguments = string_array(&take(values, &format!("{prefix}.arguments"))?)?;
            let credential = match string(&take(values, &format!("{prefix}.credential"))?)?.as_str()
            {
                "none" => Credential::None,
                "github-token" => Credential::GithubToken,
                other => {
                    return Err(Diagnostic::manifest(format!(
                        "invalid step credential {other}"
                    )));
                }
            };
            Operation::Run(Invocation {
                executable,
                arguments,
                credential,
            })
        }
        "action" => {
            let action = string(&take(values, &format!("{prefix}.action"))?)?;
            let order = values
                .remove(&format!("{prefix}.with-order"))
                .map(|value| string_array(&value))
                .transpose()?
                .unwrap_or_default();
            unique(&order, &format!("{prefix}.with-order"))?;
            let mut inputs = Vec::new();
            for input in order {
                inputs.push((
                    input.clone(),
                    string(&take(values, &format!("{prefix}.with.{input}"))?)?,
                ));
            }
            Operation::Action { action, inputs }
        }
        other => {
            return Err(Diagnostic::manifest(format!(
                "invalid physical step kind {other}"
            )));
        }
    };
    Ok(Step {
        name,
        id: step_id,
        condition,
        working_directory,
        operation,
    })
}

fn load_actions(
    values: &mut BTreeMap<String, String>,
) -> Result<BTreeMap<String, Action>, Diagnostic> {
    let mut result = BTreeMap::new();
    for id in sections(values, "action", 2) {
        let prefix = format!("action.{id}");
        let action = Action {
            repository: string(&take(values, &format!("{prefix}.repository"))?)?,
            revision: string(&take(values, &format!("{prefix}.ref"))?)?,
            inputs: string_array(&take(values, &format!("{prefix}.inputs"))?)?,
            outputs: string_array(&take(values, &format!("{prefix}.outputs"))?)?,
        };
        unique(&action.inputs, &format!("{prefix}.inputs"))?;
        unique(&action.outputs, &format!("{prefix}.outputs"))?;
        result.insert(id, action);
    }
    Ok(result)
}

fn load_permissions(
    values: &mut BTreeMap<String, String>,
) -> Result<BTreeMap<String, Permission>, Diagnostic> {
    let mut result = BTreeMap::new();
    for id in sections(values, "permission", 2) {
        let prefix = format!("permission.{id}");
        result.insert(
            id,
            Permission {
                actions: access(&take(values, &format!("{prefix}.actions"))?)?,
                contents: access(&take(values, &format!("{prefix}.contents"))?)?,
                id_token: access(&take(values, &format!("{prefix}.id-token"))?)?,
                attestations: access(&take(values, &format!("{prefix}.attestations"))?)?,
                artifact_metadata: access(&take(values, &format!("{prefix}.artifact-metadata"))?)?,
            },
        );
    }
    Ok(result)
}

fn load_commands(
    values: &mut BTreeMap<String, String>,
) -> Result<BTreeMap<String, Invocation>, Diagnostic> {
    let mut result = BTreeMap::new();
    for id in sections(values, "command", 2) {
        let prefix = format!("command.{id}");
        let credential = match string(&take(values, &format!("{prefix}.credential"))?)?.as_str() {
            "none" => Credential::None,
            "github-token" => Credential::GithubToken,
            other => return Err(Diagnostic::manifest(format!("invalid credential {other}"))),
        };
        let invocation = Invocation {
            executable: string(&take(values, &format!("{prefix}.executable"))?)?,
            arguments: string_array(&take(values, &format!("{prefix}.arguments"))?)?,
            credential,
        };
        result.insert(id, invocation);
    }
    Ok(result)
}

fn validate_references(
    workflows: &BTreeMap<String, Workflow>,
    actions: &BTreeMap<String, Action>,
    permissions: &BTreeMap<String, Permission>,
    commands: &BTreeMap<String, Invocation>,
) -> Result<(), Diagnostic> {
    for workflow in workflows.values() {
        if !permissions.contains_key(&workflow.physical.permission) {
            return Err(Diagnostic::manifest(format!(
                "workflow {} references unknown permission {}",
                workflow.id, workflow.physical.permission
            )));
        }
        for (id, job) in &workflow.job_specs {
            if !permissions.contains_key(&job.permission) {
                return Err(Diagnostic::manifest(format!(
                    "job {}.{id} references unknown permission {}",
                    workflow.id, job.permission
                )));
            }
            if !commands.contains_key(&job.command) {
                return Err(Diagnostic::manifest(format!(
                    "job {}.{id} references unknown command {}",
                    workflow.id, job.command
                )));
            }
            for need in &job.needs {
                if !workflow.job_specs.contains_key(need) {
                    return Err(Diagnostic::manifest(format!(
                        "job {}.{id} needs unknown job {need}",
                        workflow.id
                    )));
                }
            }
            let principal = commands
                .get(&job.command)
                .expect("command reference checked");
            let mut principal_count = 0_usize;
            for step in &job.steps {
                match &step.operation {
                    Operation::Action { action, inputs } => {
                        let action_spec = actions.get(action).ok_or_else(|| {
                            Diagnostic::manifest(format!(
                                "job {}.{id} references unknown action {action}",
                                workflow.id
                            ))
                        })?;
                        let allowed = action_spec.inputs.iter().collect::<BTreeSet<_>>();
                        if inputs.iter().any(|(name, _)| !allowed.contains(name)) {
                            return Err(Diagnostic::manifest(format!(
                                "job {}.{id} supplies an undeclared input to action {action}",
                                workflow.id
                            )));
                        }
                    }
                    Operation::Run(invocation)
                        if invocation.executable == principal.executable
                            && invocation.arguments == principal.arguments
                            && invocation.credential == principal.credential =>
                    {
                        principal_count += 1;
                    }
                    Operation::Run(_) => {}
                }
            }
            if principal_count != 1 {
                return Err(Diagnostic::manifest(format!(
                    "job {}.{id} does not contain its declared principal command exactly once",
                    workflow.id
                )));
            }
        }
    }
    Ok(())
}

fn sections(
    values: &BTreeMap<String, String>,
    namespace: &str,
    component_count: usize,
) -> BTreeSet<String> {
    values
        .keys()
        .filter_map(|key| {
            let rest = key.strip_prefix(namespace)?.strip_prefix('.')?;
            let mut components = rest.split('.');
            let id = components.next()?;
            (rest.split('.').count() >= component_count - 1).then(|| id.to_owned())
        })
        .collect()
}

fn take(values: &mut BTreeMap<String, String>, key: &str) -> Result<String, Diagnostic> {
    strict_toml::take(values, key).map_err(Diagnostic::manifest)
}

fn string(value: &str) -> Result<String, Diagnostic> {
    parse_basic_string(value)
}

fn optional_string(
    values: &mut BTreeMap<String, String>,
    key: &str,
) -> Result<Option<String>, Diagnostic> {
    values.remove(key).map(|value| string(&value)).transpose()
}

fn string_array(value: &str) -> Result<Vec<String>, Diagnostic> {
    let inner = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| Diagnostic::manifest(format!("expected string array, observed {value:?}")))?
        .trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    let mut start = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in inner.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                result.push(parse_basic_string(inner[start..index].trim())?);
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    if quoted || escaped {
        return Err(Diagnostic::manifest("unterminated string array item"));
    }
    let tail = inner[start..]
        .trim()
        .strip_suffix(',')
        .unwrap_or(inner[start..].trim())
        .trim();
    if !tail.is_empty() {
        result.push(parse_basic_string(tail)?);
    }
    Ok(result)
}

fn parse_basic_string(value: &str) -> Result<String, Diagnostic> {
    let inner = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| {
            Diagnostic::manifest(format!("expected quoted string, observed {value:?}"))
        })?;
    let mut output = String::new();
    let mut characters = inner.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' => match characters.next() {
                Some('\\') => output.push('\\'),
                Some('"') => output.push('"'),
                Some('n') => output.push('\n'),
                Some('r') => output.push('\r'),
                Some('t') => output.push('\t'),
                Some(other) => {
                    return Err(Diagnostic::manifest(format!(
                        "unsupported TOML escape \\{other}"
                    )));
                }
                None => return Err(Diagnostic::manifest("unterminated TOML escape")),
            },
            '\n' | '\r' | '\0' => return Err(Diagnostic::manifest("multiline or NUL TOML string")),
            other => output.push(other),
        }
    }
    Ok(output)
}

fn boolean(value: &str) -> Result<bool, Diagnostic> {
    strict_toml::boolean(value).map_err(Diagnostic::manifest)
}

fn integer(value: &str) -> Result<u64, Diagnostic> {
    let parsed = value.parse::<u64>().map_err(|_| {
        Diagnostic::manifest(format!(
            "expected canonical unsigned integer, observed {value:?}"
        ))
    })?;
    if value != parsed.to_string() {
        return Err(Diagnostic::manifest(format!(
            "noncanonical unsigned integer {value:?}"
        )));
    }
    Ok(parsed)
}

fn access(value: &str) -> Result<Access, Diagnostic> {
    match string(value)?.as_str() {
        "none" => Ok(Access::None),
        "read" => Ok(Access::Read),
        "write" => Ok(Access::Write),
        other => Err(Diagnostic::manifest(format!(
            "invalid permission access {other}"
        ))),
    }
}

fn unique(values: &[String], name: &str) -> Result<(), Diagnostic> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(Diagnostic::manifest(format!("{name} contains duplicates")));
    }
    Ok(())
}
