use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};

use serde_yaml::{Mapping, Value};

use super::model::{Access, Credential, Manifest, MergeGroup, Permission, Workflow};

#[derive(Clone, Debug)]
pub(super) struct Diagnostic {
    pub code: &'static str,
    pub message: String,
}

impl Diagnostic {
    pub(super) fn manifest(message: impl Into<String>) -> Self {
        Self {
            code: "workflow.protocol.invalid",
            message: message.into(),
        }
    }

    fn drift(message: impl Into<String>) -> Self {
        Self {
            code: "workflow.generated.drift",
            message: message.into(),
        }
    }
}

pub(super) fn workflows(
    manifest: &Manifest,
    repository_root: &Path,
    workflow_root: &Path,
) -> Result<(), Diagnostic> {
    regular_directory(repository_root, "repository root")?;
    regular_directory(workflow_root, "workflow directory")?;
    let expected_names = manifest
        .workflows
        .values()
        .map(|workflow| {
            workflow
                .path
                .file_name()
                .expect("validated below")
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    let observed_names = fs::read_dir(workflow_root)
        .map_err(|error| {
            Diagnostic::drift(format!("cannot read {}: {error}", workflow_root.display()))
        })?
        .map(|entry| {
            let entry = entry.map_err(|error| {
                Diagnostic::drift(format!("cannot read workflow directory entry: {error}"))
            })?;
            let metadata = entry.file_type().map_err(|error| {
                Diagnostic::drift(format!(
                    "cannot inspect {}: {error}",
                    entry.path().display()
                ))
            })?;
            if !metadata.is_file() || metadata.is_symlink() {
                return Err(Diagnostic::drift(format!(
                    "{} is not a regular workflow file",
                    entry.path().display()
                )));
            }
            Ok(entry.file_name())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if observed_names != expected_names {
        return Err(Diagnostic::drift(format!(
            "workflow file inventory differs: expected {expected_names:?}, observed {observed_names:?}"
        )));
    }
    for workflow in manifest.workflows.values() {
        validate_relative_workflow_path(&workflow.path)?;
        let file_name = workflow.path.file_name().ok_or_else(|| {
            Diagnostic::manifest(format!("workflow {} has no filename", workflow.id))
        })?;
        let path = workflow_root.join(file_name);
        validate_workflow(manifest, workflow, &path)?;
        let observed = read_bounded_regular(&path)?;
        let generated = super::render::workflow_bytes(manifest, workflow)?;
        if observed != generated {
            return Err(Diagnostic::drift(format!(
                "{} differs byte-for-byte from its typed protocol rendering",
                path.display()
            )));
        }
    }
    Ok(())
}

fn validate_workflow(
    manifest: &Manifest,
    expected: &Workflow,
    path: &Path,
) -> Result<(), Diagnostic> {
    let bytes = read_bounded_regular(path)?;
    if !bytes.ends_with(b"\n") {
        return Err(Diagnostic::drift(format!(
            "{} has no trailing newline",
            path.display()
        )));
    }
    let document: Value = serde_yaml::from_slice(&bytes)
        .map_err(|error| Diagnostic::drift(format!("cannot parse {}: {error}", path.display())))?;
    let root = mapping(&document, "workflow root")?;
    reject_key(root, "shell", "workflow root")?;
    reject_key(root, "env", "workflow root")?;
    expect_string(
        member(root, "name", "workflow root")?,
        &expected.name,
        "workflow name",
    )?;
    validate_trigger(member(root, "on", "workflow root")?, manifest, expected)?;
    validate_concurrency(member(root, "concurrency", "workflow root")?, expected)?;
    let workflow_permission = parse_permission(member(root, "permissions", "workflow root")?)?;
    let jobs = mapping(member(root, "jobs", "workflow root")?, "jobs")?;
    let observed_jobs = string_keys(jobs, "jobs")?;
    let expected_jobs = expected.jobs.iter().cloned().collect::<BTreeSet<_>>();
    if observed_jobs != expected_jobs {
        return Err(Diagnostic::drift(format!(
            "{} job inventory differs",
            expected.id
        )));
    }
    for job_id in &expected.jobs {
        let job = mapping(member(jobs, job_id, "jobs")?, "job")?;
        reject_key(job, "shell", "job")?;
        reject_key(job, "env", "job")?;
        let spec = expected
            .job_specs
            .get(job_id)
            .expect("manifest loader built exact job map");
        expect_string(member(job, "runs-on", "job")?, &spec.runner, "job runner")?;
        expect_u64(
            member(job, "timeout-minutes", "job")?,
            spec.timeout_minutes,
            "job timeout",
        )?;
        validate_needs(
            job.get(Value::String("needs".to_owned())),
            &spec.needs,
            job_id,
        )?;
        validate_permission(
            job.get(Value::String("permissions".to_owned())),
            &workflow_permission,
            manifest
                .permissions
                .get(&spec.permission)
                .expect("reference checked"),
            job_id,
        )?;
        let steps = sequence(member(job, "steps", "job")?, "job steps")?;
        validate_steps(manifest, steps, job_id, &spec.command)?;
    }
    Ok(())
}

fn validate_trigger(
    value: &Value,
    manifest: &Manifest,
    workflow: &Workflow,
) -> Result<(), Diagnostic> {
    let trigger = mapping(value, "workflow trigger")?;
    let has_push = trigger.contains_key(Value::String("push".to_owned()));
    let has_pull = trigger.contains_key(Value::String("pull_request".to_owned()));
    let has_dispatch = trigger.contains_key(Value::String("workflow_dispatch".to_owned()));
    let has_merge = trigger.contains_key(Value::String("merge_group".to_owned()));
    if has_push != workflow.trigger.push.branches
        || has_pull != workflow.trigger.pull_request
        || has_dispatch != workflow.trigger.workflow_dispatch
    {
        return Err(Diagnostic::drift(format!(
            "{} trigger topology differs",
            workflow.id
        )));
    }
    let expected_merge = match workflow.trigger.merge_group {
        MergeGroup::Always => true,
        MergeGroup::Conditional => manifest.merge_queue,
        MergeGroup::Never => false,
    };
    if has_merge != expected_merge {
        return Err(Diagnostic::drift(format!(
            "{} merge-group trigger differs",
            workflow.id
        )));
    }
    if workflow.trigger.push.branches {
        let push = mapping(member(trigger, "push", "trigger")?, "push trigger")?;
        let has_tags_ignore = push.contains_key(Value::String("tags-ignore".to_owned()));
        let has_tags = push.contains_key(Value::String("tags".to_owned()));
        if workflow.trigger.push.tags == has_tags_ignore || workflow.trigger.push.tags != has_tags {
            return Err(Diagnostic::drift(format!(
                "{} tag trigger differs",
                workflow.id
            )));
        }
        let observed_paths =
            optional_string_sequence(push.get(Value::String("paths".to_owned())), "push paths")?;
        if observed_paths != workflow.trigger.paths {
            return Err(Diagnostic::drift(format!(
                "{} path trigger differs",
                workflow.id
            )));
        }
    }
    Ok(())
}

fn validate_concurrency(value: &Value, workflow: &Workflow) -> Result<(), Diagnostic> {
    let concurrency = mapping(value, "concurrency")?;
    expect_string(
        member(concurrency, "group", "concurrency")?,
        &workflow.concurrency.group,
        "concurrency group",
    )?;
    expect_bool(
        member(concurrency, "cancel-in-progress", "concurrency")?,
        workflow.concurrency.cancel_in_progress,
        "concurrency cancellation",
    )
}

fn validate_steps(
    manifest: &Manifest,
    steps: &[Value],
    job_id: &str,
    principal_command: &str,
) -> Result<(), Diagnostic> {
    if steps.is_empty() {
        return Err(Diagnostic::drift(format!("job {job_id} has no steps")));
    }
    let expected_principal = manifest
        .commands
        .get(principal_command)
        .expect("reference checked");
    let expected_invocation = super::render::render_invocation(
        &expected_principal.executable,
        &expected_principal.arguments,
    );
    let mut principal_count = 0_usize;
    let mut observed_runs = Vec::new();
    let mut step_ids = BTreeSet::new();
    for (index, value) in steps.iter().enumerate() {
        let step = mapping(value, "step")?;
        reject_key(step, "shell", "step")?;
        if let Some(id) = step.get(Value::String("id".to_owned())) {
            let id = scalar_string(id, "step id")?;
            if !step_ids.insert(id.to_owned()) {
                return Err(Diagnostic::drift(format!(
                    "job {job_id} has duplicate step id {id}"
                )));
            }
        }
        let run = step.get(Value::String("run".to_owned()));
        let uses = step.get(Value::String("uses".to_owned()));
        if run.is_some() == uses.is_some() {
            return Err(Diagnostic::drift(format!(
                "job {job_id} step {index} must contain exactly one of run or uses"
            )));
        }
        match (run, uses) {
            (Some(run), None) => {
                let run = scalar_string(run, "run invocation")?;
                validate_invocation(run)?;
                if observed_runs.len() < 64 {
                    observed_runs.push(run.to_owned());
                }
                let credential = validate_step_environment(step, job_id, index)?;
                if run == expected_invocation {
                    principal_count += 1;
                    if credential != expected_principal.credential {
                        return Err(Diagnostic::drift(format!(
                            "job {job_id} principal command credential differs"
                        )));
                    }
                }
            }
            (None, Some(uses)) => {
                if step.contains_key(Value::String("env".to_owned())) {
                    return Err(Diagnostic::drift(format!(
                        "job {job_id} action step {index} exposes an environment"
                    )));
                }
                validate_action(manifest, scalar_string(uses, "action reference")?, step)?;
            }
            _ => unreachable!("exclusive run/uses checked"),
        }
    }
    if principal_count != 1 {
        return Err(Diagnostic::drift(format!(
            "job {job_id} must contain its declared principal command exactly once; expected {expected_invocation:?}, observed {observed_runs:?}"
        )));
    }
    Ok(())
}

fn validate_action(manifest: &Manifest, uses: &str, step: &Mapping) -> Result<(), Diagnostic> {
    let (repository, revision) = uses
        .split_once('@')
        .ok_or_else(|| Diagnostic::drift(format!("action {uses} is not pinned")))?;
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Diagnostic::drift(format!(
            "action {uses} is not pinned to a lowercase full commit SHA"
        )));
    }
    let action = manifest
        .actions
        .values()
        .find(|action| action.repository == repository && action.revision == revision)
        .ok_or_else(|| {
            Diagnostic::drift(format!("action {uses} is not declared by the protocol"))
        })?;
    if let Some(with) = step.get(Value::String("with".to_owned())) {
        let with = mapping(with, "action inputs")?;
        let observed = string_keys(with, "action inputs")?;
        let allowed = action.inputs.iter().cloned().collect::<BTreeSet<_>>();
        if !observed.is_subset(&allowed) {
            return Err(Diagnostic::drift(format!(
                "action {uses} has undeclared inputs"
            )));
        }
    }
    Ok(())
}

fn validate_invocation(invocation: &str) -> Result<(), Diagnostic> {
    if invocation.is_empty() || invocation.contains(['\n', '\r', '\0', '`']) {
        return Err(Diagnostic::drift("run invocation is empty or multiline"));
    }
    let bytes = invocation.as_bytes();
    let mut index = 0_usize;
    let mut tokens = 0_usize;
    while index < bytes.len() {
        while index < bytes.len() && bytes[index] == b' ' {
            index += 1;
        }
        if index == bytes.len() {
            break;
        }
        tokens += 1;
        if bytes[index..].starts_with(b"${{") {
            let end = find_expression_end(&bytes[index..])
                .ok_or_else(|| Diagnostic::drift("unterminated workflow expression"))?;
            let expression = &invocation[index..index + end];
            if expression.contains("secrets.")
                || expression.contains("vars.")
                || expression.contains("inputs.")
            {
                return Err(Diagnostic::drift(
                    "untrusted workflow expression in run invocation",
                ));
            }
            index += end;
            if index < bytes.len() && bytes[index] != b' ' {
                return Err(Diagnostic::drift(
                    "workflow expression must occupy one complete argument",
                ));
            }
            continue;
        }
        let start = index;
        while index < bytes.len() && bytes[index] != b' ' {
            if matches!(bytes[index], b';' | b'|' | b'>' | b'<' | b'&') {
                return Err(Diagnostic::drift("shell operator in run invocation"));
            }
            index += 1;
        }
        if invocation[start..index].contains("$(") || invocation[start..index].contains("${") {
            return Err(Diagnostic::drift("shell expansion in run invocation"));
        }
    }
    if tokens == 0 {
        return Err(Diagnostic::drift("run invocation has no executable"));
    }
    Ok(())
}

fn find_expression_end(bytes: &[u8]) -> Option<usize> {
    let mut index = 3_usize;
    while index + 1 < bytes.len() {
        if bytes[index] == b'}' && bytes[index + 1] == b'}' {
            return Some(index + 2);
        }
        index += 1;
    }
    None
}

fn validate_step_environment(
    step: &Mapping,
    job: &str,
    index: usize,
) -> Result<Credential, Diagnostic> {
    let Some(environment) = step.get(Value::String("env".to_owned())) else {
        return Ok(Credential::None);
    };
    let environment = mapping(environment, "step environment")?;
    if environment.len() != 1 {
        return Err(Diagnostic::drift(format!(
            "job {job} step {index} has unapproved environment entries"
        )));
    }
    let value = member(environment, "GITHUB_TOKEN", "step environment")?;
    expect_string(value, "${{ github.token }}", "GitHub token expression")?;
    Ok(Credential::GithubToken)
}

fn validate_needs(value: Option<&Value>, expected: &[String], job: &str) -> Result<(), Diagnostic> {
    let observed = match value {
        None => Vec::new(),
        Some(Value::String(value)) => vec![value.clone()],
        Some(value) => string_sequence(value, "job needs")?,
    };
    if observed != expected {
        return Err(Diagnostic::drift(format!("job {job} needs differs")));
    }
    Ok(())
}

fn validate_permission(
    value: Option<&Value>,
    inherited: &Permission,
    expected: &Permission,
    job: &str,
) -> Result<(), Diagnostic> {
    let observed = match value {
        None => inherited.clone(),
        Some(value) => parse_permission(value)?,
    };
    if &observed != expected {
        return Err(Diagnostic::drift(format!("job {job} permissions differ")));
    }
    Ok(())
}

fn parse_permission(value: &Value) -> Result<Permission, Diagnostic> {
    let mapping = mapping(value, "permissions")?;
    Ok(Permission {
        actions: permission_value(mapping, "actions")?,
        contents: permission_value(mapping, "contents")?,
        id_token: permission_value(mapping, "id-token")?,
        attestations: permission_value(mapping, "attestations")?,
        artifact_metadata: permission_value(mapping, "artifact-metadata")?,
    })
}

fn permission_value(mapping: &Mapping, key: &str) -> Result<Access, Diagnostic> {
    match mapping.get(Value::String(key.to_owned())) {
        None => Ok(Access::None),
        Some(Value::String(value)) if value == "read" => Ok(Access::Read),
        Some(Value::String(value)) if value == "write" => Ok(Access::Write),
        _ => Err(Diagnostic::drift(format!("invalid permission {key}"))),
    }
}

fn validate_relative_workflow_path(path: &Path) -> Result<(), Diagnostic> {
    if path.extension().and_then(|value| value.to_str()) != Some("yml")
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || path.parent() != Some(Path::new(".github/workflows"))
    {
        return Err(Diagnostic::manifest(format!(
            "invalid workflow path {}",
            path.display()
        )));
    }
    Ok(())
}

pub(super) fn validate_repository_path(path: &Path, label: &str) -> Result<(), Diagnostic> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(Diagnostic::manifest(format!(
            "{label} path {} is not normalized and repository-relative",
            path.display()
        )));
    }
    Ok(())
}

fn regular_directory(path: &Path, label: &str) -> Result<(), Diagnostic> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Diagnostic::drift(format!(
            "cannot inspect {label} {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Diagnostic::drift(format!(
            "{label} {} is not a regular directory",
            path.display()
        )));
    }
    Ok(())
}

fn read_bounded_regular(path: &Path) -> Result<Vec<u8>, Diagnostic> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Diagnostic::drift(format!("cannot inspect {}: {error}", path.display()))
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 2 * 1024 * 1024
    {
        return Err(Diagnostic::drift(format!(
            "{} is not a bounded regular workflow",
            path.display()
        )));
    }
    let bytes = fs::read(path)
        .map_err(|error| Diagnostic::drift(format!("cannot read {}: {error}", path.display())))?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(Diagnostic::drift(format!(
            "{} changed while being read",
            path.display()
        )));
    }
    Ok(bytes)
}

fn mapping<'a>(value: &'a Value, label: &str) -> Result<&'a Mapping, Diagnostic> {
    value
        .as_mapping()
        .ok_or_else(|| Diagnostic::drift(format!("{label} is not a mapping")))
}

fn sequence<'a>(value: &'a Value, label: &str) -> Result<&'a [Value], Diagnostic> {
    value
        .as_sequence()
        .map(Vec::as_slice)
        .ok_or_else(|| Diagnostic::drift(format!("{label} is not a sequence")))
}

fn member<'a>(mapping: &'a Mapping, key: &str, label: &str) -> Result<&'a Value, Diagnostic> {
    mapping
        .get(Value::String(key.to_owned()))
        .ok_or_else(|| Diagnostic::drift(format!("{label} is missing {key}")))
}

fn reject_key(mapping: &Mapping, key: &str, label: &str) -> Result<(), Diagnostic> {
    if mapping.contains_key(Value::String(key.to_owned())) {
        Err(Diagnostic::drift(format!(
            "{label} contains forbidden {key}"
        )))
    } else {
        Ok(())
    }
}

fn string_keys(mapping: &Mapping, label: &str) -> Result<BTreeSet<String>, Diagnostic> {
    mapping
        .keys()
        .map(|key| scalar_string(key, label).map(str::to_owned))
        .collect()
}

fn scalar_string<'a>(value: &'a Value, label: &str) -> Result<&'a str, Diagnostic> {
    value
        .as_str()
        .ok_or_else(|| Diagnostic::drift(format!("{label} is not a string")))
}

fn expect_string(value: &Value, expected: &str, label: &str) -> Result<(), Diagnostic> {
    let observed = scalar_string(value, label)?;
    if observed == expected {
        Ok(())
    } else {
        Err(Diagnostic::drift(format!(
            "{label} differs: expected {expected:?}, observed {observed:?}"
        )))
    }
}

fn expect_bool(value: &Value, expected: bool, label: &str) -> Result<(), Diagnostic> {
    if value.as_bool() == Some(expected) {
        Ok(())
    } else {
        Err(Diagnostic::drift(format!("{label} differs")))
    }
}

fn expect_u64(value: &Value, expected: u64, label: &str) -> Result<(), Diagnostic> {
    if value.as_u64() == Some(expected) {
        Ok(())
    } else {
        Err(Diagnostic::drift(format!("{label} differs")))
    }
}

fn string_sequence(value: &Value, label: &str) -> Result<Vec<String>, Diagnostic> {
    sequence(value, label)?
        .iter()
        .map(|value| scalar_string(value, label).map(str::to_owned))
        .collect()
}

fn optional_string_sequence(value: Option<&Value>, label: &str) -> Result<Vec<String>, Diagnostic> {
    value
        .map(|value| string_sequence(value, label))
        .transpose()
        .map(Option::unwrap_or_default)
}
