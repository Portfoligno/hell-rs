use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use serde_yaml::{Mapping, Value};

use super::model::Manifest;
use crate::release::manifest::write_atomic;

const BEGIN: &str = "# BEGIN GENERATED PHYSICAL WORKFLOW MODEL";
const END: &str = "# END GENERATED PHYSICAL WORKFLOW MODEL";

pub(super) fn steps(manifest: &Path, workflows: &Path, output: &Path) -> Result<String, String> {
    let manifest_bytes = bounded_regular(manifest, 4 * 1024 * 1024)?;
    let manifest_text = std::str::from_utf8(&manifest_bytes)
        .map_err(|_| format!("{} is not UTF-8", manifest.display()))?;
    let base = remove_generated_region(manifest_text)?;
    let assignments = crate::strict_toml::assignments(&base)?;
    let action_ids = action_ids(&assignments)?;
    let permission_ids = permission_ids(&assignments)?;
    let workflow_ids = workflow_ids(&assignments)?;
    let mut generated = String::new();
    generated.push_str(BEGIN);
    generated.push('\n');
    for workflow_id in workflow_ids {
        let path = quoted_assignment(&assignments, &format!("workflow.{workflow_id}.path"))?;
        let file_name = Path::new(&path)
            .file_name()
            .ok_or_else(|| format!("workflow {workflow_id} path has no filename"))?;
        let document = bounded_regular(&workflows.join(file_name), 2 * 1024 * 1024)?;
        let value: Value = serde_yaml::from_slice(&document)
            .map_err(|error| format!("cannot parse workflow {workflow_id}: {error}"))?;
        import_workflow(
            &mut generated,
            &assignments,
            &action_ids,
            &permission_ids,
            &workflow_id,
            &value,
        )?;
    }
    generated.push_str(END);
    generated.push('\n');
    let mut complete = base;
    if !complete.ends_with('\n') {
        complete.push('\n');
    }
    complete.push('\n');
    complete.push_str(&generated);
    write_atomic(output, complete.as_bytes())?;
    Manifest::read(output).map_err(|diagnostic| diagnostic.message)?;
    Ok(format!(
        "imported physical workflow model into {}",
        output.display()
    ))
}

fn import_workflow(
    output: &mut String,
    assignments: &BTreeMap<String, String>,
    action_ids: &BTreeMap<(String, String), String>,
    permission_ids: &BTreeMap<[String; 5], String>,
    workflow_id: &str,
    document: &Value,
) -> Result<(), String> {
    let root = mapping(document, "workflow root")?;
    let workflow_prefix = format!("physical.workflow.{workflow_id}");
    writeln!(output, "\n[{workflow_prefix}]").expect("writing to String cannot fail");
    if let Some(run_name) = root.get(Value::String("run-name".to_owned())) {
        write_string_assignment(output, "run-name", scalar(run_name, "run-name")?);
    }
    let permission = permission_identity(member(root, "permissions", "workflow root")?)?;
    let permission_id = permission_ids
        .get(&permission)
        .ok_or_else(|| format!("workflow {workflow_id} has an undeclared permission class"))?;
    write_string_assignment(output, "permission", permission_id);
    let dispatch_inputs = workflow_dispatch_inputs(root)?;
    write_string_array_assignment(
        output,
        "dispatch-inputs",
        dispatch_inputs.keys().map(String::as_str),
    );
    for (id, input) in dispatch_inputs {
        let input = mapping(&input, "dispatch input")?;
        writeln!(output, "\n[{workflow_prefix}.dispatch-input.{id}]")
            .expect("writing to String cannot fail");
        write_string_assignment(
            output,
            "description",
            scalar(
                member(input, "description", "dispatch input")?,
                "dispatch input description",
            )?,
        );
        writeln!(
            output,
            "required = {}",
            boolean(
                member(input, "required", "dispatch input")?,
                "dispatch input required"
            )?
        )
        .expect("writing to String cannot fail");
        write_string_assignment(
            output,
            "type",
            scalar(
                member(input, "type", "dispatch input")?,
                "dispatch input type",
            )?,
        );
    }
    let jobs = mapping(member(root, "jobs", "workflow root")?, "jobs")?;
    let declared_jobs =
        string_array_assignment(assignments, &format!("workflow.{workflow_id}.jobs"))?;
    let observed_jobs = jobs
        .keys()
        .map(|key| scalar(key, "job id").map(str::to_owned))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if observed_jobs != declared_jobs.iter().cloned().collect() {
        return Err(format!(
            "workflow {workflow_id} job inventory differs from the manifest"
        ));
    }
    for job_id in declared_jobs {
        import_job(
            output,
            action_ids,
            workflow_id,
            &job_id,
            mapping(member(jobs, &job_id, "jobs")?, "job")?,
        )?;
    }
    Ok(())
}

fn import_job(
    output: &mut String,
    action_ids: &BTreeMap<(String, String), String>,
    workflow: &str,
    job_id: &str,
    job: &Mapping,
) -> Result<(), String> {
    let prefix = format!("physical.job.{workflow}.{job_id}");
    writeln!(output, "\n[{prefix}]").expect("writing to String cannot fail");
    write_string_assignment(
        output,
        "name",
        scalar(member(job, "name", "job")?, "job name")?,
    );
    if let Some(condition) = job.get(Value::String("if".to_owned())) {
        write_string_assignment(output, "if", scalar(condition, "job condition")?);
    }
    let outputs = job
        .get(Value::String("outputs".to_owned()))
        .map(|value| mapping(value, "job outputs"))
        .transpose()?
        .map(ordered_scalar_mapping)
        .transpose()?
        .unwrap_or_default();
    write_string_array_assignment(
        output,
        "outputs",
        outputs.iter().map(|(name, _)| name.as_str()),
    );
    let steps = sequence(member(job, "steps", "job")?, "steps")?;
    let step_ids = (0..steps.len())
        .map(|index| format!("s{index:03}"))
        .collect::<Vec<_>>();
    write_string_array_assignment(output, "steps", step_ids.iter().map(String::as_str));
    for (name, value) in outputs {
        write_string_assignment(output, &format!("output.{name}"), &value);
    }
    for (step_id, step) in step_ids.iter().zip(steps) {
        import_step(
            output,
            action_ids,
            workflow,
            job_id,
            step_id,
            mapping(step, "step")?,
        )?;
    }
    Ok(())
}

fn import_step(
    output: &mut String,
    action_ids: &BTreeMap<(String, String), String>,
    workflow: &str,
    job: &str,
    step_id: &str,
    step: &Mapping,
) -> Result<(), String> {
    let prefix = format!("physical.step.{workflow}.{job}.{step_id}");
    writeln!(output, "\n[{prefix}]").expect("writing to String cannot fail");
    write_string_assignment(
        output,
        "name",
        scalar(member(step, "name", "step")?, "step name")?,
    );
    if let Some(id) = step.get(Value::String("id".to_owned())) {
        write_string_assignment(output, "id", scalar(id, "step id")?);
    }
    if let Some(condition) = step.get(Value::String("if".to_owned())) {
        write_string_assignment(output, "if", scalar(condition, "step condition")?);
    }
    if let Some(directory) = step.get(Value::String("working-directory".to_owned())) {
        write_string_assignment(
            output,
            "working-directory",
            scalar(directory, "working directory")?,
        );
    }
    match (
        step.get(Value::String("run".to_owned())),
        step.get(Value::String("uses".to_owned())),
    ) {
        (Some(run), None) => {
            write_string_assignment(output, "kind", "run");
            let tokens = invocation_tokens(scalar(run, "run")?)?;
            let (executable, arguments) = tokens
                .split_first()
                .ok_or_else(|| "run has no executable".to_owned())?;
            write_string_assignment(output, "executable", executable);
            write_string_array_assignment(
                output,
                "arguments",
                arguments.iter().map(String::as_str),
            );
            let credential = credential(step)?;
            write_string_assignment(output, "credential", credential);
        }
        (None, Some(uses)) => {
            write_string_assignment(output, "kind", "action");
            let uses = scalar(uses, "uses")?;
            let (repository, revision) = uses
                .split_once('@')
                .ok_or_else(|| format!("action {uses} is not pinned"))?;
            let action = action_ids
                .get(&(repository.to_owned(), revision.to_owned()))
                .ok_or_else(|| format!("action {uses} is undeclared"))?;
            write_string_assignment(output, "action", action);
            let inputs = step
                .get(Value::String("with".to_owned()))
                .map(|value| mapping(value, "action inputs"))
                .transpose()?
                .map(ordered_scalar_mapping)
                .transpose()?
                .unwrap_or_default();
            write_string_array_assignment(
                output,
                "with-order",
                inputs.iter().map(|(name, _)| name.as_str()),
            );
            for (name, value) in inputs {
                write_string_assignment(output, &format!("with.{name}"), &value);
            }
            if step.contains_key(Value::String("env".to_owned())) {
                return Err("action step has an environment".to_owned());
            }
        }
        _ => return Err("step must contain exactly one of run or uses".to_owned()),
    }
    Ok(())
}

fn credential(step: &Mapping) -> Result<&'static str, String> {
    let Some(environment) = step.get(Value::String("env".to_owned())) else {
        return Ok("none");
    };
    let environment = mapping(environment, "step environment")?;
    if environment.len() != 1
        || scalar(
            member(environment, "GITHUB_TOKEN", "step environment")?,
            "GITHUB_TOKEN",
        )? != "${{ github.token }}"
    {
        return Err("run step environment is not the closed GitHub token capability".to_owned());
    }
    Ok("github-token")
}

fn workflow_dispatch_inputs(root: &Mapping) -> Result<BTreeMap<String, Value>, String> {
    let trigger = mapping(member(root, "on", "workflow root")?, "trigger")?;
    let Some(dispatch) = trigger.get(Value::String("workflow_dispatch".to_owned())) else {
        return Ok(BTreeMap::new());
    };
    let dispatch = mapping(dispatch, "workflow dispatch")?;
    let Some(inputs) = dispatch.get(Value::String("inputs".to_owned())) else {
        return Ok(BTreeMap::new());
    };
    mapping(inputs, "workflow dispatch inputs")?
        .iter()
        .map(|(key, value)| Ok((scalar(key, "dispatch input id")?.to_owned(), value.clone())))
        .collect()
}

fn action_ids(
    assignments: &BTreeMap<String, String>,
) -> Result<BTreeMap<(String, String), String>, String> {
    let ids = assignments
        .keys()
        .filter_map(|key| key.strip_prefix("action.")?.split('.').next())
        .collect::<BTreeSet<_>>();
    let mut result = BTreeMap::new();
    for id in ids {
        let repository = quoted_assignment(assignments, &format!("action.{id}.repository"))?;
        let revision = quoted_assignment(assignments, &format!("action.{id}.ref"))?;
        if result
            .insert((repository, revision), id.to_owned())
            .is_some()
        {
            return Err("duplicate action authority in protocol manifest".to_owned());
        }
    }
    Ok(result)
}

fn permission_ids(
    assignments: &BTreeMap<String, String>,
) -> Result<BTreeMap<[String; 5], String>, String> {
    let ids = assignments
        .keys()
        .filter_map(|key| key.strip_prefix("permission.")?.split('.').next())
        .collect::<BTreeSet<_>>();
    let mut result = BTreeMap::new();
    for id in ids {
        let identity = [
            "actions",
            "contents",
            "id-token",
            "attestations",
            "artifact-metadata",
        ]
        .map(|name| quoted_assignment(assignments, &format!("permission.{id}.{name}")))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .expect("permission identity has five fields");
        if result.insert(identity, id.to_owned()).is_some() {
            return Err("duplicate permission class in protocol manifest".to_owned());
        }
    }
    Ok(result)
}

fn permission_identity(value: &Value) -> Result<[String; 5], String> {
    let mapping = mapping(value, "permissions")?;
    Ok([
        "actions",
        "contents",
        "id-token",
        "attestations",
        "artifact-metadata",
    ]
    .map(|name| {
        mapping
            .get(Value::String(name.to_owned()))
            .and_then(Value::as_str)
            .unwrap_or("none")
            .to_owned()
    }))
}

fn workflow_ids(assignments: &BTreeMap<String, String>) -> Result<Vec<String>, String> {
    let ids = assignments
        .keys()
        .filter_map(|key| {
            let rest = key.strip_prefix("workflow.")?;
            let (id, field) = rest.split_once('.')?;
            (field == "path").then(|| id.to_owned())
        })
        .collect::<Vec<_>>();
    if ids.len() != 6 || ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err("protocol manifest must declare six distinct workflows".to_owned());
    }
    Ok(ids)
}

fn remove_generated_region(document: &str) -> Result<String, String> {
    match (document.find(BEGIN), document.find(END)) {
        (None, None) => Ok(document.to_owned()),
        (Some(begin), Some(end)) if begin < end => {
            let after = end + END.len();
            let mut result = document[..begin].trim_end().to_owned();
            result.push('\n');
            result.push_str(document[after..].trim_start_matches(['\r', '\n']));
            Ok(result)
        }
        _ => Err("physical workflow model markers are inconsistent".to_owned()),
    }
}

fn invocation_tokens(value: &str) -> Result<Vec<String>, String> {
    if value.is_empty() || value.contains(['\0', '\n', '\r', '`']) {
        return Err("run invocation is empty or multiline".to_owned());
    }
    let bytes = value.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0_usize;
    while index < bytes.len() {
        while index < bytes.len() && bytes[index] == b' ' {
            index += 1;
        }
        if index == bytes.len() {
            break;
        }
        let start = index;
        if bytes[index..].starts_with(b"${{") {
            while index + 1 < bytes.len() && !(bytes[index] == b'}' && bytes[index + 1] == b'}') {
                index += 1;
            }
            if index + 1 == bytes.len() {
                return Err("unterminated workflow expression".to_owned());
            }
            index += 2;
            if index < bytes.len() && bytes[index] != b' ' {
                return Err("workflow expression is not a whole token".to_owned());
            }
        } else {
            while index < bytes.len() && bytes[index] != b' ' {
                if matches!(bytes[index], b';' | b'|' | b'>' | b'<' | b'&') {
                    return Err("shell operator in run invocation".to_owned());
                }
                index += 1;
            }
        }
        tokens.push(normalize_workflow_argument(&value[start..index])?);
    }
    Ok(tokens)
}

fn normalize_workflow_argument(value: &str) -> Result<String, String> {
    let Some(expression) = value
        .strip_prefix("${{ ")
        .and_then(|value| value.strip_suffix(" }}"))
    else {
        return Ok(value.to_owned());
    };
    if let Some(reference) = expression.strip_prefix("needs.") {
        let mut components = reference.split('.');
        let job = components
            .next()
            .ok_or_else(|| "job output lacks job".to_owned())?;
        if components.next() != Some("outputs") {
            return Err("run expression is not a whole-token job output".to_owned());
        }
        let output = components
            .next()
            .ok_or_else(|| "job output lacks output".to_owned())?;
        if components.next().is_some() {
            return Err("job output has trailing components".to_owned());
        }
        return Ok(format!(
            "$output:{job}.artifact.{}",
            output.replace('_', "-")
        ));
    }
    if let Some(reference) = expression.strip_prefix("steps.") {
        let mut components = reference.split('.');
        let step = components
            .next()
            .ok_or_else(|| "step output lacks step".to_owned())?;
        if components.next() != Some("outputs") {
            return Err("run expression is not a whole-token step output".to_owned());
        }
        let output = components
            .next()
            .ok_or_else(|| "step output lacks output".to_owned())?;
        if components.next().is_some() {
            return Err("step output has trailing components".to_owned());
        }
        return Ok(format!("$output:{step}.action.{output}"));
    }
    if let Some(reference) = expression.strip_prefix("github.") {
        if reference.is_empty() || reference.contains('.') {
            return Err("trusted GitHub context reference has invalid shape".to_owned());
        }
        return Ok(format!("$github:{reference}"));
    }
    Err("run expression is not an approved whole-token reference".to_owned())
}

fn ordered_scalar_mapping(mapping: &Mapping) -> Result<Vec<(String, String)>, String> {
    mapping
        .iter()
        .map(|(key, value)| {
            let value = match value {
                Value::String(value) => value.clone(),
                Value::Bool(value) => value.to_string(),
                Value::Number(value) => value.to_string(),
                _ => return Err("physical mapping value is not a scalar".to_owned()),
            };
            Ok((scalar(key, "mapping key")?.to_owned(), value))
        })
        .collect()
}

fn write_string_assignment(output: &mut String, key: &str, value: &str) {
    write!(output, "{key} = ").expect("writing to String cannot fail");
    write_toml_string(output, value);
    output.push('\n');
}

fn write_string_array_assignment<'a>(
    output: &mut String,
    key: &str,
    values: impl IntoIterator<Item = &'a str>,
) {
    write!(output, "{key} = [").expect("writing to String cannot fail");
    let mut separator = "";
    for value in values {
        output.push_str(separator);
        write_toml_string(output, value);
        separator = ", ";
    }
    output.push_str("]\n");
}

fn write_toml_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                write!(output, "\\u{:04x}", u32::from(character))
                    .expect("writing to String cannot fail");
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

fn quoted_assignment(assignments: &BTreeMap<String, String>, key: &str) -> Result<String, String> {
    crate::strict_toml::string(
        assignments
            .get(key)
            .ok_or_else(|| format!("manifest lacks {key}"))?,
    )
}

fn string_array_assignment(
    assignments: &BTreeMap<String, String>,
    key: &str,
) -> Result<Vec<String>, String> {
    crate::strict_toml::string_array(
        assignments
            .get(key)
            .ok_or_else(|| format!("manifest lacks {key}"))?,
    )
}

fn bounded_regular(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(format!("{} is not a bounded regular file", path.display()));
    }
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(format!("{} changed while being read", path.display()));
    }
    Ok(bytes)
}

fn mapping<'a>(value: &'a Value, label: &str) -> Result<&'a Mapping, String> {
    value
        .as_mapping()
        .ok_or_else(|| format!("{label} is not a mapping"))
}

fn sequence<'a>(value: &'a Value, label: &str) -> Result<&'a [Value], String> {
    value
        .as_sequence()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("{label} is not a sequence"))
}

fn member<'a>(mapping: &'a Mapping, key: &str, label: &str) -> Result<&'a Value, String> {
    mapping
        .get(Value::String(key.to_owned()))
        .ok_or_else(|| format!("{label} lacks {key}"))
}

fn scalar<'a>(value: &'a Value, label: &str) -> Result<&'a str, String> {
    value
        .as_str()
        .ok_or_else(|| format!("{label} is not a string"))
}

fn boolean(value: &Value, label: &str) -> Result<bool, String> {
    value
        .as_bool()
        .ok_or_else(|| format!("{label} is not a boolean"))
}
