use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::json::{JsonValue, canonical_json_bytes, json_member};
use crate::release::manifest::{read_json, write_atomic};

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments.first().and_then(|value| value.to_str()) == Some("regression-import")
}

pub(crate) fn run_cli(arguments: &[OsString]) -> ExitCode {
    match run(arguments) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(10)
        }
    }
}

fn run(arguments: &[OsString]) -> Result<String, String> {
    if arguments.get(1).and_then(|value| value.to_str()) != Some("explore-generated") {
        return Err("only automatic generated-regression exploration remains supported".to_owned());
    }
    if arguments.len() != 6 {
        return Err("regression exploration requires exact --input and --output paths".to_owned());
    }
    let input = option(arguments, "--input")?;
    let output = option(arguments, "--output")?;
    explore_generated(&input, &output)
}

fn option(arguments: &[OsString], name: &str) -> Result<PathBuf, String> {
    let mut found = None;
    for pair in arguments[2..].chunks_exact(2) {
        if pair[0].to_str() == Some(name) && found.replace(PathBuf::from(&pair[1])).is_some() {
            return Err(format!("{name} was provided more than once"));
        }
    }
    found.ok_or_else(|| format!("{name} is required"))
}

fn explore_generated(input: &Path, output: &Path) -> Result<String, String> {
    if output.exists() {
        return Err("generated regression exploration output already exists".to_owned());
    }
    let inventory = read_json(&input.join("generated-regression-inventory.json"))?;
    let inventory = inventory.object()?;
    let case_ids = json_member(inventory, "caseIds")?
        .array()?
        .iter()
        .map(|value| value.string().map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    if case_ids
        .iter()
        .any(|id| !id.starts_with("generated-") || !hell_builtins::validate_case_id(id))
    {
        return Err("generated regression inventory contains an invalid case ID".to_owned());
    }
    fs::create_dir(output)
        .map_err(|error| format!("cannot create {}: {error}", output.display()))?;
    for id in &case_ids {
        let source = input.join("mismatches/proposed-regressions").join(id);
        copy_tree(&source, &output.join(id))?;
    }
    let manifest = JsonValue::Object(BTreeMap::from([
        (
            "caseIds".to_owned(),
            JsonValue::Array(case_ids.iter().cloned().map(JsonValue::String).collect()),
        ),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
        (
            "state".to_owned(),
            JsonValue::String(if case_ids.is_empty() {
                "no-generated-mismatches".to_owned()
            } else {
                "retained-unreviewed-nonclaim".to_owned()
            }),
        ),
    ]));
    write_atomic(
        &output.join("manifest.json"),
        &canonical_json_bytes(&manifest)?,
    )?;
    Ok(format!(
        "retained {} unreviewed generated regressions",
        case_ids.len()
    ))
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("cannot inspect {}: {error}", source.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "regression source is not a real directory: {}",
            source.display()
        ));
    }
    fs::create_dir(destination)
        .map_err(|error| format!("cannot create {}: {error}", destination.display()))?;
    for entry in fs::read_dir(source)
        .map_err(|error| format!("cannot enumerate {}: {error}", source.display()))?
    {
        let entry = entry.map_err(|error| format!("cannot inspect regression entry: {error}"))?;
        let kind = entry
            .file_type()
            .map_err(|error| format!("cannot inspect regression entry type: {error}"))?;
        if kind.is_symlink() {
            return Err("regression input contains a symlink".to_owned());
        }
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), &target)
                .map_err(|error| format!("cannot copy regression evidence: {error}"))?;
        } else {
            return Err("regression input contains a special file".to_owned());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retired_regression_authority_actions_are_unrecognized() {
        let arguments = ["regression-import", "promote"]
            .map(OsString::from)
            .to_vec();
        assert!(run(&arguments).is_err());
    }
}
