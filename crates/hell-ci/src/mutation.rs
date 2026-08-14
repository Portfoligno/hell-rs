use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use hell_testkit::{sha256_bytes, sha256_file};

use crate::command::CommandSpec;
use crate::identity::require_git_sha;
use crate::json::{JsonValue, canonical_json_bytes};
use crate::release::manifest::write_atomic;

#[derive(Clone)]
struct Mutant {
    id: String,
    family: String,
    class: String,
    criticality: String,
    package: String,
    target: String,
    test: String,
    site: String,
    obligation: String,
    claim_group: String,
}

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments.first().and_then(|value| value.to_str()) == Some("mutation")
}

pub(crate) fn active(id: &str) -> bool {
    if !cfg!(feature = "mutation-testing") {
        return false;
    }
    let arguments = std::env::args_os().collect::<Vec<_>>();
    let selected = selected_mutant(&arguments);
    selected.as_deref() == Some(id)
}

fn selected_mutant(arguments: &[OsString]) -> Option<String> {
    let marker_count = arguments
        .iter()
        .filter(|argument| *argument == "__hell_mutant")
        .count();
    if marker_count == 0 {
        return None;
    }
    let selections = arguments
        .windows(4)
        .filter(|window| {
            window[0] == "--skip" && window[1] == "__hell_mutant" && window[2] == "--skip"
        })
        .collect::<Vec<_>>();
    assert_eq!(marker_count, 1, "mutation argv marker must be unique");
    assert_eq!(selections.len(), 1, "mutation argv is malformed");
    Some(
        selections[0][3]
            .to_str()
            .expect("mutation id must be UTF-8")
            .to_owned(),
    )
}

pub(crate) fn run_cli(root: &Path, arguments: &[OsString]) -> ExitCode {
    let result = parse_output(arguments).and_then(|output| {
        let candidate = git_head(root)?;
        release_mutation_catalog(root, &output, &candidate)
    });
    match result {
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

pub(crate) fn release_mutation_catalog(
    root: &Path,
    output: &Path,
    candidate_sha: &str,
) -> Result<String, String> {
    require_git_sha(candidate_sha, "release mutation candidate")?;
    if git_head(root)? != candidate_sha {
        return Err("release mutation checkout differs from the planned candidate".to_owned());
    }
    let catalog_path = root.join("compat/mutants.toml");
    let catalog = fs::read_to_string(&catalog_path)
        .map_err(|error| format!("cannot read mutation catalog: {error}"))?;
    if catalog.as_bytes() != include_bytes!("../../../compat/mutants.toml") {
        return Err("candidate mutation catalog differs from trusted automation".to_owned());
    }
    let values = crate::strict_toml::assignments(&catalog)?;
    let ids = strings(&values, "ids")?;
    let required = booleans(&values, "release_required")?;
    let required_ids = required_mutant_ids_from_values(&values)?;
    let columns = [
        strings(&values, "families")?,
        strings(&values, "classes")?,
        strings(&values, "criticalities")?,
        strings(&values, "packages")?,
        strings(&values, "targets")?,
        strings(&values, "tests")?,
        strings(&values, "mutation_sites")?,
        strings(&values, "obligation_ids")?,
        strings(&values, "claim_group_ids")?,
    ];
    if required.len() != ids.len()
        || columns.iter().any(|column| column.len() != ids.len())
        || ids.iter().collect::<BTreeSet<_>>().len() != ids.len()
        || !required.iter().any(|value| *value)
    {
        return Err("release mutation catalog columns disagree".to_owned());
    }
    let results = output
        .parent()
        .ok_or_else(|| "release mutation output has no directory".to_owned())?
        .join("mutation-results");
    fs::create_dir_all(&results)
        .map_err(|error| format!("cannot create mutation results: {error}"))?;
    let mut records = Vec::new();
    for (index, selected) in required.iter().copied().enumerate() {
        if !selected {
            continue;
        }
        let mutant = Mutant {
            id: ids[index].clone(),
            family: columns[0][index].clone(),
            class: columns[1][index].clone(),
            criticality: columns[2][index].clone(),
            package: columns[3][index].clone(),
            target: columns[4][index].clone(),
            test: columns[5][index].clone(),
            site: columns[6][index].clone(),
            obligation: columns[7][index].clone(),
            claim_group: columns[8][index].clone(),
        };
        records.push(run_mutant(root, &results, index, &mutant)?);
    }
    let report = JsonValue::Object(BTreeMap::from([
        (
            "candidateSha".to_owned(),
            JsonValue::String(candidate_sha.to_owned()),
        ),
        (
            "catalogSha256".to_owned(),
            JsonValue::String(
                sha256_file(&catalog_path)
                    .map_err(|error| format!("cannot hash mutation catalog: {error}"))?
                    .hex(),
            ),
        ),
        (
            "detected".to_owned(),
            JsonValue::Number(
                records
                    .len()
                    .try_into()
                    .map_err(|_| "mutant count overflow")?,
            ),
        ),
        ("mutants".to_owned(), JsonValue::Array(records)),
        (
            "required".to_owned(),
            JsonValue::Number(
                required
                    .iter()
                    .filter(|value| **value)
                    .count()
                    .try_into()
                    .map_err(|_| "mutant count overflow")?,
            ),
        ),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
        ("state".to_owned(), JsonValue::String("passed".to_owned())),
    ]));
    write_atomic(output, &canonical_json_bytes(&report)?)?;
    Ok(format!(
        "killed {} release-required mutants",
        required_ids.len()
    ))
}

pub(crate) fn trusted_required_mutant_ids() -> Result<BTreeSet<String>, String> {
    let trusted = std::str::from_utf8(include_bytes!("../../../compat/mutants.toml"))
        .map_err(|_| "trusted mutation catalog is not UTF-8".to_owned())?;
    let values = crate::strict_toml::assignments(trusted)?;
    required_mutant_ids_from_values(&values)
}

fn required_mutant_ids_from_values(
    values: &BTreeMap<String, String>,
) -> Result<BTreeSet<String>, String> {
    let ids = strings(values, "ids")?;
    let required = booleans(values, "release_required")?;
    if ids.len() != required.len() || ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err("release mutation catalog ID/selection columns disagree".to_owned());
    }
    let selected = ids
        .into_iter()
        .zip(required)
        .filter_map(|(id, selected)| selected.then_some(id))
        .collect::<BTreeSet<_>>();
    if selected.is_empty() {
        return Err("release mutation catalog selects no required mutants".to_owned());
    }
    Ok(selected)
}

fn run_mutant(
    root: &Path,
    results: &Path,
    index: usize,
    mutant: &Mutant,
) -> Result<JsonValue, String> {
    let arguments = cargo_arguments(mutant)?;
    let cargo = CommandSpec::cargo(Duration::from_mins(10)).current_directory(root);
    let baseline = cargo
        .clone()
        .arguments(arguments.iter().map(String::as_str))
        .run()
        .map_err(|error| format!("cannot run mutation baseline {}: {error}", mutant.id))?;
    let mut activated_arguments = arguments.clone();
    activated_arguments.extend([
        "--skip".to_owned(),
        "__hell_mutant".to_owned(),
        "--skip".to_owned(),
        mutant.id.clone(),
    ]);
    let activated = cargo
        .arguments(activated_arguments.iter().map(String::as_str))
        .run()
        .map_err(|error| format!("cannot run mutation {}: {error}", mutant.id))?;
    if !exact_result(&baseline.stdout, &mutant.test, true)?
        || exact_result(&activated.stdout, &mutant.test, true)?
        || activated.status.success()
    {
        return Err(format!("release-required mutant survived: {}", mutant.id));
    }
    let result_path = results.join(format!("mutant-{index}.json"));
    let detail = JsonValue::Object(BTreeMap::from([
        (
            "baselineStatus".to_owned(),
            JsonValue::Number(u64::try_from(baseline.status.code().unwrap_or(255)).unwrap_or(255)),
        ),
        (
            "mutantStatus".to_owned(),
            JsonValue::Number(u64::try_from(activated.status.code().unwrap_or(255)).unwrap_or(255)),
        ),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
    ]));
    let detail_bytes = canonical_json_bytes(&detail)?;
    write_atomic(&result_path, &detail_bytes)?;
    let identity = mutation_identity(mutant, &arguments);
    Ok(JsonValue::Object(BTreeMap::from([
        ("class".to_owned(), JsonValue::String(mutant.class.clone())),
        (
            "criticality".to_owned(),
            JsonValue::String(mutant.criticality.clone()),
        ),
        ("detected".to_owned(), JsonValue::Bool(true)),
        (
            "family".to_owned(),
            JsonValue::String(mutant.family.clone()),
        ),
        ("id".to_owned(), JsonValue::String(mutant.id.clone())),
        (
            "mutationIdentitySha256".to_owned(),
            JsonValue::String(identity),
        ),
        (
            "resultSha256".to_owned(),
            JsonValue::String(sha256_bytes(&detail_bytes).hex()),
        ),
        (
            "strategy".to_owned(),
            JsonValue::String("baseline-pass-mutant-fail".to_owned()),
        ),
        ("test".to_owned(), JsonValue::String(mutant.test.clone())),
    ])))
}

fn cargo_arguments(mutant: &Mutant) -> Result<Vec<String>, String> {
    let mut arguments = vec![
        "test".to_owned(),
        "--locked".to_owned(),
        "-p".to_owned(),
        mutant.package.clone(),
        "--features".to_owned(),
        "mutation-testing".to_owned(),
    ];
    if mutant.target == "lib" {
        arguments.push("--lib".to_owned());
    } else if let Some(name) = mutant.target.strip_prefix("bin:") {
        arguments.extend(["--bin".to_owned(), name.to_owned()]);
    } else if let Some(name) = mutant.target.strip_prefix("test:") {
        arguments.extend(["--test".to_owned(), name.to_owned()]);
    } else {
        return Err(format!("mutation target is invalid: {}", mutant.target));
    }
    arguments.extend([mutant.test.clone(), "--".to_owned(), "--exact".to_owned()]);
    Ok(arguments)
}

fn exact_result(stdout: &[u8], test: &str, passed: bool) -> Result<bool, String> {
    let text =
        std::str::from_utf8(stdout).map_err(|_| "mutation test output is not UTF-8".to_owned())?;
    let suffix = if passed { " ... ok" } else { " ... FAILED" };
    Ok(text
        .lines()
        .filter(|line| *line == format!("test {test}{suffix}"))
        .count()
        == 1)
}

fn mutation_identity(mutant: &Mutant, arguments: &[String]) -> String {
    let mut bytes = b"hell-release-mutant-v1\0".to_vec();
    for value in [
        &mutant.id,
        &mutant.site,
        &mutant.obligation,
        &mutant.claim_group,
    ] {
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
    }
    for argument in arguments {
        bytes.extend_from_slice(argument.as_bytes());
        bytes.push(0);
    }
    sha256_bytes(&bytes).hex()
}

fn strings(values: &BTreeMap<String, String>, key: &str) -> Result<Vec<String>, String> {
    crate::strict_toml::string_array(
        values
            .get(key)
            .ok_or_else(|| format!("mutation catalog lacks {key}"))?,
    )
}

fn booleans(values: &BTreeMap<String, String>, key: &str) -> Result<Vec<bool>, String> {
    crate::strict_toml::boolean_array(
        values
            .get(key)
            .ok_or_else(|| format!("mutation catalog lacks {key}"))?,
    )
}

fn git_head(root: &Path) -> Result<String, String> {
    let result = CommandSpec::new("git", Duration::from_secs(30))
        .arguments(["rev-parse", "HEAD"])
        .current_directory(root)
        .run()
        .map_err(|error| format!("cannot resolve mutation candidate: {error}"))?;
    if !result.status.success() {
        return Err("cannot resolve mutation candidate".to_owned());
    }
    String::from_utf8(result.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| "mutation candidate is not UTF-8".to_owned())
}

fn parse_output(arguments: &[OsString]) -> Result<PathBuf, String> {
    if arguments.get(1).and_then(|value| value.to_str()) != Some("run")
        || arguments.get(2).and_then(|value| value.to_str()) != Some("--output")
        || arguments.len() != 4
    {
        return Err("mutation requires exact `run --output PATH`".to_owned());
    }
    Ok(PathBuf::from(&arguments[3]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_test_output_is_not_detection() {
        assert!(!exact_result(b"test result: ok. 0 passed; 0 failed\n", "named", true).unwrap());
    }

    #[test]
    fn candidate_cannot_weaken_release_required_selection() {
        let trusted = include_bytes!("../../../compat/mutants.toml");
        let weakened = String::from_utf8(trusted.to_vec())
            .unwrap()
            .replacen("true", "false", 1);
        assert_ne!(weakened.as_bytes(), trusted);
        let values = crate::strict_toml::assignments(&weakened).unwrap();
        assert_ne!(
            required_mutant_ids_from_values(&values).unwrap(),
            trusted_required_mutant_ids().unwrap()
        );
    }

    #[test]
    fn mutation_selection_requires_one_exact_typed_argv_shape() {
        let selected = [
            "test-binary",
            "--skip",
            "__hell_mutant",
            "--skip",
            "exact-id",
        ]
        .map(OsString::from);
        assert_eq!(selected_mutant(&selected).as_deref(), Some("exact-id"));
        assert_eq!(selected_mutant(&[OsString::from("test-binary")]), None);
    }

    #[test]
    #[should_panic(expected = "mutation argv is malformed")]
    fn malformed_mutation_selection_fails_closed() {
        let _ = selected_mutant(&["test-binary", "__hell_mutant", "exact-id"].map(OsString::from));
    }
}
