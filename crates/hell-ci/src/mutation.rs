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
    selected
        .as_deref()
        .is_some_and(|selected| selection_activates(selected, id))
}

/// Returns the exact typed mutation suffix selected for this test process.
///
/// The returned values are intended to be appended as separate argv tokens to
/// a feature-matched child binary. An ordinary non-mutation process returns an
/// empty vector.
///
/// # Errors
///
/// Returns an error if the selected mutation ID is not valid UTF-8.
pub fn test_activation_suffix() -> Result<Vec<OsString>, String> {
    #[cfg(feature = "mutation-testing")]
    {
        let arguments = std::env::args_os().collect::<Vec<_>>();
        try_selected_mutant(&arguments)?
            .map(|id| {
                ["--skip", "__hell_mutant", "--skip"]
                    .map(OsString::from)
                    .into_iter()
                    .chain([OsString::from(id)])
                    .collect()
            })
            .map_or_else(|| Ok(Vec::new()), Ok)
    }
    #[cfg(not(feature = "mutation-testing"))]
    Ok(Vec::new())
}

pub(crate) fn without_test_activation_suffix(
    arguments: &[OsString],
) -> Result<&[OsString], String> {
    #[cfg(feature = "mutation-testing")]
    {
        let marker_count = arguments
            .iter()
            .filter(|argument| *argument == "__hell_mutant")
            .count();
        if marker_count == 0 {
            return Ok(arguments);
        }
        if marker_count != 1 || arguments.len() < 4 {
            return Err("mutation argv suffix is malformed".to_owned());
        }
        let suffix = &arguments[arguments.len() - 4..];
        if suffix[0] != "--skip"
            || suffix[1] != "__hell_mutant"
            || suffix[2] != "--skip"
            || suffix[3].to_str().is_none()
        {
            return Err("mutation argv suffix is malformed".to_owned());
        }
        let selected = std::env::args_os().collect::<Vec<_>>();
        if try_selected_mutant(&selected)?.as_deref() != suffix[3].to_str() {
            return Err("mutation argv suffix differs from process activation".to_owned());
        }
        Ok(&arguments[..arguments.len() - 4])
    }
    #[cfg(not(feature = "mutation-testing"))]
    Ok(arguments)
}

fn selection_activates(selected: &str, site: &str) -> bool {
    selected == site
        || matches!(
            (selected, site),
            ("drop-final-cell", "required-cell-omitted-from-plan")
                | ("accept-duplicate-cell", "duplicate-cell-accepted")
                | (
                    "ignore-evidence-platform",
                    "native-platform-evidence-substitution"
                )
                | ("use-wall-clock-for-exemption", "exemption-expiry-bypassed")
        )
}

fn selected_mutant(arguments: &[OsString]) -> Option<String> {
    try_selected_mutant(arguments).unwrap_or_else(|error| panic!("{error}"))
}

fn try_selected_mutant(arguments: &[OsString]) -> Result<Option<String>, String> {
    let marker_count = arguments
        .iter()
        .filter(|argument| *argument == "__hell_mutant")
        .count();
    if marker_count == 0 {
        return Ok(None);
    }
    let selections = arguments
        .windows(4)
        .filter(|window| {
            window[0] == "--skip" && window[1] == "__hell_mutant" && window[2] == "--skip"
        })
        .collect::<Vec<_>>();
    if marker_count != 1 {
        return Err("mutation argv marker must be unique".to_owned());
    }
    if selections.len() != 1 {
        return Err("mutation argv is malformed".to_owned());
    }
    Ok(Some(
        selections[0][3]
            .to_str()
            .ok_or_else(|| "mutation id must be UTF-8".to_owned())?
            .to_owned(),
    ))
}

pub(crate) fn run_cli(root: &Path, arguments: &[OsString]) -> ExitCode {
    let result = match arguments.get(1).and_then(|value| value.to_str()) {
        Some("run") => parse_output(arguments).and_then(|output| {
            let candidate = git_head(root)?;
            release_mutation_catalog(root, &output, &candidate)
        }),
        Some("assurance") => {
            parse_assurance_options(arguments).and_then(|options| run_assurance(&options))
        }
        _ => Err("mutation requires `run` or `assurance`".to_owned()),
    };
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

#[derive(Debug)]
struct AssuranceOptions {
    manifest: PathBuf,
    repository_root: PathBuf,
    output: PathBuf,
}

#[derive(Debug)]
struct AssuranceMutant {
    id: String,
    claim: String,
    module: String,
    source: PathBuf,
    symbol: String,
    test_command: Vec<String>,
    vectors: Vec<String>,
}

fn run_assurance(options: &AssuranceOptions) -> Result<String, String> {
    let root = canonical_regular_directory(&options.repository_root, "mutation repository root")?;
    if options.output.exists() {
        return Err(format!(
            "mutation assurance output {} already exists",
            options.output.display()
        ));
    }
    let (catalog_id, mutants, manifest_bytes) = read_assurance_manifest(&options.manifest)?;
    if mutants.len() != 13 {
        return Err(format!(
            "mutation assurance requires exactly 13 mutants, observed {}",
            mutants.len()
        ));
    }
    let mut ids = BTreeSet::new();
    let mut records = Vec::new();
    for mutant in &mutants {
        if !ids.insert(mutant.id.clone()) {
            return Err(format!("duplicate assurance mutant {}", mutant.id));
        }
        validate_assurance_binding(&root, mutant)?;
        records.push(run_assurance_mutant(&root, mutant)?);
    }
    fs::create_dir_all(&options.output)
        .map_err(|error| format!("cannot create {}: {error}", options.output.display()))?;
    let report = JsonValue::Object(BTreeMap::from([
        ("catalogId".to_owned(), JsonValue::String(catalog_id)),
        (
            "catalogSha256".to_owned(),
            JsonValue::String(sha256_bytes(&manifest_bytes).hex()),
        ),
        ("mutants".to_owned(), JsonValue::Array(records)),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
        ("state".to_owned(), JsonValue::String("passed".to_owned())),
    ]));
    write_atomic(
        &options.output.join("assurance.json"),
        &canonical_json_bytes(&report)?,
    )?;
    Ok(format!(
        "killed {} source-bound assurance mutants",
        mutants.len()
    ))
}

fn run_assurance_mutant(root: &Path, mutant: &AssuranceMutant) -> Result<JsonValue, String> {
    let (program, arguments) = mutant
        .test_command
        .split_first()
        .ok_or_else(|| format!("mutant {} has an empty test command", mutant.id))?;
    if program != "cargo" {
        return Err(format!(
            "mutant {} test command executable must be cargo",
            mutant.id
        ));
    }
    validate_argument_vector(&mutant.id, arguments)?;
    let command = CommandSpec::new(program, Duration::from_mins(15)).current_directory(root);
    let baseline = command
        .clone()
        .arguments(arguments.iter().map(String::as_str))
        .run()
        .map_err(|error| format!("cannot run assurance baseline {}: {error}", mutant.id))?;
    if !baseline.status.success() || baseline.timed_out {
        return Err(format!("assurance baseline failed for {}", mutant.id));
    }
    let mut mutant_arguments = arguments.to_vec();
    if !mutant_arguments.iter().any(|argument| argument == "--") {
        mutant_arguments.push("--".to_owned());
    }
    mutant_arguments.extend([
        "--skip".to_owned(),
        "__hell_mutant".to_owned(),
        "--skip".to_owned(),
        mutant.id.clone(),
    ]);
    let activated = command
        .arguments(mutant_arguments.iter().map(String::as_str))
        .run()
        .map_err(|error| format!("cannot run assurance mutant {}: {error}", mutant.id))?;
    if activated.status.success() || activated.timed_out {
        return Err(format!("assurance mutant survived: {}", mutant.id));
    }
    Ok(JsonValue::Object(BTreeMap::from([
        ("claim".to_owned(), JsonValue::String(mutant.claim.clone())),
        ("detected".to_owned(), JsonValue::Bool(true)),
        ("id".to_owned(), JsonValue::String(mutant.id.clone())),
        (
            "module".to_owned(),
            JsonValue::String(mutant.module.clone()),
        ),
        (
            "source".to_owned(),
            JsonValue::String(mutant.source.to_string_lossy().into_owned()),
        ),
        (
            "symbol".to_owned(),
            JsonValue::String(mutant.symbol.clone()),
        ),
        (
            "vectors".to_owned(),
            JsonValue::Array(
                mutant
                    .vectors
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        ),
    ])))
}

fn validate_argument_vector(id: &str, arguments: &[String]) -> Result<(), String> {
    if arguments.is_empty()
        || !arguments.iter().any(|argument| argument == "test")
        || !arguments.iter().any(|argument| argument == "--locked")
    {
        return Err(format!(
            "mutant {id} test command must be a locked cargo test invocation"
        ));
    }
    for argument in arguments {
        if argument.is_empty()
            || argument.contains(['\0', '\n', '\r'])
            || ["sh", "bash", "-c", "&&", "||", ";", "|"].contains(&argument.as_str())
        {
            return Err(format!("mutant {id} contains an invalid test argument"));
        }
    }
    Ok(())
}

fn validate_assurance_binding(root: &Path, mutant: &AssuranceMutant) -> Result<(), String> {
    let source = safe_relative_path(root, &mutant.source, "mutant source")?;
    let bytes = read_bounded_regular(&source, 4 * 1024 * 1024, "mutant source")?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| format!("{} is not UTF-8", source.display()))?;
    if !contains_symbol(text, &mutant.symbol) {
        return Err(format!(
            "mutant {} symbol {} is absent from {}",
            mutant.id,
            mutant.symbol,
            source.display()
        ));
    }
    if mutant.vectors.is_empty()
        || mutant.vectors.iter().collect::<BTreeSet<_>>().len() != mutant.vectors.len()
    {
        return Err(format!(
            "mutant {} requires distinct vector bindings",
            mutant.id
        ));
    }
    for vector in &mutant.vectors {
        if vector.is_empty() || vector.contains(['\0', '\n', '\r']) {
            return Err(format!("mutant {} has an invalid vector id", mutant.id));
        }
    }
    Ok(())
}

fn contains_symbol(source: &str, expected: &str) -> bool {
    let expected = expected.split("::").collect::<Vec<_>>();
    if expected.is_empty() || expected.iter().any(|part| part.is_empty()) {
        return false;
    }
    if let [type_name, method_name] = expected.as_slice() {
        let impl_marker = format!("impl {type_name} {{");
        let method_marker = format!("fn {method_name}(");
        return source.split(&impl_marker).skip(1).any(|tail| {
            tail.split_once("\n}\n")
                .map_or(tail, |(body, _)| body)
                .contains(&method_marker)
        });
    }
    let identifiers = source
        .split(|character: char| !(character == '_' || character.is_ascii_alphanumeric()))
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    identifiers
        .windows(expected.len())
        .any(|window| window == expected)
        || (expected.len() == 1 && identifiers.contains(&expected[0]))
}

fn read_assurance_manifest(path: &Path) -> Result<(String, Vec<AssuranceMutant>, Vec<u8>), String> {
    let bytes = read_bounded_regular(path, 1024 * 1024, "assurance manifest")?;
    if !bytes.ends_with(b"\n") {
        return Err(format!("{} has no trailing newline", path.display()));
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| format!("{} is not UTF-8", path.display()))?;
    let mut root = BTreeMap::new();
    let mut records = Vec::<BTreeMap<String, String>>::new();
    let mut current = None::<BTreeMap<String, String>>;
    for (line_index, original) in text.lines().enumerate() {
        let line = strip_toml_comment(original)?.trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[mutant]]" {
            if let Some(record) = current.take() {
                records.push(record);
            }
            current = Some(BTreeMap::new());
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("invalid assurance manifest line {}", line_index + 1))?;
        let key = key.trim();
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(format!("invalid assurance key at line {}", line_index + 1));
        }
        let destination = current.as_mut().unwrap_or(&mut root);
        if destination
            .insert(key.to_owned(), value.trim().to_owned())
            .is_some()
        {
            return Err(format!("duplicate assurance key {key}"));
        }
    }
    if let Some(record) = current {
        records.push(record);
    }
    require_exact_keys(
        &root,
        &["catalog-id", "execution-strategy", "schema-version"],
        "assurance root",
    )?;
    if take_integer(&mut root, "schema-version")? != 1
        || take_string(&mut root, "execution-strategy")? != "baseline-pass-mutant-fail"
    {
        return Err("unsupported assurance manifest protocol".to_owned());
    }
    let catalog_id = take_string(&mut root, "catalog-id")?;
    let mut mutants = Vec::new();
    for mut record in records {
        require_exact_keys(
            &record,
            &[
                "claim",
                "id",
                "module",
                "source",
                "symbol",
                "test-command",
                "vectors",
            ],
            "assurance mutant",
        )?;
        mutants.push(AssuranceMutant {
            id: take_string(&mut record, "id")?,
            claim: take_string(&mut record, "claim")?,
            module: take_string(&mut record, "module")?,
            source: PathBuf::from(take_string(&mut record, "source")?),
            symbol: take_string(&mut record, "symbol")?,
            test_command: take_string_array(&mut record, "test-command")?,
            vectors: take_string_array(&mut record, "vectors")?,
        });
    }
    Ok((catalog_id, mutants, bytes))
}

fn parse_assurance_options(arguments: &[OsString]) -> Result<AssuranceOptions, String> {
    let mut manifest = None;
    let mut repository_root = None;
    let mut output = None;
    let mut index = 2_usize;
    while index < arguments.len() {
        let flag = arguments[index]
            .to_str()
            .ok_or_else(|| "mutation assurance option must be UTF-8".to_owned())?;
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("{flag} requires a value"))?;
        let slot = match flag {
            "--manifest" => &mut manifest,
            "--repository-root" => &mut repository_root,
            "--output" => &mut output,
            _ => return Err(format!("unknown mutation assurance option {flag}")),
        };
        if slot.is_some() {
            return Err(format!("{flag} was provided more than once"));
        }
        *slot = Some(PathBuf::from(value));
        index += 2;
    }
    Ok(AssuranceOptions {
        manifest: manifest.ok_or_else(|| "mutation assurance requires --manifest".to_owned())?,
        repository_root: repository_root
            .ok_or_else(|| "mutation assurance requires --repository-root".to_owned())?,
        output: output.ok_or_else(|| "mutation assurance requires --output".to_owned())?,
    })
}

fn require_exact_keys(
    values: &BTreeMap<String, String>,
    expected: &[&str],
    label: &str,
) -> Result<(), String> {
    let observed = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if observed == expected {
        Ok(())
    } else {
        Err(format!(
            "{label} keys differ: expected {expected:?}, observed {observed:?}"
        ))
    }
}

fn take_string(values: &mut BTreeMap<String, String>, key: &str) -> Result<String, String> {
    crate::strict_toml::string(&values.remove(key).ok_or_else(|| format!("missing {key}"))?)
}

fn take_string_array(
    values: &mut BTreeMap<String, String>,
    key: &str,
) -> Result<Vec<String>, String> {
    crate::strict_toml::string_array(&values.remove(key).ok_or_else(|| format!("missing {key}"))?)
}

fn take_integer(values: &mut BTreeMap<String, String>, key: &str) -> Result<u64, String> {
    let value = values.remove(key).ok_or_else(|| format!("missing {key}"))?;
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{key} must be a canonical unsigned integer"))?;
    if value != parsed.to_string() {
        return Err(format!("{key} must be a canonical unsigned integer"));
    }
    Ok(parsed)
}

fn strip_toml_comment(line: &str) -> Result<&str, String> {
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            '#' if !quoted => return Ok(&line[..index]),
            _ => {}
        }
    }
    if quoted {
        Err("unterminated assurance TOML string".to_owned())
    } else {
        Ok(line)
    }
}

fn canonical_regular_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve {label} {}: {error}", path.display()))?;
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|error| format!("cannot inspect {label}: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("{label} is not a regular directory"));
    }
    Ok(canonical)
}

fn safe_relative_path(root: &Path, relative: &Path, label: &str) -> Result<PathBuf, String> {
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!(
            "{label} must be a normalized repository-relative path"
        ));
    }
    let joined = root.join(relative);
    let canonical = fs::canonicalize(&joined)
        .map_err(|error| format!("cannot resolve {label} {}: {error}", joined.display()))?;
    if !canonical.starts_with(root) {
        return Err(format!("{label} escapes the repository"));
    }
    Ok(canonical)
}

fn read_bounded_regular(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(format!(
            "{label} {} is not a bounded regular file",
            path.display()
        ));
    }
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read {label} {}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(format!("{label} changed while being read"));
    }
    Ok(bytes)
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
    let stdout_text =
        std::str::from_utf8(stdout).map_err(|_| "mutation test output is not UTF-8".to_owned())?;
    let suffix = if passed { " ... ok" } else { " ... FAILED" };
    Ok(stdout_text
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
        .git_safe_directory(root)
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
