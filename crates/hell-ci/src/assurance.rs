use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::json::{JsonValue, canonical_json_bytes};
use crate::release::manifest::{write_atomic, write_atomic_new};

const MAP_LIMIT: u64 = 4 * 1024 * 1024;
const TEXT_LIMIT: u64 = 32 * 1024 * 1024;

#[derive(Clone)]
struct Claim {
    id: String,
    statement: String,
    severity: String,
    implementation: Vec<PathBuf>,
    workflow_gates: Vec<String>,
    vectors: Vec<String>,
    fuzz_targets: Vec<String>,
    mutants: Vec<String>,
    residual_assumptions: Vec<String>,
}

struct AssuranceMap {
    id: String,
    claims: Vec<Claim>,
    bytes: Vec<u8>,
}

type TableFields = BTreeMap<String, String>;
type ParsedTables = (TableFields, Vec<TableFields>);

struct Options {
    command: String,
    map: PathBuf,
    repository_root: Option<PathBuf>,
    output: PathBuf,
}

/// One exact invalid control-plane transition exercised by mutation assurance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrimaryControl {
    FinalCellOmission,
    DuplicateCell,
    RelabeledNativeEvidence,
    ExemptionSelectorMismatch,
    ExemptionExpiredAtPlanTime,
    ExtraEvidenceArchiveMember,
    OmittedSubject,
}

/// Exercises the production validator for one intentionally invalid control.
///
/// A normal build rejects every variant. A selected mutation changes only its
/// corresponding validation branch, so the focused mutation test observes an
/// unexpected success without recreating the protected algorithm externally.
///
/// # Errors
///
/// Returns the production validation diagnostic for the selected invalid
/// control.
pub fn exercise(control: PrimaryControl) -> Result<(), String> {
    match control {
        PrimaryControl::FinalCellOmission => crate::conformance::assurance_final_cell_omission(),
        PrimaryControl::DuplicateCell => crate::conformance::assurance_duplicate_cell(),
        PrimaryControl::RelabeledNativeEvidence => {
            crate::conformance::assurance_relabeled_native_evidence()
        }
        PrimaryControl::ExemptionSelectorMismatch => {
            crate::conformance::assurance_exemption_selector_mismatch()
        }
        PrimaryControl::ExemptionExpiredAtPlanTime => {
            crate::conformance::assurance_exemption_expired_at_plan_time()
        }
        PrimaryControl::ExtraEvidenceArchiveMember => {
            crate::release::assurance_extra_evidence_archive_member()
        }
        PrimaryControl::OmittedSubject => crate::release::assurance_omitted_subject(),
    }
}

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments.first().and_then(|argument| argument.to_str()) == Some("assurance")
}

pub(crate) fn run(arguments: &[OsString]) -> Result<String, String> {
    let options = parse_options(arguments)?;
    match options.command.as_str() {
        "render" => render(&options),
        "check" => check(&options),
        _ => Err(usage()),
    }
}

fn parse_options(arguments: &[OsString]) -> Result<Options, String> {
    let command = arguments
        .get(1)
        .and_then(|argument| argument.to_str())
        .ok_or_else(usage)?
        .to_owned();
    let mut map = None;
    let mut repository_root = None;
    let mut output = None;
    let mut index = 2;
    while index < arguments.len() {
        let flag = arguments[index]
            .to_str()
            .ok_or_else(|| "assurance option must be UTF-8".to_owned())?;
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("{flag} requires a value"))?;
        let slot = match flag {
            "--map" => &mut map,
            "--repository-root" => &mut repository_root,
            "--output" => &mut output,
            _ => return Err(format!("unknown assurance option {flag:?}")),
        };
        if slot.is_some() {
            return Err(format!("{flag} was provided more than once"));
        }
        *slot = Some(PathBuf::from(value));
        index += 2;
    }
    if command != "check" && command != "render" {
        return Err(usage());
    }
    if command == "check" && repository_root.is_none() {
        return Err("assurance check requires --repository-root".to_owned());
    }
    if command == "render" && repository_root.is_some() {
        return Err("assurance render does not accept --repository-root".to_owned());
    }
    Ok(Options {
        command,
        map: map.ok_or_else(|| "assurance requires --map".to_owned())?,
        repository_root,
        output: output.ok_or_else(|| "assurance requires --output".to_owned())?,
    })
}

fn check(options: &Options) -> Result<String, String> {
    if options.output.exists() {
        return Err("assurance check output already exists".to_owned());
    }
    let result = (|| {
        let root = canonical_directory(
            options
                .repository_root
                .as_deref()
                .ok_or_else(|| "assurance check requires --repository-root".to_owned())?,
        )?;
        let map_path = resolve_input(&root, &options.map, "assurance map")?;
        let map = read_map(&map_path)?;
        validate_map(&root, &map)?;
        let generated_path = root.join("spec/generated/assurance-map.md");
        let generated = read_text_file(&generated_path, TEXT_LIMIT, "generated assurance map")?;
        if generated.as_bytes() != render_bytes(&map).as_slice() {
            return Err("generated assurance documentation differs from the map".to_owned());
        }
        Ok(map)
    })();
    match result {
        Ok(map) => {
            write_atomic_new(
                &options.output,
                &canonical_json_bytes(&JsonValue::Object(BTreeMap::from([
                    (
                        "claimCount".to_owned(),
                        JsonValue::Number(
                            map.claims
                                .len()
                                .try_into()
                                .map_err(|_| "assurance claim count overflow")?,
                        ),
                    ),
                    ("mapId".to_owned(), JsonValue::String(map.id)),
                    (
                        "mapSha256".to_owned(),
                        JsonValue::String(hell_testkit::sha256_bytes(&map.bytes).hex()),
                    ),
                    ("schemaVersion".to_owned(), JsonValue::Number(1)),
                    ("state".to_owned(), JsonValue::String("checked".to_owned())),
                ])))?,
            )?;
            Ok(format!(
                "verified {} release assurance claims",
                map.claims.len()
            ))
        }
        Err(primary) => {
            let report = write_atomic_new(
                &options.output,
                &canonical_json_bytes(&JsonValue::Object(BTreeMap::from([
                    (
                        "diagnosticCode".to_owned(),
                        JsonValue::String("assurance.map.invalid".to_owned()),
                    ),
                    (
                        "diagnosticMessage".to_owned(),
                        JsonValue::String(primary.clone()),
                    ),
                    ("schemaVersion".to_owned(), JsonValue::Number(1)),
                    ("state".to_owned(), JsonValue::String("blocked".to_owned())),
                ])))?,
            );
            match report {
                Ok(()) => Err(format!("assurance.map.invalid: {primary}")),
                Err(persistence) => Err(format!(
                    "assurance.map.invalid: {primary}; additionally, cannot persist blocked report: {persistence}"
                )),
            }
        }
    }
}

fn render(options: &Options) -> Result<String, String> {
    let map = read_map(&options.map)?;
    write_atomic(&options.output, &render_bytes(&map))?;
    Ok(format!(
        "rendered {} release assurance claims",
        map.claims.len()
    ))
}

fn validate_map(root: &Path, map: &AssuranceMap) -> Result<(), String> {
    if map.claims.is_empty() {
        return Err("assurance map contains no claims".to_owned());
    }
    require_unique(map.claims.iter().map(|claim| claim.id.as_str()), "claim ID")?;

    let protocol = root.join("ci/protocol/v1.toml");
    let release_vectors = root.join("ci/release-protocol/v1/manifest.toml");
    let workflow_vectors = root.join("ci/workflow-vectors/v1/manifest.toml");
    let control_vectors = root.join("ci/control-vectors/v1/manifest.toml");
    let fuzz_manifest = root.join("ci/fuzz-targets.toml");
    let mutant_manifest = root.join("compat/assurance-mutants.toml");
    let governance = root.join("ci/governance-policy.toml");
    let gates = protocol_job_ids(&protocol)?;
    let release_gates = gates
        .iter()
        .filter(|gate| gate.starts_with("release/"))
        .cloned()
        .collect::<BTreeSet<_>>();
    let vectors = table_ids(&release_vectors, "[[vector]]")?
        .into_iter()
        .chain(table_ids(&workflow_vectors, "[[vector]]")?)
        .chain(table_ids(&control_vectors, "[[vector]]")?)
        .collect::<BTreeSet<_>>();
    let fuzz_targets = table_ids(&fuzz_manifest, "[[target]]")?;
    let mutants = table_ids(&mutant_manifest, "[[mutant]]")?;
    let residuals = table_ids(&governance, "[[residual-assumption]]")?;
    validate_mutant_bindings(&mutant_manifest)?;

    let mut mapped_release_gates = BTreeSet::new();
    for claim in &map.claims {
        validate_claim_shape(claim)?;
        for implementation in &claim.implementation {
            let path = resolve_input(root, implementation, "assurance implementation")?;
            let _ = read_text_file(&path, TEXT_LIMIT, "assurance implementation")?;
        }
        require_known(&claim.workflow_gates, &gates, &claim.id, "workflow gate")?;
        require_known(&claim.vectors, &vectors, &claim.id, "vector")?;
        require_known(&claim.fuzz_targets, &fuzz_targets, &claim.id, "fuzz target")?;
        require_known(&claim.mutants, &mutants, &claim.id, "mutant")?;
        require_known(
            &claim.residual_assumptions,
            &residuals,
            &claim.id,
            "residual assumption",
        )?;
        if claim.severity == "release-blocking" && claim.vectors.is_empty() {
            return Err(format!(
                "release-blocking claim {} has no negative vector",
                claim.id
            ));
        }
        mapped_release_gates.extend(
            claim
                .workflow_gates
                .iter()
                .filter(|gate| gate.starts_with("release/"))
                .cloned(),
        );
    }
    if mapped_release_gates != release_gates {
        return Err(format!(
            "release workflow gate coverage differs: expected {release_gates:?}, observed {mapped_release_gates:?}"
        ));
    }
    Ok(())
}

fn validate_claim_shape(claim: &Claim) -> Result<(), String> {
    if !valid_upper_id(&claim.id)
        || claim.statement.is_empty()
        || claim.severity != "release-blocking"
        || claim.implementation.is_empty()
        || claim.workflow_gates.is_empty()
    {
        return Err(format!("assurance claim {} has an invalid shape", claim.id));
    }
    for (values, label) in [
        (&claim.workflow_gates, "workflow gates"),
        (&claim.vectors, "vectors"),
        (&claim.fuzz_targets, "fuzz targets"),
        (&claim.mutants, "mutants"),
        (&claim.residual_assumptions, "residual assumptions"),
    ] {
        require_unique(values.iter().map(String::as_str), label)?;
        if values.iter().any(String::is_empty) {
            return Err(format!("claim {} contains an empty {label}", claim.id));
        }
    }
    Ok(())
}

fn require_known(
    values: &[String],
    known: &BTreeSet<String>,
    claim: &str,
    label: &str,
) -> Result<(), String> {
    if let Some(value) = values.iter().find(|value| !known.contains(*value)) {
        return Err(format!("claim {claim} names unknown {label} {value:?}"));
    }
    Ok(())
}

fn validate_mutant_bindings(path: &Path) -> Result<(), String> {
    let text = read_text_file(path, TEXT_LIMIT, "assurance mutant catalog")?;
    let (_, records) = parse_tables(&text, "[[mutant]]")?;
    if records.len() != 13 {
        return Err(format!(
            "assurance mutant catalog requires 13 records, observed {}",
            records.len()
        ));
    }
    for mut record in records {
        let id = take_string(&mut record, "id")?;
        for key in ["claim", "module", "source", "symbol"] {
            if take_string(&mut record, key)?.is_empty() {
                return Err(format!("mutant {id} has empty {key}"));
            }
        }
        if take_array(&mut record, "test-command")?.is_empty()
            || take_array(&mut record, "vectors")?.is_empty()
            || !record.is_empty()
        {
            return Err(format!("mutant {id} lacks exact executable bindings"));
        }
    }
    Ok(())
}

fn read_map(path: &Path) -> Result<AssuranceMap, String> {
    let bytes = read_regular(path, MAP_LIMIT, "assurance map")?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| format!("{} is not UTF-8", path.display()))?;
    let (mut root, records) = parse_tables(text, "[[claim]]")?;
    if take_unsigned(&mut root, "schema-version")? != 1 || root.len() != 1 {
        return Err("assurance map root differs from schema version 1".to_owned());
    }
    let id = take_string(&mut root, "map-id")?;
    if id != "hell-rs-release-assurance-v1" {
        return Err("assurance map ID differs".to_owned());
    }
    let claims = records
        .into_iter()
        .map(parse_claim)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AssuranceMap { id, claims, bytes })
}

fn parse_claim(mut fields: BTreeMap<String, String>) -> Result<Claim, String> {
    let claim = Claim {
        id: take_string(&mut fields, "id")?,
        statement: take_string(&mut fields, "statement")?,
        severity: take_string(&mut fields, "severity")?,
        implementation: take_array(&mut fields, "implementation")?
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        workflow_gates: take_array(&mut fields, "workflow-gates")?,
        vectors: take_array(&mut fields, "vectors")?,
        fuzz_targets: take_array(&mut fields, "fuzz-targets")?,
        mutants: take_array(&mut fields, "mutants")?,
        residual_assumptions: take_array(&mut fields, "residual-assumptions")?,
    };
    if !fields.is_empty() {
        return Err(format!(
            "claim {} contains unknown fields {:?}",
            claim.id,
            fields.keys().collect::<Vec<_>>()
        ));
    }
    Ok(claim)
}

fn parse_tables(text: &str, table_header: &str) -> Result<ParsedTables, String> {
    let mut root = BTreeMap::new();
    let mut records = Vec::new();
    let mut current = None::<BTreeMap<String, String>>;
    for (line_index, original) in text.lines().enumerate() {
        let line = strip_comment(original)?.trim();
        if line.is_empty() {
            continue;
        }
        if line == table_header {
            if let Some(record) = current.take() {
                records.push(record);
            }
            current = Some(BTreeMap::new());
            continue;
        }
        if line.starts_with('[') {
            return Err(format!("unexpected table at line {}", line_index + 1));
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("invalid assignment at line {}", line_index + 1))?;
        let key = key.trim();
        if !valid_key(key) {
            return Err(format!("invalid key at line {}", line_index + 1));
        }
        let destination = current.as_mut().unwrap_or(&mut root);
        if destination
            .insert(key.to_owned(), value.trim().to_owned())
            .is_some()
        {
            return Err(format!("duplicate key {key}"));
        }
    }
    if let Some(record) = current {
        records.push(record);
    }
    Ok((root, records))
}

fn protocol_job_ids(path: &Path) -> Result<BTreeSet<String>, String> {
    let text = read_text_file(path, TEXT_LIMIT, "protocol manifest")?;
    let mut ids = BTreeSet::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(table) = trimmed
            .strip_prefix("[job.")
            .and_then(|value| value.strip_suffix(']'))
        else {
            continue;
        };
        let Some((workflow, job)) = table.split_once('.') else {
            return Err("protocol job table has no workflow/job split".to_owned());
        };
        let id = format!("{workflow}/{job}");
        if !ids.insert(id) {
            return Err("protocol contains a duplicate job table".to_owned());
        }
    }
    if ids.is_empty() {
        return Err("protocol contains no jobs".to_owned());
    }
    Ok(ids)
}

fn table_ids(path: &Path, header: &str) -> Result<BTreeSet<String>, String> {
    let text = read_text_file(path, TEXT_LIMIT, "assurance inventory")?;
    let mut ids = BTreeSet::new();
    let mut target_table = false;
    let mut pending_id = None;
    for (line_index, original) in text.lines().enumerate() {
        let line = strip_comment(original)?.trim();
        if line.starts_with('[') {
            if target_table {
                let id = pending_id.take().ok_or_else(|| {
                    format!(
                        "{} target table before line {} lacks an ID",
                        path.display(),
                        line_index + 1
                    )
                })?;
                if !ids.insert(id) {
                    return Err(format!("{} has a duplicate ID", path.display()));
                }
            }
            target_table = line == header;
            pending_id = None;
            continue;
        }
        if target_table {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key.trim() == "id" {
                if pending_id.is_some() {
                    return Err(format!("{} target table has duplicate ID", path.display()));
                }
                pending_id = Some(crate::strict_toml::string(value.trim())?);
            }
        }
    }
    if target_table {
        let id = pending_id
            .ok_or_else(|| format!("{} final target table lacks an ID", path.display()))?;
        if !ids.insert(id) {
            return Err(format!("{} has a duplicate ID", path.display()));
        }
    }
    if ids.is_empty() {
        return Err(format!("{} contains no {header} tables", path.display()));
    }
    Ok(ids)
}

fn render_bytes(map: &AssuranceMap) -> Vec<u8> {
    let mut rendered = String::from(
        "# Release assurance map\n\nGenerated from `spec/assurance-map.toml`. Edit the TOML map and run\n`hell-ci assurance render`; do not edit this file directly.\n\n| Claim | Severity | Assurance statement |\n| --- | --- | --- |\n",
    );
    for claim in &map.claims {
        rendered.push_str("| `");
        rendered.push_str(&claim.id);
        rendered.push_str("` | ");
        rendered.push_str(&claim.severity);
        rendered.push_str(" | ");
        rendered.push_str(&claim.statement);
        rendered.push_str(" |\n");
    }
    rendered.push_str(
        "\nThe machine-readable map is authoritative for implementation paths, workflow\ngates, vectors, fuzz targets, mutants, and residual assumptions.\n",
    );
    rendered.into_bytes()
}

fn take_string(values: &mut BTreeMap<String, String>, key: &str) -> Result<String, String> {
    crate::strict_toml::string(&values.remove(key).ok_or_else(|| format!("missing {key}"))?)
}

fn take_array(values: &mut BTreeMap<String, String>, key: &str) -> Result<Vec<String>, String> {
    crate::strict_toml::string_array(&values.remove(key).ok_or_else(|| format!("missing {key}"))?)
}

fn take_unsigned(values: &mut BTreeMap<String, String>, key: &str) -> Result<u64, String> {
    let raw = values.remove(key).ok_or_else(|| format!("missing {key}"))?;
    let value = raw
        .parse::<u64>()
        .map_err(|_| format!("{key} must be an unsigned integer"))?;
    if raw != value.to_string() {
        return Err(format!("{key} is not canonical"));
    }
    Ok(value)
}

fn strip_comment(line: &str) -> Result<&str, String> {
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
        } else {
            match character {
                '\\' if quoted => escaped = true,
                '"' => quoted = !quoted,
                '#' if !quoted => return Ok(&line[..index]),
                _ => {}
            }
        }
    }
    if quoted {
        Err("unterminated TOML string".to_owned())
    } else {
        Ok(line)
    }
}

fn resolve_input(root: &Path, path: &Path, label: &str) -> Result<PathBuf, String> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "{label} must be a normalized repository-relative path"
        ));
    }
    let resolved = fs::canonicalize(root.join(path))
        .map_err(|error| format!("cannot resolve {label} {}: {error}", path.display()))?;
    if !resolved.starts_with(root) {
        return Err(format!("{label} escapes the repository"));
    }
    Ok(resolved)
}

fn canonical_directory(path: &Path) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve repository root: {error}"))?;
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|error| format!("cannot inspect repository root: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("repository root is not a real directory".to_owned());
    }
    Ok(canonical)
}

fn read_text_file(path: &Path, limit: u64, label: &str) -> Result<String, String> {
    let bytes = read_regular(path, limit, label)?;
    String::from_utf8(bytes).map_err(|_| format!("{label} is not UTF-8"))
}

fn read_regular(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(format!("{label} is not a bounded regular file"));
    }
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read {label} {}: {error}", path.display()))?;
    if !bytes.ends_with(b"\n") || u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(format!("{label} is not stable newline-terminated text"));
    }
    Ok(bytes)
}

fn require_unique<'a>(
    values: impl IntoIterator<Item = &'a str>,
    label: &str,
) -> Result<(), String> {
    let values = values.into_iter().collect::<Vec<_>>();
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(format!("duplicate {label}"));
    }
    Ok(())
}

fn valid_key(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_upper_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_uppercase())
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

fn usage() -> String {
    "usage: hell-ci assurance check --map PATH --repository-root PATH --output PATH\n       hell-ci assurance render --map PATH --output PATH".to_owned()
}
