use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::digest;
use crate::json::{self, Value};
use crate::model;

const MAX_LOCK_BYTES: u64 = 1024 * 1024;
const LOCK_DOMAIN: &[u8] = b"hell-rs:external-input-lock:1";
const ALLOWED_INPUT_KEYS: [&str; 17] = [
    "acquisition-phase",
    "cache-permitted",
    "commit",
    "expected-filename",
    "id",
    "kind",
    "maximum-compressed-bytes",
    "maximum-expanded-bytes",
    "media-type",
    "package",
    "platform",
    "platforms",
    "repository",
    "sha256",
    "timeout-seconds",
    "toolchain",
    "version",
];

pub(crate) struct Authority {
    pub(crate) sha256: String,
    pub(crate) oracle_repository: String,
    pub(crate) oracle_commit: String,
    pub(crate) linux_oracle_executable_sha256: String,
}

pub(crate) fn load(path: &Path) -> Result<Authority, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect external-input lock: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_LOCK_BYTES {
        return Err("external-input lock is not one bounded regular file".to_owned());
    }
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read external-input lock: {error}"))?;
    parse(&bytes)
}

pub(crate) fn require_expected(authority: &Authority, expected: &str) -> Result<(), String> {
    model::require_digest(expected, "release-plan external-input digest")?;
    if authority.sha256 != expected {
        return Err(
            "release plan external-input digest differs from the independently parsed trusted lock"
                .to_owned(),
        );
    }
    Ok(())
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Authority, String> {
    if !bytes.ends_with(b"\n") || bytes.contains(&0) {
        return Err("external-input lock is not trailing-LF text".to_owned());
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| "external-input lock is not UTF-8".to_owned())?;
    let document = Document::parse(text)?;
    let root_keys = document
        .root
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if root_keys != BTreeSet::from(["lock-id", "schema-version"]) {
        return Err("external-input lock root key inventory differs".to_owned());
    }
    if parse_integer(member(&document.root, "schema-version")?)? != 1 {
        return Err("unsupported external-input lock schema".to_owned());
    }
    let lock_id = parse_string(member(&document.root, "lock-id")?)?;
    require_identifier(&lock_id, "external-input lock ID")?;
    if document.inputs.is_empty() {
        return Err("external-input lock contains no inputs".to_owned());
    }

    let allowed = ALLOWED_INPUT_KEYS.into_iter().collect::<BTreeSet<_>>();
    let mut ids = BTreeSet::new();
    let mut inputs = Vec::with_capacity(document.inputs.len());
    let mut oracle_repository = None;
    let mut oracle_commit = None;
    let mut linux_oracle_executable_sha256 = None;
    for table in document.inputs {
        let ParsedInput { id, kind, fields } = parse_input(&table, &allowed, &mut ids)?;
        if id == "upstream-oracle-source" {
            if kind != "git-commit" {
                return Err("upstream oracle source has the wrong external-input kind".to_owned());
            }
            oracle_repository = Some(value_string(&fields, "repository")?);
            oracle_commit = Some(value_string(&fields, "commit")?);
        }
        if id == "linux-release-oracle" {
            if kind != "https-file" {
                return Err("Linux oracle has the wrong external-input kind".to_owned());
            }
            linux_oracle_executable_sha256 = Some(value_string(&fields, "sha256")?);
        }
        inputs.push(Value::Object(fields));
    }

    let oracle_repository = oracle_repository
        .ok_or_else(|| "external-input lock lacks upstream oracle source".to_owned())?;
    if oracle_repository != "chrisdone/hell" {
        return Err("external-input oracle repository is not the reviewed authority".to_owned());
    }
    let oracle_commit = oracle_commit
        .ok_or_else(|| "external-input lock lacks upstream oracle commit".to_owned())?;
    model::require_sha(&oracle_commit, "external-input oracle commit")?;
    let linux_oracle_executable_sha256 = linux_oracle_executable_sha256
        .ok_or_else(|| "external-input lock lacks Linux oracle executable".to_owned())?;
    model::require_digest(
        &linux_oracle_executable_sha256,
        "external-input Linux oracle executable",
    )?;

    let canonical = json::canonical(&json::object([
        ("inputs", Value::Array(inputs)),
        ("lockId", json::string(&lock_id)),
        ("schemaVersion", json::number(1)),
    ]))?;
    let mut bound = Vec::with_capacity(LOCK_DOMAIN.len() + 1 + canonical.len());
    bound.extend_from_slice(LOCK_DOMAIN);
    bound.push(0);
    bound.extend_from_slice(&canonical);
    Ok(Authority {
        sha256: digest::sha256_hex(&bound),
        oracle_repository,
        oracle_commit,
        linux_oracle_executable_sha256,
    })
}

struct ParsedInput {
    id: String,
    kind: String,
    fields: BTreeMap<String, Value>,
}

fn parse_input(
    table: &BTreeMap<String, String>,
    allowed: &BTreeSet<&str>,
    ids: &mut BTreeSet<String>,
) -> Result<ParsedInput, String> {
    if let Some(key) = table.keys().find(|key| !allowed.contains(key.as_str())) {
        return Err(format!("unknown external-input lock key {key}"));
    }
    for required in ["acquisition-phase", "id", "kind"] {
        if !table.contains_key(required) {
            return Err(format!("external input lacks {required}"));
        }
    }
    let id = parse_string(member(table, "id")?)?;
    require_identifier(&id, "external input ID")?;
    if !ids.insert(id.clone()) {
        return Err(format!("duplicate external input {id}"));
    }
    let kind = parse_string(member(table, "kind")?)?;
    let required: &[&str] = match kind.as_str() {
        "git-commit" => &["commit", "repository"],
        "https-file" => &[
            "expected-filename",
            "maximum-compressed-bytes",
            "maximum-expanded-bytes",
            "media-type",
            "sha256",
            "timeout-seconds",
        ],
        "tool-version" => &["version"],
        "cargo-package" => &["package", "version"],
        _ => return Err(format!("external input {id} has unsupported kind {kind}")),
    };
    if required.iter().any(|key| !table.contains_key(*key)) {
        return Err(format!("external input {id} lacks kind-specific fields"));
    }
    let fields = table
        .iter()
        .map(|(key, encoded)| parse_field(&id, key, encoded).map(|value| (key.clone(), value)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    if let Some(value) = fields.get("sha256") {
        model::require_digest(value.string()?, "external-input digest")?;
    }
    Ok(ParsedInput { id, kind, fields })
}

fn parse_field(id: &str, key: &str, encoded: &str) -> Result<Value, String> {
    match key {
        "cache-permitted" => Ok(Value::Bool(parse_boolean(encoded)?)),
        "maximum-compressed-bytes" | "maximum-expanded-bytes" | "timeout-seconds" => {
            let number = parse_integer(encoded)?;
            if number == 0 {
                return Err(format!("external input {id} has a zero bound"));
            }
            Ok(json::number(number))
        }
        "platforms" => Ok(Value::Array(
            parse_string_array(encoded)?
                .into_iter()
                .map(|value| json::string(&value))
                .collect(),
        )),
        _ => Ok(json::string(&parse_string(encoded)?)),
    }
}

fn member<'a>(table: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    table
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing external-input TOML key {key}"))
}

fn value_string(fields: &BTreeMap<String, Value>, key: &str) -> Result<String, String> {
    fields
        .get(key)
        .ok_or_else(|| format!("missing external-input field {key}"))?
        .string()
        .map(str::to_owned)
}

fn require_identifier(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!("invalid {label} {value:?}"));
    }
    Ok(())
}

fn parse_string(value: &str) -> Result<String, String> {
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| format!("external-input TOML value is not a quoted string: {value:?}"))?;
    if value.contains(['"', '\\', '\n', '\r']) {
        return Err("external-input TOML strings may not contain escapes".to_owned());
    }
    Ok(value.to_owned())
}

fn parse_integer(value: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("external-input TOML integer is invalid: {value:?}"))?;
    if value != parsed.to_string() {
        return Err("external-input TOML integer is not canonical".to_owned());
    }
    Ok(parsed)
}

fn parse_boolean(value: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("external-input TOML boolean is invalid: {value:?}")),
    }
}

fn parse_string_array(value: &str) -> Result<Vec<String>, String> {
    let inner = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| format!("external-input TOML array is invalid: {value:?}"))?
        .trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let values = inner
        .split(',')
        .map(|value| parse_string(value.trim()))
        .collect::<Result<Vec<_>, _>>()?;
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err("external-input TOML string array contains duplicates".to_owned());
    }
    Ok(values)
}

#[derive(Default)]
struct Document {
    root: BTreeMap<String, String>,
    inputs: Vec<BTreeMap<String, String>>,
}

impl Document {
    fn parse(text: &str) -> Result<Self, String> {
        let mut document = Self::default();
        let mut current = None::<usize>;
        for (index, source) in text.lines().enumerate() {
            let line_number = index + 1;
            let line = strip_comment(source)?.trim();
            if line.is_empty() {
                continue;
            }
            if line == "[[input]]" {
                document.inputs.push(BTreeMap::new());
                current = Some(document.inputs.len() - 1);
                continue;
            }
            if line.starts_with('[') {
                return Err(format!(
                    "unknown external-input TOML table at line {line_number}"
                ));
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("expected TOML assignment at line {line_number}"))?;
            let key = key.trim();
            require_identifier(key, "external-input TOML key")?;
            let value = value.trim();
            if value.is_empty() || value.contains(['\n', '\r']) {
                return Err(format!("invalid TOML scalar at line {line_number}"));
            }
            let target = if let Some(current) = current {
                document
                    .inputs
                    .get_mut(current)
                    .ok_or_else(|| "external-input TOML parser state is invalid".to_owned())?
            } else {
                &mut document.root
            };
            if target.insert(key.to_owned(), value.to_owned()).is_some() {
                return Err(format!("duplicate TOML key {key} at line {line_number}"));
            }
        }
        Ok(document)
    }
}

fn strip_comment(line: &str) -> Result<&str, String> {
    let mut quoted = false;
    for (index, character) in line.char_indices() {
        match character {
            '"' => quoted = !quoted,
            '#' if !quoted => return Ok(&line[..index]),
            '\\' if quoted => {
                return Err("external-input TOML escapes are not accepted".to_owned());
            }
            _ => {}
        }
    }
    if quoted {
        return Err("unterminated external-input TOML string".to_owned());
    }
    Ok(line)
}
