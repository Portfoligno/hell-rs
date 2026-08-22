use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::json::{
    JsonValue, canonical_json_bytes, json_member, parse_json, require_exact_json_keys,
};
use crate::release::manifest::write_json;

const MAX_ACTION_LOCK_BYTES: u64 = 2 * 1024 * 1024;
const NORMALIZATION: &str = "RFC8785 object with sorted input and output names and runtime class";

struct Action {
    id: String,
    repository: String,
    commit_sha: String,
    reviewed_version: String,
    inputs: Vec<String>,
    outputs: Vec<String>,
    runtime: String,
    permission: String,
}

pub(super) fn update(lock: &Path, output: &Path) -> Result<String, String> {
    let document = read_lock(lock)?;
    let root = document.object()?;
    require_exact_json_keys(
        root,
        &["actions", "lockId", "normalization", "schemaVersion"],
    )?;
    if json_member(root, "schemaVersion")?.number()? != 1 {
        return Err("action metadata lock schemaVersion must be 1".to_owned());
    }
    let lock_id = validated_identifier(json_member(root, "lockId")?.string()?, "lockId")?;
    if json_member(root, "normalization")?.string()? != NORMALIZATION {
        return Err("action metadata lock normalization rule differs".to_owned());
    }

    let mut ids = BTreeSet::new();
    let mut repositories = BTreeSet::new();
    let mut actions = Vec::new();
    for value in json_member(root, "actions")?.array()? {
        let action = parse_action(value)?;
        if !ids.insert(action.id.clone()) {
            return Err(format!(
                "action metadata lock duplicates id {:?}",
                action.id
            ));
        }
        if !repositories.insert(action.repository.clone()) {
            return Err(format!(
                "action metadata lock duplicates repository {:?}",
                action.repository
            ));
        }
        actions.push(action_json(&action)?);
    }
    if actions.is_empty() {
        return Err("action metadata lock contains no actions".to_owned());
    }

    let metadata = JsonValue::Object(BTreeMap::from([
        ("actions".to_owned(), JsonValue::Array(actions)),
        ("lockId".to_owned(), JsonValue::String(lock_id)),
        (
            "normalization".to_owned(),
            JsonValue::String(NORMALIZATION.to_owned()),
        ),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
    ]));
    write_json(output, &metadata)?;
    Ok(format!("updated action metadata from {}", lock.display()))
}

fn read_lock(path: &Path) -> Result<JsonValue, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_ACTION_LOCK_BYTES
    {
        return Err(format!(
            "{} is not a bounded regular action metadata lock",
            path.display()
        ));
    }
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(format!("{} changed while being read", path.display()));
    }
    let text =
        std::str::from_utf8(&bytes).map_err(|_| format!("{} is not UTF-8", path.display()))?;
    parse_json(text).map_err(|error| format!("cannot parse {}: {error}", path.display()))
}

fn parse_action(value: &JsonValue) -> Result<Action, String> {
    let object = value.object()?;
    let without_digest = [
        "commitSha",
        "id",
        "inputs",
        "outputs",
        "projectPermissionClass",
        "repository",
        "reviewedVersion",
        "runtime",
    ];
    let with_digest = [
        "commitSha",
        "id",
        "inputs",
        "normalizedMetadataSha256",
        "outputs",
        "projectPermissionClass",
        "repository",
        "reviewedVersion",
        "runtime",
    ];
    if require_exact_json_keys(object, &without_digest).is_err() {
        require_exact_json_keys(object, &with_digest)?;
    }
    let action = Action {
        id: validated_identifier(json_member(object, "id")?.string()?, "action id")?,
        repository: validated_repository(json_member(object, "repository")?.string()?)?,
        commit_sha: validated_sha(json_member(object, "commitSha")?.string()?)?,
        reviewed_version: validated_version(json_member(object, "reviewedVersion")?.string()?)?,
        inputs: string_set(json_member(object, "inputs")?, "action inputs")?,
        outputs: string_set(json_member(object, "outputs")?, "action outputs")?,
        runtime: validated_runtime(json_member(object, "runtime")?.string()?)?,
        permission: validated_permission(json_member(object, "projectPermissionClass")?.string()?)?,
    };
    if let Some(expected) = object.get("normalizedMetadataSha256") {
        let observed = normalized_metadata_sha256(&action)?;
        if validated_digest(expected.string()?)? != observed {
            return Err(format!(
                "action {:?} normalized metadata digest differs",
                action.id
            ));
        }
    }
    Ok(action)
}

fn action_json(action: &Action) -> Result<JsonValue, String> {
    Ok(JsonValue::Object(BTreeMap::from([
        (
            "commitSha".to_owned(),
            JsonValue::String(action.commit_sha.clone()),
        ),
        ("id".to_owned(), JsonValue::String(action.id.clone())),
        (
            "inputs".to_owned(),
            JsonValue::Array(
                action
                    .inputs
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        ),
        (
            "normalizedMetadataSha256".to_owned(),
            JsonValue::String(normalized_metadata_sha256(action)?),
        ),
        (
            "outputs".to_owned(),
            JsonValue::Array(
                action
                    .outputs
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        ),
        (
            "projectPermissionClass".to_owned(),
            JsonValue::String(action.permission.clone()),
        ),
        (
            "repository".to_owned(),
            JsonValue::String(action.repository.clone()),
        ),
        (
            "reviewedVersion".to_owned(),
            JsonValue::String(action.reviewed_version.clone()),
        ),
        (
            "runtime".to_owned(),
            JsonValue::String(action.runtime.clone()),
        ),
    ])))
}

fn normalized_metadata_sha256(action: &Action) -> Result<String, String> {
    let normalized = JsonValue::Object(BTreeMap::from([
        (
            "inputs".to_owned(),
            JsonValue::Array(
                action
                    .inputs
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        ),
        (
            "outputs".to_owned(),
            JsonValue::Array(
                action
                    .outputs
                    .iter()
                    .cloned()
                    .map(JsonValue::String)
                    .collect(),
            ),
        ),
        (
            "runtime".to_owned(),
            JsonValue::String(action.runtime.clone()),
        ),
    ]));
    let mut bytes = canonical_json_bytes(&normalized)?;
    if bytes.pop() != Some(b'\n') {
        return Err("canonical action metadata lacks its terminal LF".to_owned());
    }
    Ok(hell_testkit::sha256_bytes(&bytes).hex())
}

fn string_set(value: &JsonValue, label: &str) -> Result<Vec<String>, String> {
    let mut result = value
        .array()?
        .iter()
        .map(|value| validated_identifier(value.string()?, label))
        .collect::<Result<Vec<_>, _>>()?;
    let observed = result.clone();
    result.sort();
    result.dedup();
    if result != observed {
        return Err(format!("{label} must be sorted and unique"));
    }
    Ok(result)
}

fn validated_identifier(value: &str, label: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!("{label} is not a bounded identifier"));
    }
    Ok(value.to_owned())
}

fn validated_repository(value: &str) -> Result<String, String> {
    let components = value.split('/').collect::<Vec<_>>();
    if !(2..=4).contains(&components.len()) {
        return Err(
            "action repository must contain owner/name and an optional action path".to_owned(),
        );
    }
    for component in components {
        validated_identifier(component, "action repository component")?;
    }
    Ok(value.to_owned())
}

fn validated_sha(value: &str) -> Result<String, String> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("action commitSha must be 40 lowercase hexadecimal characters".to_owned());
    }
    Ok(value.to_owned())
}

fn validated_digest(value: &str) -> Result<String, String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("normalizedMetadataSha256 must be a lowercase SHA-256 digest".to_owned());
    }
    Ok(value.to_owned())
}

fn validated_version(value: &str) -> Result<String, String> {
    let Some(version) = value.strip_prefix('v') else {
        return Err("reviewedVersion must start with v".to_owned());
    };
    if version.is_empty()
        || value.len() > 64
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err("reviewedVersion is not a bounded version".to_owned());
    }
    Ok(value.to_owned())
}

fn validated_runtime(value: &str) -> Result<String, String> {
    if !matches!(value, "node" | "composite" | "docker") {
        return Err("action runtime class is unknown".to_owned());
    }
    Ok(value.to_owned())
}

fn validated_permission(value: &str) -> Result<String, String> {
    if !matches!(value, "read" | "attest" | "publish") {
        return Err("action project permission class is unknown".to_owned());
    }
    Ok(value.to_owned())
}
