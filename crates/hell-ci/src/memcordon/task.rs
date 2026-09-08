use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::strict_toml;

const OPERATIONS: [&str; 7] = [
    "readiness",
    "release",
    "nightly",
    "mutation",
    "regression-corpus",
    "regression-subject",
    "fuzz",
];

#[derive(Clone, Debug)]
pub(super) struct Task {
    #[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
    pub(super) policy_path: PathBuf,
    pub(super) lock: PathBuf,
    pub(super) output: PathBuf,
    pub(super) download_cache: PathBuf,
    pub(super) runtime_root: PathBuf,
    pub(super) operation: String,
    pub(super) required_operation_ids: Vec<String>,
}

impl Task {
    pub(super) fn load(path: &Path, operation: &str) -> Result<Self, String> {
        if !OPERATIONS.contains(&operation) {
            return Err(format!("unsupported MemCordon operation {operation:?}"));
        }
        let bytes = fs::read(path)
            .map_err(|error| format!("cannot read MemCordon task {}: {error}", path.display()))?;
        if !bytes.ends_with(b"\n") {
            return Err("MemCordon task lacks its trailing newline".to_owned());
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| "MemCordon task is not UTF-8".to_owned())?;
        let mut assignments = strict_toml::assignments(text)?;
        let schema = take_integer(&mut assignments, "schema-version")?;
        if schema != 1 {
            return Err("unsupported MemCordon task schema".to_owned());
        }
        let lock = take_relative_path(&mut assignments, "runtime-lock")?;
        let output = take_relative_path(&mut assignments, "output-root")?;
        let download_cache = take_relative_path(&mut assignments, "download-cache")?;
        let runtime_root = take_relative_path(&mut assignments, "runtime-root")?;
        let mut declared = BTreeSet::new();
        let mut selected_required = None;
        for name in OPERATIONS {
            let key = format!("operation.{name}.plan-kind");
            let value = strict_toml::string(&strict_toml::take(&mut assignments, &key)?)?;
            if value != name || !declared.insert(value) {
                return Err(format!("MemCordon task operation {name} is not exact"));
            }
            let required_key = format!("operation.{name}.required-operation-ids");
            let required =
                strict_toml::string_array(&strict_toml::take(&mut assignments, &required_key)?)?;
            if required.is_empty()
                || required.iter().any(|id| !valid_identifier(id))
                || required.iter().collect::<BTreeSet<_>>().len() != required.len()
            {
                return Err(format!(
                    "MemCordon task operation {name} has invalid required operation IDs"
                ));
            }
            if name == operation {
                selected_required = Some(required);
            }
        }
        if !assignments.is_empty() {
            return Err(format!(
                "unknown MemCordon task keys: {}",
                assignments.keys().cloned().collect::<Vec<_>>().join(", ")
            ));
        }
        let task_repository = path
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| "MemCordon task must be inside a repository ci directory".to_owned())?;
        Ok(Self {
            policy_path: path.to_path_buf(),
            lock: task_repository.join(lock),
            output,
            download_cache,
            runtime_root,
            operation: operation.to_owned(),
            required_operation_ids: selected_required
                .ok_or_else(|| "MemCordon task operation policy is missing".to_owned())?,
        })
    }

    pub(super) fn platform_id() -> Result<&'static str, String> {
        if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
            Ok("linux-x86_64")
        } else if cfg!(target_os = "windows") && cfg!(target_arch = "x86_64") {
            Ok("windows-x86_64")
        } else {
            Err("MemCordon sealed tasks support only Linux x86_64 and Windows x86_64".to_owned())
        }
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn take_integer(
    assignments: &mut std::collections::BTreeMap<String, String>,
    key: &str,
) -> Result<u64, String> {
    let value = strict_toml::take(assignments, key)?;
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("MemCordon task {key} must be an integer"))?;
    if value != parsed.to_string() {
        return Err(format!("MemCordon task {key} is not canonical"));
    }
    Ok(parsed)
}

fn take_relative_path(
    assignments: &mut std::collections::BTreeMap<String, String>,
    key: &str,
) -> Result<PathBuf, String> {
    let path = PathBuf::from(strict_toml::string(&strict_toml::take(assignments, key)?)?);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "MemCordon task {key} must be a normalized relative path"
        ));
    }
    Ok(path)
}
