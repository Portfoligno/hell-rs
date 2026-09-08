use std::collections::BTreeSet;
use std::path::{Component, Path};

use hell_digest::Digest;
use serde::{Deserialize, Serialize};

use crate::ContractError;

pub const MAX_EXPANDED_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_EXECUTABLE_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_JSON_METADATA_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_ARCHIVE_ENTRIES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeManifest {
    pub schema_version: u32,
    pub version: String,
    pub source_commit: String,
    pub target: String,
    pub archive_sha256: String,
    pub components: Vec<RuntimeComponent>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeComponent {
    pub name: String,
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    #[serde(default)]
    pub executable: bool,
}

impl RuntimeManifest {
    /// Parses a bounded strict runtime manifest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON or invalid component authority.
    pub fn parse(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() as u64 > MAX_JSON_METADATA_BYTES {
            return Err(ContractError::new(
                "runtime manifest exceeds consumer bound",
            ));
        }
        let manifest: Self = serde_json::from_slice(bytes).map_err(|error| {
            ContractError::new(format!("invalid strict runtime manifest: {error}"))
        })?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validates authority, bounds, path safety, digests, and uniqueness.
    ///
    /// # Errors
    ///
    /// Returns an error when any manifest invariant fails.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version == 0
            || self.version != crate::MEMCORDON_VERSION
            || self.source_commit != "67aa1f74d9a76713ab343ea2afbe6403da7429b7"
        {
            return Err(ContractError::new("runtime manifest authority drifted"));
        }
        require_digest(&self.archive_sha256)?;
        if self.components.is_empty() || self.components.len() > MAX_ARCHIVE_ENTRIES {
            return Err(ContractError::new(
                "runtime component inventory has invalid size",
            ));
        }
        let mut names = BTreeSet::new();
        let mut paths = BTreeSet::new();
        let mut folded_paths = BTreeSet::new();
        let mut expanded = 0_u64;
        for component in &self.components {
            require_digest(&component.sha256)?;
            validate_relative_path(&component.path)?;
            if component.name.is_empty()
                || !names.insert(component.name.clone())
                || !paths.insert(component.path.clone())
                || !folded_paths.insert(component.path.to_lowercase())
            {
                return Err(ContractError::new("duplicate runtime component identity"));
            }
            if component.executable && component.bytes > MAX_EXECUTABLE_BYTES {
                return Err(ContractError::new(
                    "runtime executable exceeds consumer bound",
                ));
            }
            expanded = expanded
                .checked_add(component.bytes)
                .ok_or_else(|| ContractError::new("runtime expanded byte count overflowed"))?;
        }
        if expanded > MAX_EXPANDED_BYTES {
            return Err(ContractError::new(
                "runtime bundle exceeds expanded-size bound",
            ));
        }
        Ok(())
    }
}

/// Requires every lock-selected component to occur in the measured manifest.
///
/// # Errors
///
/// Returns an error when a required component is absent.
pub fn validate_component_inventory(
    manifest: &RuntimeManifest,
    required: &[String],
) -> Result<(), ContractError> {
    let observed = manifest
        .components
        .iter()
        .map(|component| component.name.as_str())
        .collect::<BTreeSet<_>>();
    for name in required {
        if !observed.contains(name.as_str()) {
            return Err(ContractError::new(format!(
                "runtime manifest omits required component {name}"
            )));
        }
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), ContractError> {
    if value.contains(':') || value.ends_with('.') || value.ends_with(' ') {
        return Err(ContractError::new("unsafe runtime component path"));
    }
    let path = Path::new(value);
    if path.is_absolute() || value.starts_with("//") || value.starts_with("\\\\") {
        return Err(ContractError::new("runtime component path is absolute"));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(ContractError::new(
            "runtime component path traverses its root",
        ));
    }
    Ok(())
}

fn require_digest(value: &str) -> Result<(), ContractError> {
    Digest::from_hex(value)
        .map(|_| ())
        .map_err(|error| ContractError::new(format!("invalid component digest: {error}")))
}
