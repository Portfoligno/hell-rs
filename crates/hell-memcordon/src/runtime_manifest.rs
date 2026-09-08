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
    pub project: String,
    pub version: String,
    pub source_commit: String,
    pub target: String,
    pub components: Vec<RuntimeComponent>,
    pub sealed: SealedRuntime,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeComponent {
    pub id: String,
    pub path: String,
    pub role: RuntimeComponentRole,
    pub size: u64,
    pub mode: u32,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeComponentRole {
    PublicCli,
    SealedAgent,
    DesktopBootstrap,
    SessionBroker,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SealedRuntime {
    Included {
        agent_component: String,
        provider_protocol: u32,
        mechanism: String,
        execution_report_schema: u32,
        plan_report_schema: u32,
        doctor_report_schema: u32,
        qualification_schema: u32,
    },
    NotApplicable {
        reason: String,
    },
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
        if self.schema_version != 1
            || self.project != "memcordon"
            || self.version != crate::MEMCORDON_VERSION
            || self.source_commit != "67aa1f74d9a76713ab343ea2afbe6403da7429b7"
        {
            return Err(ContractError::new("runtime manifest authority drifted"));
        }
        self.validate_platform()?;
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
            if component.id.is_empty()
                || !names.insert(component.id.clone())
                || !paths.insert(component.path.clone())
                || !folded_paths.insert(component.path.to_lowercase())
            {
                return Err(ContractError::new("duplicate runtime component identity"));
            }
            if component.size == 0
                || component.size > MAX_EXECUTABLE_BYTES
                || component.mode != 0o755
            {
                return Err(ContractError::new(
                    "runtime executable exceeds consumer bound",
                ));
            }
            expanded = expanded
                .checked_add(component.size)
                .ok_or_else(|| ContractError::new("runtime expanded byte count overflowed"))?;
        }
        if expanded > MAX_EXPANDED_BYTES {
            return Err(ContractError::new(
                "runtime bundle exceeds expanded-size bound",
            ));
        }
        Ok(())
    }

    fn validate_platform(&self) -> Result<(), ContractError> {
        let (windows, protocol, mechanism) = match self.target.as_str() {
            "x86_64-unknown-linux-gnu" => (false, 2, "linux-pid-namespace-cgroup-v2"),
            "x86_64-pc-windows-msvc" => (true, 1, "windows-job-object-v2"),
            _ => return Err(ContractError::new("unsupported runtime manifest target")),
        };
        let expected_sealed = SealedRuntime::Included {
            agent_component: "sealed-agent".to_owned(),
            provider_protocol: protocol,
            mechanism: mechanism.to_owned(),
            execution_report_schema: 8,
            plan_report_schema: 7,
            doctor_report_schema: 5,
            qualification_schema: 2,
        };
        if self.sealed != expected_sealed {
            return Err(ContractError::new("runtime sealed authority drifted"));
        }
        if self.components.len() != if windows { 4 } else { 2 } {
            return Err(ContractError::new("runtime component inventory differs"));
        }
        for component in &self.components {
            let (id, path) = match (component.role, windows) {
                (RuntimeComponentRole::PublicCli, false) => ("public-cli", "memcordon"),
                (RuntimeComponentRole::PublicCli, true) => ("public-cli", "memcordon.exe"),
                (RuntimeComponentRole::SealedAgent, false) => {
                    ("sealed-agent", "memcordon-sealed-agent")
                }
                (RuntimeComponentRole::SealedAgent, true) => {
                    ("sealed-agent", "memcordon-sealed-agent.exe")
                }
                (RuntimeComponentRole::DesktopBootstrap, true) => (
                    "target-desktop-bootstrap",
                    "memcordon-target-desktop-bootstrap.exe",
                ),
                (RuntimeComponentRole::SessionBroker, true) => {
                    ("session-broker", "memcordon-session-broker.exe")
                }
                _ => {
                    return Err(ContractError::new(
                        "runtime component role is invalid for target",
                    ));
                }
            };
            if component.id != id || component.path != path {
                return Err(ContractError::new(
                    "runtime component identity differs from its role",
                ));
            }
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
        .map(|component| component.path.as_str())
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
