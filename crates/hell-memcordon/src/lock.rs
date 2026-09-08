use std::collections::BTreeMap;

use hell_digest::{Digest, Sha256};
use serde::{Deserialize, Serialize};

use crate::ContractError;

pub const MEMCORDON_VERSION: &str = "0.5.2-rc.23";
pub const EXECUTION_SCHEMA: u32 = 8;
pub const PLAN_SCHEMA: u32 = 7;
pub const PACKAGE_INSPECTION_SCHEMA: u32 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Platform {
    #[serde(rename = "linux-x86_64")]
    LinuxX86_64,
    #[serde(rename = "windows-x86_64")]
    WindowsX86_64,
}

impl Platform {
    /// Returns the supported runtime platform for this compilation target.
    #[must_use]
    pub const fn current() -> Option<Self> {
        if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            Some(Self::LinuxX86_64)
        } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
            Some(Self::WindowsX86_64)
        } else {
            None
        }
    }

    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "linux-x86_64",
            Self::WindowsX86_64 => "windows-x86_64",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RuntimeMetadataAsset {
    pub asset_id: u64,
    pub filename: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RuntimeMetadata {
    pub release_manifest: RuntimeMetadataAsset,
    pub publication_report: RuntimeMetadataAsset,
    pub checksums: RuntimeMetadataAsset,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RuntimeAsset {
    pub asset_id: u64,
    pub filename: String,
    pub bytes: u64,
    pub sha256: String,
    pub target: String,
    pub mechanism: String,
    pub required_components: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RuntimeLock {
    pub schema_version: u32,
    pub version: String,
    pub repository: String,
    pub release_id: u64,
    pub source_commit: String,
    pub execution_schema: u32,
    pub plan_schema: u32,
    pub doctor_schema: u32,
    #[serde(default = "clean_schema")]
    pub clean_schema: u32,
    pub package_inspection_schema: u32,
    pub metadata: RuntimeMetadata,
    pub platform: BTreeMap<Platform, RuntimeAsset>,
}

const fn clean_schema() -> u32 {
    2
}

impl RuntimeLock {
    /// Parses and validates a strict version-one runtime lock.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed TOML or an authority mismatch.
    pub fn parse(text: &str) -> Result<Self, ContractError> {
        let parsed: Self = toml::from_str(text).map_err(|error| {
            ContractError::new(format!("invalid MemCordon runtime lock: {error}"))
        })?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// Validates release, schema, platform, digest, and component bindings.
    ///
    /// # Errors
    ///
    /// Returns an error when any binding differs from the reviewed contract.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != 1
            || self.version != MEMCORDON_VERSION
            || self.repository != "Portfoligno/memcordon"
            || self.release_id != 384_239_676
            || self.source_commit != "67aa1f74d9a76713ab343ea2afbe6403da7429b7"
            || self.execution_schema != EXECUTION_SCHEMA
            || self.plan_schema != PLAN_SCHEMA
            || self.doctor_schema != 5
            || self.clean_schema != 2
            || self.package_inspection_schema != PACKAGE_INSPECTION_SCHEMA
        {
            return Err(ContractError::new(
                "runtime lock does not identify the reviewed MemCordon rc.23 contract",
            ));
        }
        if self.platform.len() != 2 {
            return Err(ContractError::new(
                "runtime lock must contain exactly Linux x86-64 and Windows x86-64",
            ));
        }
        validate_metadata(&self.metadata)?;
        validate_asset(
            self.asset(Platform::LinuxX86_64)?,
            "x86_64-unknown-linux-gnu",
            "linux-pid-namespace-cgroup-v2",
            &["memcordon", "memcordon-sealed-agent"],
        )?;
        validate_asset(
            self.asset(Platform::WindowsX86_64)?,
            "x86_64-pc-windows-msvc",
            "windows-job-object-v2",
            &[
                "memcordon.exe",
                "memcordon-sealed-agent.exe",
                "memcordon-target-desktop-bootstrap.exe",
                "memcordon-session-broker.exe",
            ],
        )
    }

    /// Selects the exact asset for a supported platform.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform entry is absent.
    pub fn asset(&self, platform: Platform) -> Result<&RuntimeAsset, ContractError> {
        self.platform
            .get(&platform)
            .ok_or_else(|| ContractError::new(format!("runtime lock omits {}", platform.key())))
    }

    /// Selects the asset for the current compilation platform.
    ///
    /// # Errors
    ///
    /// Returns an error on unsupported platforms or an incomplete lock.
    pub fn current_asset(&self) -> Result<&RuntimeAsset, ContractError> {
        let platform = Platform::current().ok_or_else(|| {
            ContractError::new("MemCordon sealed runtime is unavailable on this platform")
        })?;
        self.asset(platform)
    }
}

fn validate_metadata(metadata: &RuntimeMetadata) -> Result<(), ContractError> {
    for asset in [
        &metadata.release_manifest,
        &metadata.publication_report,
        &metadata.checksums,
    ] {
        validate_digest(&asset.sha256)?;
        if asset.filename.is_empty() || asset.bytes == 0 {
            return Err(ContractError::new("metadata asset identity is incomplete"));
        }
    }
    Ok(())
}

fn validate_asset(
    asset: &RuntimeAsset,
    target: &str,
    mechanism: &str,
    components: &[&str],
) -> Result<(), ContractError> {
    validate_digest(&asset.sha256)?;
    if asset.asset_id == 0 || asset.bytes == 0 || asset.filename.is_empty() {
        return Err(ContractError::new("runtime asset identity is incomplete"));
    }
    if asset.target != target || asset.mechanism != mechanism {
        return Err(ContractError::new("runtime asset platform binding drifted"));
    }
    let expected = components
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    if asset.required_components != expected {
        return Err(ContractError::new(
            "runtime asset component inventory is incomplete or reordered",
        ));
    }
    Ok(())
}

fn validate_digest(digest: &str) -> Result<(), ContractError> {
    Digest::from_hex(digest)
        .map(|_| ())
        .map_err(|error| ContractError::new(format!("invalid SHA-256 digest: {error}")))
}

#[must_use]
pub fn runtime_lock_digest(bytes: &[u8]) -> Digest {
    let mut hash = Sha256::new();
    hash.update(bytes);
    hash.finish()
}
