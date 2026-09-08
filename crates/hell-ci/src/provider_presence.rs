//! Read-only presence evidence for the pinned MemCordon rc.23 package contract.

use std::fs;
use std::io;
use std::path::Path;

use serde::Serialize;

/// No lease authorizes no removal; only native proof authorizes an absent receipt.
pub fn unowned_cleanup_receipt(
    provider_lease_id: String,
    operation_id: String,
    platform: hell_memcordon::PlatformId,
    absence: Result<(), String>,
) -> hell_memcordon::ProviderCleanupReceiptV1 {
    use hell_memcordon::{
        PROVIDER_CLEANUP_RECEIPT_SCHEMA_V1, ProviderCleanupReceiptV1, ProviderLifecycleState,
    };
    let failure = absence.err();
    ProviderCleanupReceiptV1 {
        schema_version: PROVIDER_CLEANUP_RECEIPT_SCHEMA_V1,
        provider_lease_id,
        operation_id,
        platform,
        attempted: false,
        final_state: if failure.is_none() {
            ProviderLifecycleState::Absent
        } else {
            ProviderLifecycleState::FailedDirty
        },
        installed_footprint_absent: failure.is_none(),
        active_operations: 0,
        failure,
    }
}

pub const LINUX_PATHS: &[&str] = &[
    "/run/memcordon-sealed-package.lock",
    "/usr/libexec/memcordon-sealed-agent",
    "/usr/lib/systemd/system/memcordon-sealed-agent.service",
    "/usr/lib/systemd/system/memcordon-sealed-agent.socket",
    "/usr/lib/systemd/system/memcordon-sealed-launcher.service",
    "/usr/lib/systemd/system/memcordon-sealed-launcher.socket",
    "/usr/lib/tmpfiles.d/memcordon.conf",
    "/run/memcordon",
    "/var/lib/memcordon/sealed",
    "/sys/fs/cgroup/memcordon-sealed",
];

pub const LINUX_UNITS: &[&str] = &[
    "memcordon-sealed-agent.service",
    "memcordon-sealed-agent.socket",
    "memcordon-sealed-launcher.service",
    "memcordon-sealed-launcher.socket",
];

pub const WINDOWS_SERVICES: &[&str] = &[
    "MemCordonSealedControl",
    "MemCordonSealedLauncher",
    "MemCordonSealedSessionBroker",
    "MemCordonSealedGuardian-000",
    "MemCordonSealedGuardian-001",
    "MemCordonSealedGuardian-002",
    "MemCordonSealedGuardian-003",
    "MemCordonSealedGuardian-004",
    "MemCordonSealedGuardian-005",
    "MemCordonSealedGuardian-006",
    "MemCordonSealedGuardian-007",
];

pub const WINDOWS_PIPES: &[&str] = &[
    "memcordon-sealed-agent-v1",
    "memcordon-sealed-launcher-v1",
    "memcordon-sealed-session-broker-v1",
];

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Presence {
    Absent,
    Present,
    Unreadable,
}

#[derive(Debug, Serialize)]
pub struct Observation {
    pub authority: String,
    pub presence: Presence,
    pub detail: Option<String>,
}

/// Only native NotFound establishes absence; symlinks and unreadable paths do not.
pub fn observe_path(path: &Path) -> Observation {
    observe_metadata(path, fs::symlink_metadata(path))
}

pub fn observe_metadata(path: &Path, result: io::Result<fs::Metadata>) -> Observation {
    let (presence, detail) = match result {
        Ok(_) => (Presence::Present, None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (Presence::Absent, None),
        Err(error) => (Presence::Unreadable, Some(error.to_string())),
    };
    Observation {
        authority: path.display().to_string(),
        presence,
        detail,
    }
}

pub fn require_absent(observations: &[Observation]) -> Result<(), String> {
    if observations.is_empty() {
        return Err("provider footprint inspection collected no native evidence".to_owned());
    }
    if let Some(observed) = observations
        .iter()
        .find(|entry| entry.presence != Presence::Absent)
    {
        return Err(format!(
            "provider authority {} is {:?}: {}",
            observed.authority,
            observed.presence,
            observed
                .detail
                .as_deref()
                .unwrap_or("preexisting footprint")
        ));
    }
    Ok(())
}

/// A missing systemd unit must have all four expected native properties.
pub fn systemd_unit_absent(stdout: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(stdout).map_err(|_| "systemd properties are not UTF-8")?;
    let mut properties = std::collections::BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').ok_or("malformed systemd property")?;
        if properties.insert(key, value).is_some() {
            return Err("duplicate systemd property".to_owned());
        }
    }
    let expected = std::collections::BTreeMap::from([
        ("LoadState", "not-found"),
        ("ActiveState", "inactive"),
        ("FragmentPath", ""),
        ("UnitFileState", ""),
    ]);
    if properties != expected {
        return Err("systemd unit has loaded, enabled, or ambiguous state".to_owned());
    }
    Ok(())
}

/// This validates the producer response, never installation absence by itself.
pub fn verify_failure_protocol(
    linux: bool,
    code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
    overflow: bool,
) -> Result<(), String> {
    if overflow || code != Some(125) || !stdout.is_empty() {
        return Err("package verification returned unexpected status or bounded output".to_owned());
    }
    let diagnostic =
        std::str::from_utf8(stderr).map_err(|_| "package verification diagnostic is not UTF-8")?;
    if diagnostic.trim().is_empty()
        || (linux
            && diagnostic.trim_end() != "MCSEALED-PACKAGE-VERIFY: installed package is incomplete")
    {
        return Err(
            "package verification returned an unexpected diagnostic; see retained command evidence"
                .to_owned(),
        );
    }
    Ok(())
}
