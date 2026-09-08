use serde::{Deserialize, Serialize};

use std::collections::BTreeSet;
use std::path::{Component, Path};

use hell_digest::Digest;

use crate::ContractError;

pub const ACQUISITION_RECEIPT_SCHEMA_V1: u32 = 1;
pub const PROVIDER_RECEIPT_SCHEMA_V1: u32 = 1;
pub const PROVIDER_CLEANUP_RECEIPT_SCHEMA_V1: u32 = 1;
pub const OPERATION_RECEIPT_SCHEMA_V1: u32 = 1;
pub const FINALIZATION_RECEIPT_SCHEMA_V1: u32 = 1;
pub const WINDOWS_CANDIDATE_IDENTITY_RECEIPT_SCHEMA_V1: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlatformId {
    LinuxX86_64,
    WindowsX86_64,
    MacosAarch64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateBoundaryPolicy {
    SealedLinux,
    SealedWindows,
    ExistingMacosNative,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationClass {
    TrustedHostOperation,
    SealedRootCandidateOperation,
    DescendantOfSealedOperation,
    ExistingMacosCandidateOperation,
}

impl OperationClass {
    #[must_use]
    pub const fn requires_new_provider_boundary(self) -> bool {
        matches!(self, Self::SealedRootCandidateOperation)
    }

    #[must_use]
    pub const fn forbids_provider_launch(self) -> bool {
        matches!(
            self,
            Self::TrustedHostOperation
                | Self::DescendantOfSealedOperation
                | Self::ExistingMacosCandidateOperation
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportStatus {
    Downloaded,
    VerifiedCacheHit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentObservationV1 {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionReceiptV1 {
    pub schema_version: u32,
    pub runtime_lock_digest: String,
    pub version: String,
    pub release_id: u64,
    pub source_commit: String,
    pub platform: PlatformId,
    pub target: String,
    pub mechanism: String,
    pub archive_filename: String,
    pub archive_bytes: u64,
    pub archive_sha256: String,
    pub release_manifest_sha256: String,
    pub publication_report_sha256: String,
    pub checksums_sha256: String,
    pub runtime_manifest_sha256: String,
    pub components: Vec<ComponentObservationV1>,
    pub transport: TransportStatus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderLifecycleState {
    Absent,
    Acquired,
    PackageInspected,
    Installing,
    Qualified,
    Running,
    Draining,
    Uninstalling,
    Removed,
    FailedDirty,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderLeaseStateMachine {
    state: ProviderLifecycleState,
}

impl Default for ProviderLeaseStateMachine {
    fn default() -> Self {
        Self {
            state: ProviderLifecycleState::Absent,
        }
    }
}

impl ProviderLeaseStateMachine {
    #[must_use]
    pub const fn state(&self) -> ProviderLifecycleState {
        self.state
    }

    #[must_use]
    pub const fn admits_sealed_roots(&self) -> bool {
        matches!(
            self.state,
            ProviderLifecycleState::Qualified | ProviderLifecycleState::Running
        )
    }

    /// Applies one reviewed provider lifecycle transition.
    ///
    /// # Errors
    ///
    /// Returns an error for a skipped, reversed, or post-removal transition.
    pub fn transition(&mut self, next: ProviderLifecycleState) -> Result<(), ContractError> {
        let valid = matches!(
            (self.state, next),
            (
                ProviderLifecycleState::Absent,
                ProviderLifecycleState::Acquired
            ) | (
                ProviderLifecycleState::Acquired,
                ProviderLifecycleState::PackageInspected
            ) | (
                ProviderLifecycleState::PackageInspected,
                ProviderLifecycleState::Installing
            ) | (
                ProviderLifecycleState::Installing,
                ProviderLifecycleState::Qualified
            ) | (
                ProviderLifecycleState::Qualified,
                ProviderLifecycleState::Running | ProviderLifecycleState::Draining
            ) | (
                ProviderLifecycleState::Running,
                ProviderLifecycleState::Draining
            ) | (
                ProviderLifecycleState::Draining,
                ProviderLifecycleState::Uninstalling
            ) | (
                ProviderLifecycleState::Uninstalling,
                ProviderLifecycleState::Removed
            )
        ) || (next == ProviderLifecycleState::FailedDirty
            && self.state != ProviderLifecycleState::Removed);
        if !valid {
            return Err(ContractError::new(format!(
                "invalid provider lifecycle transition {:?} -> {next:?}",
                self.state
            )));
        }
        self.state = next;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderLifecycleReceiptV1 {
    pub schema_version: u32,
    pub provider_lease_id: String,
    pub lease_owner: String,
    pub runtime_lock_digest: String,
    pub agent_sha256: String,
    pub package_inspection_digest: Option<String>,
    pub package_verification_digest: Option<String>,
    pub qualification_digest: Option<String>,
    pub state: ProviderLifecycleState,
    pub admission_closed: bool,
    pub active_operations: u32,
    pub cleanup_succeeded: bool,
    pub failure: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCleanupReceiptV1 {
    pub schema_version: u32,
    pub provider_lease_id: String,
    pub operation_id: String,
    pub platform: PlatformId,
    pub attempted: bool,
    pub final_state: ProviderLifecycleState,
    pub installed_footprint_absent: bool,
    pub active_operations: u32,
    pub failure: Option<String>,
}

impl ProviderCleanupReceiptV1 {
    /// Validates terminal cleanup consistency.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema or contradictory facts.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != PROVIDER_CLEANUP_RECEIPT_SCHEMA_V1 {
            return Err(ContractError::new(
                "unsupported provider-cleanup receipt schema",
            ));
        }
        let clean = self.final_state == ProviderLifecycleState::Removed
            && self.installed_footprint_absent
            && self.active_operations == 0
            && self.failure.is_none();
        let absent_without_install = self.final_state == ProviderLifecycleState::Absent
            && !self.attempted
            && self.installed_footprint_absent
            && self.active_operations == 0
            && self.failure.is_none();
        if !clean
            && !absent_without_install
            && self.final_state != ProviderLifecycleState::FailedDirty
        {
            return Err(ContractError::new(
                "provider-cleanup receipt has contradictory terminal facts",
            ));
        }
        Ok(())
    }
}

/// Terminal state of the trusted Windows restricted-token adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsIdentityAdapterOutcomeV1 {
    Completed,
    SetupRejected,
    Failed,
}

/// Terminal state of the adapter-owned immediate-child stream relays.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsIdentityRelayOutcomeV1 {
    NotUsed,
    Completed,
    Failed,
}

/// Strict receipt for the Windows candidate-identity adapter boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCandidateIdentityReceiptV1 {
    pub schema_version: u32,
    pub operation_id: String,
    pub candidate_released: bool,
    pub token_policy_digest: String,
    pub command_binding_digest: String,
    pub child_native_status: Option<u32>,
    pub direct_child_reaped: bool,
    pub adapter_outcome: WindowsIdentityAdapterOutcomeV1,
    pub relay_outcome: WindowsIdentityRelayOutcomeV1,
}

impl WindowsCandidateIdentityReceiptV1 {
    /// Validates full-width child-status and adapter/relay lifecycle provenance.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema or contradictory lifecycle facts.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != WINDOWS_CANDIDATE_IDENTITY_RECEIPT_SCHEMA_V1
            || self.operation_id.is_empty()
            || self.operation_id.len() > 256
        {
            return Err(ContractError::new(
                "invalid Windows candidate-identity receipt envelope",
            ));
        }
        require_digest(&self.token_policy_digest)?;
        require_digest(&self.command_binding_digest)?;
        if self.candidate_released {
            if self.child_native_status.is_none()
                || !self.direct_child_reaped
                || self.adapter_outcome != WindowsIdentityAdapterOutcomeV1::Completed
                || self.relay_outcome == WindowsIdentityRelayOutcomeV1::Failed
            {
                return Err(ContractError::new(
                    "released Windows candidate lacks terminal adapter evidence",
                ));
            }
        } else if self.child_native_status.is_some()
            || self.direct_child_reaped
            || self.adapter_outcome == WindowsIdentityAdapterOutcomeV1::Completed
        {
            return Err(ContractError::new(
                "unreleased Windows candidate claims child completion",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CandidateResult {
    Exited { native_status: u32 },
    Signaled { signal: u32 },
    NotReleased,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SealedTerminal {
    OrdinaryResult,
    InnerDeadline,
    OuterDeadline,
    SetupRejection { reason: String },
    ProviderFailure { reason: String },
    InvalidOrMissingReport { reason: String },
    CleanupUncertainty { reason: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedOperationReceiptV1 {
    pub schema_version: u32,
    pub operation_id: String,
    pub platform: PlatformId,
    pub candidate_commit: String,
    pub workflow_commit: String,
    pub policy_digest: String,
    pub request_digest: String,
    pub runtime_lock_digest: String,
    pub runtime_manifest_digest: String,
    pub provider_lease_id: String,
    pub package_verification_digest: String,
    pub qualification_digest: String,
    pub frontend_lifecycle_digest: String,
    pub raw_memcordon_report_digest: String,
    pub identity_adapter_receipt_digest: Option<String>,
    pub output_receipt_digest: String,
    pub candidate_result: CandidateResult,
    pub terminal: SealedTerminal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationLedgerEntryV1 {
    pub operation_id: String,
    pub boundary: CandidateBoundaryPolicy,
    pub request_digest: String,
    pub raw_report_path: Option<String>,
    pub raw_report_digest: Option<String>,
    pub normalized_report_path: Option<String>,
    pub normalized_report_digest: Option<String>,
    pub identity_adapter_path: Option<String>,
    pub identity_adapter_digest: Option<String>,
    pub terminal: SealedTerminal,
}

impl OperationLedgerEntryV1 {
    /// Validates one canonical operation-ledger entry.
    ///
    /// # Errors
    ///
    /// Returns an error when an identifier, digest binding, path, or platform
    /// evidence shape is incomplete.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.operation_id.is_empty()
            || self.operation_id.len() > 256
            || self
                .operation_id
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(ContractError::new("invalid operation ledger id"));
        }
        require_digest(&self.request_digest)?;
        require_path_digest_pair(
            self.raw_report_path.as_deref(),
            self.raw_report_digest.as_deref(),
            "raw report",
        )?;
        require_path_digest_pair(
            self.normalized_report_path.as_deref(),
            self.normalized_report_digest.as_deref(),
            "normalized report",
        )?;
        require_path_digest_pair(
            self.identity_adapter_path.as_deref(),
            self.identity_adapter_digest.as_deref(),
            "identity adapter",
        )?;
        match self.boundary {
            CandidateBoundaryPolicy::SealedLinux => {
                require_sealed_report_bindings(self)?;
            }
            CandidateBoundaryPolicy::SealedWindows => {
                require_sealed_report_bindings(self)?;
                if self.identity_adapter_path.is_none() {
                    return Err(ContractError::new(
                        "sealed Windows operation lacks identity adapter evidence",
                    ));
                }
            }
            CandidateBoundaryPolicy::ExistingMacosNative => {
                if self.raw_report_path.is_some()
                    || self.normalized_report_path.is_some()
                    || self.identity_adapter_path.is_some()
                {
                    return Err(ContractError::new(
                        "existing macOS boundary cannot claim MemCordon evidence",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Validates a complete ledger and rejects duplicate ids and bound paths.
///
/// # Errors
///
/// Returns an error when an entry is malformed or when two entries claim the
/// same operation id or evidence path.
pub fn validate_operation_ledger(entries: &[OperationLedgerEntryV1]) -> Result<(), ContractError> {
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for entry in entries {
        entry.validate()?;
        if !ids.insert(entry.operation_id.as_str()) {
            return Err(ContractError::new(
                "operation ledger contains duplicate ids",
            ));
        }
        for path in [
            entry.raw_report_path.as_deref(),
            entry.normalized_report_path.as_deref(),
            entry.identity_adapter_path.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !paths.insert(path) {
                return Err(ContractError::new(
                    "operation ledger contains duplicate evidence paths",
                ));
            }
        }
    }
    Ok(())
}

/// Serializes a validated ledger in deterministic operation-id order.
///
/// # Errors
///
/// Returns an error when the ledger is malformed or cannot be serialized.
pub fn operation_ledger_json(entries: &[OperationLedgerEntryV1]) -> Result<Vec<u8>, ContractError> {
    validate_operation_ledger(entries)?;
    let mut ordered = entries.to_vec();
    ordered.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    let mut bytes = serde_json::to_vec(&ordered).map_err(|error| {
        ContractError::new(format!("cannot serialize operation ledger: {error}"))
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn require_sealed_report_bindings(entry: &OperationLedgerEntryV1) -> Result<(), ContractError> {
    if entry.raw_report_path.is_none() || entry.normalized_report_path.is_none() {
        return Err(ContractError::new(
            "sealed operation lacks raw or normalized report evidence",
        ));
    }
    Ok(())
}

fn require_path_digest_pair(
    path: Option<&str>,
    digest: Option<&str>,
    label: &str,
) -> Result<(), ContractError> {
    if path.is_some() != digest.is_some() {
        return Err(ContractError::new(format!(
            "operation ledger {label} path/digest binding is incomplete"
        )));
    }
    if let Some(path) = path {
        let path = Path::new(path);
        if path.as_os_str().is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(ContractError::new(format!(
                "operation ledger {label} path is not a safe relative path"
            )));
        }
        require_digest(digest.expect("paired digest is present"))?;
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizationReceiptV1 {
    pub schema_version: u32,
    pub platform: PlatformId,
    pub candidate_commit: String,
    pub workflow_commit: String,
    pub runtime_lock_digest: String,
    pub acquisition_digest: Option<String>,
    pub provider_lifecycle_digest: Option<String>,
    pub provider_cleanup_digest: Option<String>,
    pub operations_digest: Option<String>,
    pub inventory_digest: String,
    pub required_operation_ids: Vec<String>,
    pub observed_operation_ids: Vec<String>,
    pub cleanup_succeeded: bool,
    pub admitted: bool,
    pub failure: Option<String>,
}

impl FinalizationReceiptV1 {
    /// Validates cleanup ordering, digests, and exact operation coverage.
    ///
    /// # Errors
    ///
    /// Returns an error when an admitted receipt is incomplete or inconsistent.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != FINALIZATION_RECEIPT_SCHEMA_V1 {
            return Err(ContractError::new(
                "unsupported finalization receipt schema",
            ));
        }
        require_digest(&self.runtime_lock_digest)?;
        require_digest(&self.inventory_digest)?;
        for digest in [
            self.acquisition_digest.as_deref(),
            self.provider_lifecycle_digest.as_deref(),
            self.provider_cleanup_digest.as_deref(),
            self.operations_digest.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            require_digest(digest)?;
        }
        let mut required = self.required_operation_ids.clone();
        required.sort();
        let mut observed = self.observed_operation_ids.clone();
        observed.sort();
        let unique = |values: &[String]| values.windows(2).all(|pair| pair[0] != pair[1]);
        if !unique(&required) || !unique(&observed) {
            return Err(ContractError::new(
                "operation ledger contains duplicate ids",
            ));
        }
        if self.admitted
            && (!self.cleanup_succeeded
                || self.failure.is_some()
                || required != observed
                || self.acquisition_digest.is_none()
                || self.provider_cleanup_digest.is_none()
                || self.operations_digest.is_none())
        {
            return Err(ContractError::new(
                "admitted platform finalization is incomplete or precedes cleanup",
            ));
        }
        Ok(())
    }
}

fn require_digest(value: &str) -> Result<(), ContractError> {
    Digest::from_hex(value)
        .map(|_| ())
        .map_err(|error| ContractError::new(format!("invalid evidence digest: {error}")))
}
