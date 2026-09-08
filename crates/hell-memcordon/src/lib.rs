//! Strict consumer contract for the pinned `MemCordon` runtime.
//!
//! This crate deliberately contains no provider implementation and no native
//! service handles. It binds released bytes, native argv, lifecycle admission,
//! and the evidence that higher-level CI code must retain.

mod admission;
mod deadlines;
mod evidence;
mod invocation;
mod lock;
mod report;
mod reservation;
mod runtime_manifest;

pub use admission::{AdmissionError, AdmissionLease, SealedAdmission};
pub use deadlines::{AbsoluteDeadlines, DeadlineError, InnerBudget};
pub use evidence::{
    ACQUISITION_RECEIPT_SCHEMA_V1, AcquisitionReceiptV1, CandidateBoundaryPolicy, CandidateResult,
    ComponentObservationV1, FINALIZATION_RECEIPT_SCHEMA_V1, FinalizationReceiptV1,
    OPERATION_GROUP_PHASES_V2, OPERATION_LEDGER_SCHEMA_V2, OPERATION_RECEIPT_SCHEMA_V1,
    OperationClass, OperationGroupV2, OperationLedgerEntryV1, OperationLedgerV2,
    PROVIDER_CLEANUP_RECEIPT_SCHEMA_V1, PROVIDER_RECEIPT_SCHEMA_V1, PlatformId,
    ProviderCleanupReceiptV1, ProviderLeaseStateMachine, ProviderLifecycleReceiptV1,
    ProviderLifecycleState, SealedOperationReceiptV1, SealedTerminal, TransportStatus,
    WINDOWS_CANDIDATE_IDENTITY_RECEIPT_SCHEMA_V1, WindowsCandidateIdentityReceiptV1,
    WindowsIdentityAdapterOutcomeV1, WindowsIdentityRelayOutcomeV1, operation_ledger_json,
    operation_ledger_v2_json, validate_operation_ledger, validate_operation_ledger_v2,
};
pub use invocation::{
    AuthorizedCandidateRequest, NativeArgument, NativeArgumentRaw, PreparedSealedInvocation,
    sealed_arguments,
};
pub use lock::{
    EXECUTION_SCHEMA, MEMCORDON_VERSION, PACKAGE_INSPECTION_SCHEMA, PLAN_SCHEMA, Platform,
    RuntimeAsset, RuntimeLock, RuntimeMetadataAsset, runtime_lock_digest,
};
pub use report::{
    MAX_EXECUTION_REPORT_BYTES, Schema8ProjectionV1, Schema8TerminalV1, parse_schema8_projection,
    project_schema8_report, validate_schema8_wire,
};
pub use reservation::ReportReservation;
pub use runtime_manifest::{
    MAX_ARCHIVE_ENTRIES, MAX_EXECUTABLE_BYTES, MAX_EXPANDED_BYTES, MAX_JSON_METADATA_BYTES,
    RuntimeComponent, RuntimeComponentRole, RuntimeManifest, SealedRuntime,
    validate_component_inventory,
};

/// Error returned when a versioned consumer contract is malformed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractError(String);

impl ContractError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for ContractError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ContractError {}
