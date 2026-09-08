use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Component, Path};

use hell_memcordon::{
    AcquisitionReceiptV1, CandidateBoundaryPolicy, FINALIZATION_RECEIPT_SCHEMA_V1,
    FinalizationReceiptV1, OperationLedgerEntryV1, PlatformId, ProviderCleanupReceiptV1,
    ProviderLifecycleReceiptV1, ProviderLifecycleState, SealedTerminal,
};

use crate::json::{JsonValue, json_member, parse_json, require_exact_json_keys};
use crate::release::manifest::{write_atomic, write_json_new};

use super::task::Task;

const REQUIRED_SUCCESS_FILES: [&str; 8] = [
    "acquisition.json",
    "package-inspect.json",
    "package-verify.json",
    "doctor.json",
    "canaries.json",
    "operations.json",
    "provider-lease.json",
    "provider-cleanup.json",
];

pub(crate) struct FinalizedEvidenceBinding {
    pub(crate) finalization_sha256: String,
    pub(crate) inventory_sha256: String,
    pub(crate) runtime_lock_sha256: String,
    pub(crate) operation_ids: Vec<String>,
}

pub(super) fn run(
    task: &Task,
    candidate_commit: Option<&str>,
    workflow_commit: Option<&str>,
) -> Result<String, String> {
    let output = &task.output;
    let acquisition_bytes = read_regular(&output.join("acquisition.json"))?;
    let acquisition: AcquisitionReceiptV1 = serde_json::from_slice(&acquisition_bytes)
        .map_err(|error| format!("invalid MemCordon acquisition receipt: {error}"))?;
    let cleanup_bytes = read_regular(&output.join("provider-cleanup.json"))?;
    let cleanup: ProviderCleanupReceiptV1 = serde_json::from_slice(&cleanup_bytes)
        .map_err(|error| format!("invalid MemCordon cleanup receipt: {error}"))?;
    cleanup.validate().map_err(|error| error.to_string())?;
    let mut missing = Vec::new();
    for relative in REQUIRED_SUCCESS_FILES {
        if !output.join(relative).is_file() {
            missing.push(relative.to_owned());
        }
    }
    let operations_bytes = read_regular(&output.join("operations.json"))?;
    let operations: Vec<OperationLedgerEntryV1> = serde_json::from_slice(&operations_bytes)
        .map_err(|error| format!("invalid MemCordon operation ledger: {error}"))?;
    let canonical_operations =
        hell_memcordon::operation_ledger_json(&operations).map_err(|error| error.to_string())?;
    if canonical_operations != operations_bytes {
        return Err("MemCordon operation ledger is not canonical".to_owned());
    }
    let observed_operation_ids = validate_operations(output, &acquisition, &operations)?;
    let required_operation_ids = task.required_operation_ids.clone();
    let exact_coverage =
        sorted_unique(&required_operation_ids)? == sorted_unique(&observed_operation_ids)?;
    let success = missing.is_empty()
        && !operations.is_empty()
        && exact_coverage
        && cleanup.final_state == ProviderLifecycleState::Removed
        && cleanup.installed_footprint_absent
        && cleanup.active_operations == 0
        && cleanup.failure.is_none();
    let inventory = inventory(output)?;
    let inventory_bytes = encode_inventory(&inventory);
    write_atomic(&output.join("inventory.sha256"), &inventory_bytes)?;
    let (candidate_commit, workflow_commit) = match (candidate_commit, workflow_commit) {
        (Some(candidate), Some(workflow)) => (candidate.to_owned(), workflow.to_owned()),
        (None, None) if matches!(task.operation.as_str(), "readiness" | "release") => {
            platform_commits(output)?
        }
        (None, None) => {
            return Err(
                "non-release MemCordon finalization requires trusted commit arguments".to_owned(),
            );
        }
        _ => return Err("MemCordon finalization commit binding is incomplete".to_owned()),
    };
    let finalization = FinalizationReceiptV1 {
        schema_version: FINALIZATION_RECEIPT_SCHEMA_V1,
        platform: acquisition.platform,
        candidate_commit,
        workflow_commit,
        runtime_lock_digest: acquisition.runtime_lock_digest,
        acquisition_digest: Some(hell_testkit::sha256_bytes(&acquisition_bytes).hex()),
        provider_lifecycle_digest: Some(file_digest(&output.join("provider-lease.json"))?),
        provider_cleanup_digest: Some(hell_testkit::sha256_bytes(&cleanup_bytes).hex()),
        operations_digest: Some(hell_testkit::sha256_bytes(&operations_bytes).hex()),
        inventory_digest: hell_testkit::sha256_bytes(&inventory_bytes).hex(),
        required_operation_ids,
        observed_operation_ids,
        cleanup_succeeded: success,
        admitted: success,
        failure: (!success).then(|| {
            format!(
                "incomplete MemCordon evidence; missing={}; cleanup={:?}",
                missing.join(","),
                cleanup.final_state
            )
        }),
    };
    finalization.validate().map_err(|error| error.to_string())?;
    let finalization_bytes = write_serde(&output.join("finalization.json"), &finalization)?;
    if success {
        if matches!(task.operation.as_str(), "readiness" | "release") {
            finalize_platform_report(output, &finalization, &finalization_bytes, &inventory_bytes)?;
        }
        Ok(format!(
            "finalized admissible MemCordon evidence for {}",
            Task::platform_id()?
        ))
    } else {
        Err(format!(
            "MemCordon evidence is not admissible: cleanup={:?}, missing={}",
            cleanup.final_state,
            missing.join(",")
        ))
    }
}

fn platform_commits(output: &Path) -> Result<(String, String), String> {
    let platform_report_path = output
        .parent()
        .ok_or_else(|| "MemCordon output root has no platform-report parent".to_owned())?
        .join("platform-report.provisional.json");
    let platform_report = read_json(&platform_report_path)?;
    let platform_fields = platform_report.object()?;
    Ok((
        platform_fields
            .get("candidateSha")
            .ok_or_else(|| "platform report lacks candidateSha".to_owned())?
            .string()?
            .to_owned(),
        platform_fields
            .get("workflowSha")
            .ok_or_else(|| "platform report lacks workflowSha".to_owned())?
            .string()?
            .to_owned(),
    ))
}

fn validate_operations(
    root: &Path,
    acquisition: &AcquisitionReceiptV1,
    operations: &[OperationLedgerEntryV1],
) -> Result<Vec<String>, String> {
    hell_memcordon::validate_operation_ledger(operations).map_err(|error| error.to_string())?;
    let expected_boundary = match acquisition.platform {
        PlatformId::LinuxX86_64 => CandidateBoundaryPolicy::SealedLinux,
        PlatformId::WindowsX86_64 => CandidateBoundaryPolicy::SealedWindows,
        PlatformId::MacosAarch64 => {
            return Err("MemCordon operation ledger cannot target macOS".to_owned());
        }
    };
    let mut ids = Vec::with_capacity(operations.len());
    for entry in operations {
        if entry.boundary != expected_boundary
            || !matches!(entry.terminal, SealedTerminal::OrdinaryResult)
        {
            return Err(format!(
                "MemCordon operation {} lacks the required sealed ordinary terminal",
                entry.operation_id
            ));
        }
        let raw = require_bound_file(
            root,
            entry.raw_report_path.as_deref(),
            entry.raw_report_digest.as_deref(),
            "raw report",
        )?;
        let normalized = require_bound_file(
            root,
            entry.normalized_report_path.as_deref(),
            entry.normalized_report_digest.as_deref(),
            "normalized report",
        )?;
        let normalized = hell_memcordon::parse_schema8_projection(&normalized)
            .map_err(|error| error.to_string())?;
        let request = serde_json::to_vec(&normalized.target_argv)
            .map_err(|error| format!("cannot encode MemCordon request binding: {error}"))?;
        if hell_testkit::sha256_bytes(&request).hex() != entry.request_digest {
            return Err(format!(
                "MemCordon operation {} request binding differs",
                entry.operation_id
            ));
        }
        let reprojected = hell_memcordon::project_schema8_report(
            &raw,
            &acquisition.mechanism,
            &normalized.target_argv,
        )
        .map_err(|error| error.to_string())?;
        if reprojected != normalized {
            return Err(format!(
                "MemCordon operation {} raw report and normalized projection differ",
                entry.operation_id
            ));
        }
        match acquisition.platform {
            PlatformId::WindowsX86_64 => {
                let adapter = require_bound_file(
                    root,
                    entry.identity_adapter_path.as_deref(),
                    entry.identity_adapter_digest.as_deref(),
                    "Windows identity adapter receipt",
                )?;
                let adapter: hell_memcordon::WindowsCandidateIdentityReceiptV1 =
                    serde_json::from_slice(&adapter).map_err(|error| {
                        format!("invalid Windows identity adapter receipt: {error}")
                    })?;
                adapter.validate().map_err(|error| error.to_string())?;
                if adapter.operation_id != entry.operation_id {
                    return Err(format!(
                        "Windows identity adapter receipt differs from operation {}",
                        entry.operation_id
                    ));
                }
            }
            PlatformId::LinuxX86_64 => {
                if entry.identity_adapter_path.is_some() || entry.identity_adapter_digest.is_some()
                {
                    require_bound_file(
                        root,
                        entry.identity_adapter_path.as_deref(),
                        entry.identity_adapter_digest.as_deref(),
                        "Linux identity adapter receipt",
                    )?;
                }
            }
            PlatformId::MacosAarch64 => unreachable!("rejected above"),
        }
        ids.push(entry.operation_id.clone());
    }
    sorted_unique(&ids)?;
    Ok(ids)
}

pub(crate) fn verify_finalized_evidence(
    output: &Path,
    expected_platform: PlatformId,
    candidate_commit: &str,
    workflow_commit: &str,
    required_operation_ids: &[String],
) -> Result<FinalizedEvidenceBinding, String> {
    let acquisition_bytes = read_regular(&output.join("acquisition.json"))?;
    let acquisition: AcquisitionReceiptV1 = serde_json::from_slice(&acquisition_bytes)
        .map_err(|error| format!("invalid MemCordon acquisition receipt: {error}"))?;
    if acquisition.schema_version != 1
        || acquisition.version != "0.5.2-rc.23"
        || acquisition.platform != expected_platform
    {
        return Err("MemCordon acquisition identity differs from the platform".to_owned());
    }
    let provider_bytes = read_regular(&output.join("provider-lease.json"))?;
    let provider: ProviderLifecycleReceiptV1 = serde_json::from_slice(&provider_bytes)
        .map_err(|error| format!("invalid MemCordon provider lease: {error}"))?;
    let cleanup_bytes = read_regular(&output.join("provider-cleanup.json"))?;
    let cleanup: ProviderCleanupReceiptV1 = serde_json::from_slice(&cleanup_bytes)
        .map_err(|error| format!("invalid MemCordon cleanup receipt: {error}"))?;
    cleanup.validate().map_err(|error| error.to_string())?;
    if provider.schema_version != 1
        || provider.state != ProviderLifecycleState::Qualified
        || provider.lease_owner != "job"
        || provider.admission_closed
        || provider.active_operations != 0
        || provider.failure.is_some()
        || provider.runtime_lock_digest != acquisition.runtime_lock_digest
        || cleanup.platform != expected_platform
        || cleanup.provider_lease_id != provider.provider_lease_id
        || cleanup.final_state != ProviderLifecycleState::Removed
        || !cleanup.installed_footprint_absent
        || cleanup.active_operations != 0
        || cleanup.failure.is_some()
    {
        return Err("MemCordon provider lifecycle is not cleanly finalized".to_owned());
    }
    let operations_bytes = read_regular(&output.join("operations.json"))?;
    let operations: Vec<OperationLedgerEntryV1> = serde_json::from_slice(&operations_bytes)
        .map_err(|error| format!("invalid MemCordon operation ledger: {error}"))?;
    if hell_memcordon::operation_ledger_json(&operations).map_err(|error| error.to_string())?
        != operations_bytes
    {
        return Err("MemCordon operation ledger is not canonical".to_owned());
    }
    let observed_operation_ids = validate_operations(output, &acquisition, &operations)?;
    let required_operation_ids = sorted_unique(required_operation_ids)?;
    if observed_operation_ids != required_operation_ids {
        return Err("MemCordon operation coverage differs from the platform report".to_owned());
    }
    let inventory_bytes = read_regular(&output.join("inventory.sha256"))?;
    let expected_inventory_bytes = encode_inventory(&inventory(output)?);
    if inventory_bytes != expected_inventory_bytes {
        return Err("MemCordon finalized inventory differs from exact evidence bytes".to_owned());
    }
    let finalization_bytes = read_regular(&output.join("finalization.json"))?;
    let finalization: FinalizationReceiptV1 = serde_json::from_slice(&finalization_bytes)
        .map_err(|error| format!("invalid MemCordon finalization receipt: {error}"))?;
    finalization.validate().map_err(|error| error.to_string())?;
    if !finalization.admitted
        || !finalization.cleanup_succeeded
        || finalization.failure.is_some()
        || finalization.platform != expected_platform
        || finalization.candidate_commit != candidate_commit
        || finalization.workflow_commit != workflow_commit
        || finalization.runtime_lock_digest != acquisition.runtime_lock_digest
        || finalization.acquisition_digest.as_deref()
            != Some(
                hell_testkit::sha256_bytes(&acquisition_bytes)
                    .hex()
                    .as_str(),
            )
        || finalization.provider_lifecycle_digest.as_deref()
            != Some(hell_testkit::sha256_bytes(&provider_bytes).hex().as_str())
        || finalization.provider_cleanup_digest.as_deref()
            != Some(hell_testkit::sha256_bytes(&cleanup_bytes).hex().as_str())
        || finalization.operations_digest.as_deref()
            != Some(hell_testkit::sha256_bytes(&operations_bytes).hex().as_str())
        || finalization.inventory_digest != hell_testkit::sha256_bytes(&inventory_bytes).hex()
        || sorted_unique(&finalization.required_operation_ids)? != required_operation_ids
        || sorted_unique(&finalization.observed_operation_ids)? != required_operation_ids
    {
        return Err("MemCordon finalization binding differs".to_owned());
    }
    Ok(FinalizedEvidenceBinding {
        finalization_sha256: hell_testkit::sha256_bytes(&finalization_bytes).hex(),
        inventory_sha256: hell_testkit::sha256_bytes(&inventory_bytes).hex(),
        runtime_lock_sha256: acquisition.runtime_lock_digest,
        operation_ids: required_operation_ids,
    })
}

fn validate_archived_platform_report(
    bytes: &[u8],
    expected_platform: PlatformId,
    candidate_commit: &str,
    workflow_commit: &str,
    binding: &FinalizedEvidenceBinding,
) -> Result<(), String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "archived platform report is not UTF-8".to_owned())?;
    let value = parse_json(text)?;
    if crate::json::canonical_json_bytes(&value)? != bytes {
        return Err("archived platform report is not canonical".to_owned());
    }
    let fields = value.object()?;
    require_exact_json_keys(
        fields,
        &[
            "archiveName",
            "archiveSha256",
            "assignedObligationCount",
            "buildInputsSha256",
            "candidateSha",
            "conformancePlanSha256",
            "conformanceStandard",
            "evidence",
            "evidenceManifestSha256",
            "externalInputsSha256",
            "exploratoryObservationCount",
            "gates",
            "imageOS",
            "imageVersion",
            "memcordon",
            "nativeEnvironmentSha256",
            "planSha256",
            "platform",
            "producedEvidenceRecordCount",
            "runAttempt",
            "runId",
            "schemaVersion",
            "state",
            "tag",
            "toolIdentities",
            "trustedConformanceInputsSha256",
            "unclassifiedMismatchCount",
            "version",
            "workflowSha",
        ],
    )?;
    let platform = match expected_platform {
        PlatformId::LinuxX86_64 => "linux-x86_64",
        PlatformId::WindowsX86_64 => "windows-x86_64",
        PlatformId::MacosAarch64 => return Err("MemCordon report cannot target macOS".to_owned()),
    };
    if json_member(fields, "schemaVersion")?.number()? != 3
        || json_member(fields, "state")?.string()? != "passed"
        || json_member(fields, "platform")?.string()? != platform
        || json_member(fields, "candidateSha")?.string()? != candidate_commit
        || json_member(fields, "workflowSha")?.string()? != workflow_commit
    {
        return Err("archived platform report binding differs".to_owned());
    }
    let memcordon = json_member(fields, "memcordon")?.object()?;
    require_exact_json_keys(
        memcordon,
        &[
            "evidencePath",
            "finalizationSha256",
            "inventorySha256",
            "operationIds",
            "runtimeLockSha256",
            "schemaVersion",
        ],
    )?;
    let operation_ids = json_member(memcordon, "operationIds")?
        .array()?
        .iter()
        .map(|value| value.string().map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    if json_member(memcordon, "schemaVersion")?.number()? != 1
        || json_member(memcordon, "evidencePath")?.string()? != "memcordon"
        || json_member(memcordon, "finalizationSha256")?.string()? != binding.finalization_sha256
        || json_member(memcordon, "inventorySha256")?.string()? != binding.inventory_sha256
        || json_member(memcordon, "runtimeLockSha256")?.string()? != binding.runtime_lock_sha256
        || operation_ids != binding.operation_ids
    {
        return Err("archived platform MemCordon binding differs".to_owned());
    }
    Ok(())
}

pub(crate) fn verify_archived_finalized_evidence(
    members: &BTreeMap<String, Vec<u8>>,
    prefix: &str,
    expected_platform: PlatformId,
    candidate_commit: &str,
    workflow_commit: &str,
    required_operation_ids: &[String],
) -> Result<FinalizedEvidenceBinding, String> {
    let read = |relative: &str| {
        members
            .get(&format!("{prefix}{relative}"))
            .cloned()
            .ok_or_else(|| format!("archived MemCordon evidence lacks {relative}"))
    };
    let acquisition_bytes = read("acquisition.json")?;
    let acquisition: AcquisitionReceiptV1 = serde_json::from_slice(&acquisition_bytes)
        .map_err(|error| format!("invalid archived MemCordon acquisition receipt: {error}"))?;
    if acquisition.schema_version != 1
        || acquisition.version != "0.5.2-rc.23"
        || acquisition.platform != expected_platform
    {
        return Err("archived MemCordon acquisition identity differs".to_owned());
    }
    let provider_bytes = read("provider-lease.json")?;
    let provider: ProviderLifecycleReceiptV1 = serde_json::from_slice(&provider_bytes)
        .map_err(|error| format!("invalid archived MemCordon provider lease: {error}"))?;
    let cleanup_bytes = read("provider-cleanup.json")?;
    let cleanup: ProviderCleanupReceiptV1 = serde_json::from_slice(&cleanup_bytes)
        .map_err(|error| format!("invalid archived MemCordon cleanup receipt: {error}"))?;
    cleanup.validate().map_err(|error| error.to_string())?;
    if provider.schema_version != 1
        || provider.state != ProviderLifecycleState::Qualified
        || provider.lease_owner != "job"
        || provider.admission_closed
        || provider.active_operations != 0
        || provider.failure.is_some()
        || provider.runtime_lock_digest != acquisition.runtime_lock_digest
        || cleanup.platform != expected_platform
        || cleanup.provider_lease_id != provider.provider_lease_id
        || cleanup.final_state != ProviderLifecycleState::Removed
        || !cleanup.installed_footprint_absent
        || cleanup.active_operations != 0
        || cleanup.failure.is_some()
    {
        return Err("archived MemCordon provider lifecycle is not cleanly finalized".to_owned());
    }
    let operations_bytes = read("operations.json")?;
    let operations: Vec<OperationLedgerEntryV1> = serde_json::from_slice(&operations_bytes)
        .map_err(|error| format!("invalid archived MemCordon operation ledger: {error}"))?;
    if hell_memcordon::operation_ledger_json(&operations).map_err(|error| error.to_string())?
        != operations_bytes
    {
        return Err("archived MemCordon operation ledger is not canonical".to_owned());
    }
    hell_memcordon::validate_operation_ledger(&operations).map_err(|error| error.to_string())?;
    let observed_operation_ids =
        validate_archived_operations(&read, &operations, &acquisition, expected_platform)?;
    let required_operation_ids = sorted_unique(required_operation_ids)?;
    if sorted_unique(&observed_operation_ids)? != required_operation_ids {
        return Err("archived MemCordon operation coverage differs".to_owned());
    }
    let result = validate_archived_finalization(
        &read,
        members,
        prefix,
        &ArchivedFinalizationInputs {
            expected_platform,
            candidate_commit,
            workflow_commit,
            required_operation_ids: &required_operation_ids,
            acquisition: &acquisition,
            acquisition_bytes: &acquisition_bytes,
            provider_bytes: &provider_bytes,
            cleanup_bytes: &cleanup_bytes,
            operations_bytes: &operations_bytes,
        },
    )?;
    validate_archived_platform_report(
        &read("platform-report.json")?,
        expected_platform,
        candidate_commit,
        workflow_commit,
        &result,
    )?;
    Ok(result)
}

struct ArchivedFinalizationInputs<'a> {
    expected_platform: PlatformId,
    candidate_commit: &'a str,
    workflow_commit: &'a str,
    required_operation_ids: &'a [String],
    acquisition: &'a AcquisitionReceiptV1,
    acquisition_bytes: &'a [u8],
    provider_bytes: &'a [u8],
    cleanup_bytes: &'a [u8],
    operations_bytes: &'a [u8],
}

fn validate_archived_finalization(
    read: &impl Fn(&str) -> Result<Vec<u8>, String>,
    members: &BTreeMap<String, Vec<u8>>,
    prefix: &str,
    inputs: &ArchivedFinalizationInputs<'_>,
) -> Result<FinalizedEvidenceBinding, String> {
    let inventory_bytes = read("inventory.sha256")?;
    let inventory = parse_inventory_bytes(&inventory_bytes)?;
    for (path, digest) in &inventory {
        if hell_testkit::sha256_bytes(&read(path)?).hex() != *digest {
            return Err(format!("archived MemCordon inventory differs for {path}"));
        }
    }
    let expected_paths = inventory
        .keys()
        .map(|path| format!("{prefix}{path}"))
        .chain([
            format!("{prefix}finalization.json"),
            format!("{prefix}inventory.sha256"),
            format!("{prefix}platform-report.json"),
        ])
        .collect::<BTreeSet<_>>();
    let observed_paths = members
        .keys()
        .filter(|path| path.starts_with(prefix))
        .cloned()
        .collect::<BTreeSet<_>>();
    if observed_paths != expected_paths {
        return Err("archived MemCordon evidence exact set differs".to_owned());
    }
    let finalization_bytes = read("finalization.json")?;
    let finalization: FinalizationReceiptV1 = serde_json::from_slice(&finalization_bytes)
        .map_err(|error| format!("invalid archived MemCordon finalization: {error}"))?;
    finalization.validate().map_err(|error| error.to_string())?;
    if !finalization.admitted
        || !finalization.cleanup_succeeded
        || finalization.failure.is_some()
        || finalization.platform != inputs.expected_platform
        || finalization.candidate_commit != inputs.candidate_commit
        || finalization.workflow_commit != inputs.workflow_commit
        || finalization.runtime_lock_digest != inputs.acquisition.runtime_lock_digest
        || finalization.acquisition_digest
            != Some(hell_testkit::sha256_bytes(inputs.acquisition_bytes).hex())
        || finalization.provider_lifecycle_digest
            != Some(hell_testkit::sha256_bytes(inputs.provider_bytes).hex())
        || finalization.provider_cleanup_digest
            != Some(hell_testkit::sha256_bytes(inputs.cleanup_bytes).hex())
        || finalization.operations_digest
            != Some(hell_testkit::sha256_bytes(inputs.operations_bytes).hex())
        || finalization.inventory_digest != hell_testkit::sha256_bytes(&inventory_bytes).hex()
        || sorted_unique(&finalization.required_operation_ids)? != inputs.required_operation_ids
        || sorted_unique(&finalization.observed_operation_ids)? != inputs.required_operation_ids
    {
        return Err("archived MemCordon finalization binding differs".to_owned());
    }
    Ok(FinalizedEvidenceBinding {
        finalization_sha256: hell_testkit::sha256_bytes(&finalization_bytes).hex(),
        inventory_sha256: hell_testkit::sha256_bytes(&inventory_bytes).hex(),
        runtime_lock_sha256: inputs.acquisition.runtime_lock_digest.clone(),
        operation_ids: inputs.required_operation_ids.to_vec(),
    })
}

fn validate_archived_operations(
    read: &impl Fn(&str) -> Result<Vec<u8>, String>,
    operations: &[OperationLedgerEntryV1],
    acquisition: &AcquisitionReceiptV1,
    expected_platform: PlatformId,
) -> Result<Vec<String>, String> {
    let expected_boundary = match expected_platform {
        PlatformId::LinuxX86_64 => CandidateBoundaryPolicy::SealedLinux,
        PlatformId::WindowsX86_64 => CandidateBoundaryPolicy::SealedWindows,
        PlatformId::MacosAarch64 => {
            return Err("archived MemCordon evidence cannot target macOS".to_owned());
        }
    };
    for entry in operations {
        if entry.boundary != expected_boundary
            || !matches!(entry.terminal, SealedTerminal::OrdinaryResult)
        {
            return Err(format!(
                "archived MemCordon operation {} is not an ordinary sealed result",
                entry.operation_id
            ));
        }
        let raw = read(
            entry
                .raw_report_path
                .as_deref()
                .ok_or_else(|| "archived operation lacks raw report path".to_owned())?,
        )?;
        let normalized = read(
            entry
                .normalized_report_path
                .as_deref()
                .ok_or_else(|| "archived operation lacks normalized report path".to_owned())?,
        )?;
        if entry.raw_report_digest.as_deref()
            != Some(hell_testkit::sha256_bytes(&raw).hex().as_str())
            || entry.normalized_report_digest.as_deref()
                != Some(hell_testkit::sha256_bytes(&normalized).hex().as_str())
        {
            return Err("archived MemCordon operation digest differs".to_owned());
        }
        validate_archived_projection(entry, acquisition, &raw, &normalized)?;
        validate_archived_adapter(read, entry, expected_platform)?;
    }
    Ok(operations
        .iter()
        .map(|entry| entry.operation_id.clone())
        .collect())
}

fn validate_archived_projection(
    entry: &OperationLedgerEntryV1,
    acquisition: &AcquisitionReceiptV1,
    raw: &[u8],
    normalized: &[u8],
) -> Result<(), String> {
    let projection =
        hell_memcordon::parse_schema8_projection(normalized).map_err(|error| error.to_string())?;
    let reprojected = hell_memcordon::project_schema8_report(
        raw,
        &acquisition.mechanism,
        &projection.target_argv,
    )
    .map_err(|error| error.to_string())?;
    if reprojected != projection {
        return Err("archived MemCordon raw/projection evidence differs".to_owned());
    }
    let request = serde_json::to_vec(&projection.target_argv)
        .map_err(|error| format!("cannot encode archived request binding: {error}"))?;
    if hell_testkit::sha256_bytes(&request).hex() != entry.request_digest {
        return Err("archived MemCordon request binding differs".to_owned());
    }
    Ok(())
}

fn validate_archived_adapter(
    read: &impl Fn(&str) -> Result<Vec<u8>, String>,
    entry: &OperationLedgerEntryV1,
    expected_platform: PlatformId,
) -> Result<(), String> {
    match expected_platform {
        PlatformId::WindowsX86_64 => {
            let adapter = read(entry.identity_adapter_path.as_deref().ok_or_else(|| {
                "archived Windows operation lacks identity adapter path".to_owned()
            })?)?;
            if entry.identity_adapter_digest.as_deref()
                != Some(hell_testkit::sha256_bytes(&adapter).hex().as_str())
            {
                return Err("archived Windows identity adapter digest differs".to_owned());
            }
            let adapter: hell_memcordon::WindowsCandidateIdentityReceiptV1 =
                serde_json::from_slice(&adapter).map_err(|error| {
                    format!("invalid archived Windows identity adapter receipt: {error}")
                })?;
            adapter.validate().map_err(|error| error.to_string())?;
            if adapter.operation_id != entry.operation_id {
                return Err("archived Windows identity operation differs".to_owned());
            }
        }
        PlatformId::LinuxX86_64 => {
            if entry.identity_adapter_path.is_some() || entry.identity_adapter_digest.is_some() {
                return Err("archived Linux operation claims an identity adapter".to_owned());
            }
        }
        PlatformId::MacosAarch64 => unreachable!("rejected above"),
    }
    Ok(())
}

fn parse_inventory_bytes(bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
    if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 || !bytes.ends_with(b"\n") {
        return Err("MemCordon inventory framing is invalid".to_owned());
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| "MemCordon inventory is not UTF-8".to_owned())?;
    let mut inventory = BTreeMap::new();
    let mut previous: Option<&str> = None;
    for line in text.lines() {
        let (digest, path) = line
            .split_once("  ")
            .ok_or_else(|| "MemCordon inventory line lacks its exact separator".to_owned())?;
        hell_testkit::Digest::from_hex(digest)
            .map_err(|error| format!("invalid MemCordon inventory digest: {error}"))?;
        let path_value = Path::new(path);
        if path_value.as_os_str().is_empty()
            || path_value.is_absolute()
            || path_value
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            || matches!(path, "finalization.json" | "inventory.sha256")
            || previous.is_some_and(|prior| prior >= path)
        {
            return Err("MemCordon inventory path is unsafe, duplicate, or unsorted".to_owned());
        }
        previous = Some(path);
        inventory.insert(path.to_owned(), digest.to_owned());
    }
    for required in [
        "acquisition.json",
        "canaries.json",
        "doctor.json",
        "operations.json",
        "package-inspect.json",
        "package-verify.json",
        "provider-cleanup.json",
        "provider-lease.json",
    ] {
        if !inventory.contains_key(required) {
            return Err(format!("MemCordon inventory lacks {required}"));
        }
    }
    Ok(inventory)
}

fn encode_inventory(inventory: &[(String, String)]) -> Vec<u8> {
    inventory
        .iter()
        .fold(String::new(), |mut encoded, (path, digest)| {
            writeln!(encoded, "{digest}  {path}").expect("writing to a String cannot fail");
            encoded
        })
        .into_bytes()
}

fn require_bound_file(
    root: &Path,
    relative: Option<&str>,
    expected_digest: Option<&str>,
    label: &str,
) -> Result<Vec<u8>, String> {
    let relative = relative.ok_or_else(|| format!("MemCordon {label} path is missing"))?;
    let expected_digest =
        expected_digest.ok_or_else(|| format!("MemCordon {label} digest is missing"))?;
    hell_testkit::Digest::from_hex(expected_digest)
        .map_err(|error| format!("MemCordon {label} digest is invalid: {error}"))?;
    let path = Path::new(relative);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("MemCordon {label} path is not normalized"));
    }
    let bytes = read_regular(&root.join(path))?;
    if hell_testkit::sha256_bytes(&bytes).hex() != expected_digest {
        return Err(format!("MemCordon {label} digest differs"));
    }
    Ok(bytes)
}

fn sorted_unique(values: &[String]) -> Result<Vec<String>, String> {
    let mut sorted = values.to_vec();
    sorted.sort();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("MemCordon operation ledger contains duplicate IDs".to_owned());
    }
    Ok(sorted)
}

fn read_regular(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(format!("{} changed while being read", path.display()));
    }
    Ok(bytes)
}

fn file_digest(path: &Path) -> Result<String, String> {
    hell_testkit::sha256_file(path)
        .map(hell_digest::Digest::hex)
        .map_err(|error| format!("cannot hash {}: {error}", path.display()))
}

fn write_serde(path: &Path, value: &impl serde::Serialize) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("cannot serialize MemCordon finalization: {error}"))?;
    let text = std::str::from_utf8(&bytes).expect("JSON serializer emits UTF-8");
    write_json_new(path, &parse_json(text)?)
}

pub(crate) fn finalize_platform_report(
    output: &Path,
    finalization: &FinalizationReceiptV1,
    finalization_bytes: &[u8],
    inventory_bytes: &[u8],
) -> Result<(), String> {
    finalization.validate().map_err(|error| error.to_string())?;
    if !finalization.admitted || !finalization.cleanup_succeeded || finalization.failure.is_some() {
        return Err(
            "platform success cannot be finalized before clean provider retirement".to_owned(),
        );
    }
    let encoded: FinalizationReceiptV1 = serde_json::from_slice(finalization_bytes)
        .map_err(|error| format!("invalid persisted MemCordon finalization bytes: {error}"))?;
    if &encoded != finalization
        || finalization.inventory_digest != hell_testkit::sha256_bytes(inventory_bytes).hex()
    {
        return Err(
            "persisted MemCordon finalization bytes or inventory binding differs".to_owned(),
        );
    }
    let platform_root = output
        .parent()
        .ok_or_else(|| "MemCordon output root has no platform-report parent".to_owned())?;
    let provisional_path = platform_root.join("platform-report.provisional.json");
    let provisional = read_json(&provisional_path)?;
    let mut fields = provisional.object()?.clone();
    validate_provisional_platform_report(&fields, finalization)?;
    let operation_ids = finalization
        .required_operation_ids
        .iter()
        .cloned()
        .map(JsonValue::String)
        .collect();
    fields.insert(
        "memcordon".to_owned(),
        JsonValue::Object(BTreeMap::from([
            (
                "evidencePath".to_owned(),
                JsonValue::String("memcordon".to_owned()),
            ),
            (
                "finalizationSha256".to_owned(),
                JsonValue::String(hell_testkit::sha256_bytes(finalization_bytes).hex()),
            ),
            (
                "inventorySha256".to_owned(),
                JsonValue::String(hell_testkit::sha256_bytes(inventory_bytes).hex()),
            ),
            ("operationIds".to_owned(), JsonValue::Array(operation_ids)),
            (
                "runtimeLockSha256".to_owned(),
                JsonValue::String(finalization.runtime_lock_digest.clone()),
            ),
            ("schemaVersion".to_owned(), JsonValue::Number(1)),
        ])),
    );
    validate_final_platform_report_keys(&fields)?;
    write_json_new(
        &platform_root.join("platform-report.json"),
        &JsonValue::Object(fields),
    )?;
    fs::remove_file(&provisional_path).map_err(|error| {
        format!(
            "cannot retire provisional platform report {}: {error}",
            provisional_path.display()
        )
    })
}

fn validate_provisional_platform_report(
    fields: &BTreeMap<String, JsonValue>,
    finalization: &FinalizationReceiptV1,
) -> Result<(), String> {
    if json_member(fields, "schemaVersion")?.number()? != 3
        || json_member(fields, "state")?.string()? != "passed"
        || !matches!(json_member(fields, "memcordon")?, JsonValue::Null)
        || json_member(fields, "candidateSha")?.string()? != finalization.candidate_commit
        || json_member(fields, "workflowSha")?.string()? != finalization.workflow_commit
    {
        return Err(
            "provisional platform report is not bound to MemCordon finalization".to_owned(),
        );
    }
    Ok(())
}

fn validate_final_platform_report_keys(fields: &BTreeMap<String, JsonValue>) -> Result<(), String> {
    require_exact_json_keys(
        fields,
        &[
            "archiveName",
            "archiveSha256",
            "assignedObligationCount",
            "buildInputsSha256",
            "candidateSha",
            "conformancePlanSha256",
            "conformanceStandard",
            "evidence",
            "evidenceManifestSha256",
            "externalInputsSha256",
            "exploratoryObservationCount",
            "gates",
            "imageOS",
            "imageVersion",
            "memcordon",
            "nativeEnvironmentSha256",
            "planSha256",
            "platform",
            "producedEvidenceRecordCount",
            "runAttempt",
            "runId",
            "schemaVersion",
            "state",
            "tag",
            "toolIdentities",
            "trustedConformanceInputsSha256",
            "unclassifiedMismatchCount",
            "version",
            "workflowSha",
        ],
    )
}

fn read_json(path: &Path) -> Result<JsonValue, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| format!("{} is not UTF-8", path.display()))?;
    parse_json(text)
}

fn inventory(root: &Path) -> Result<Vec<(String, String)>, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    let mut identities = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory)
            .map_err(|error| format!("cannot enumerate {}: {error}", directory.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("cannot enumerate evidence: {error}"))?;
            let kind = entry
                .file_type()
                .map_err(|error| format!("cannot inspect evidence: {error}"))?;
            if kind.is_symlink() {
                return Err("MemCordon evidence inventory contains a symbolic link".to_owned());
            }
            if kind.is_dir() {
                pending.push(entry.path());
                continue;
            }
            if !kind.is_file()
                || matches!(
                    entry.file_name().to_str(),
                    Some("finalization.json" | "inventory.sha256")
                )
            {
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(|_| "MemCordon evidence escaped its root".to_owned())?
                .to_path_buf();
            if relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
            {
                return Err("MemCordon evidence path is not normalized".to_owned());
            }
            let display = relative
                .components()
                .map(|component| component.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            let identity = if cfg!(windows) {
                display.to_ascii_lowercase()
            } else {
                display.clone()
            };
            if !identities.insert(identity) {
                return Err("MemCordon evidence has a duplicate normalized path".to_owned());
            }
            let digest = hell_testkit::sha256_file(&entry.path())
                .map_err(|error| format!("cannot hash {}: {error}", entry.path().display()))?
                .hex();
            files.push((display, digest));
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(files)
}
