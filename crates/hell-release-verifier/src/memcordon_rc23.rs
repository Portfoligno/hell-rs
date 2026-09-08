use std::collections::BTreeMap;

use crate::json::{self, Value};

const MAX_REPORT_BYTES: usize = 8 * 1024 * 1024;
const TOOL_VERSION: &str = "0.5.2-rc.23";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemcordonPlatform {
    LinuxX86_64,
    WindowsX86_64,
}

impl MemcordonPlatform {
    const fn mechanism(self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "linux-pid-namespace-cgroup-v2",
            Self::WindowsX86_64 => "windows-job-object-v2",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedNativeArgument {
    pub display: String,
    pub raw_encoding: Option<String>,
    pub raw_data: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedTermination {
    ExitCode(u32),
    UnixSignal(u32),
    WindowsStatus(u32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedMemcordonReport {
    pub platform: MemcordonPlatform,
    pub argv: Vec<ExpectedNativeArgument>,
    pub deadline_token: String,
    pub termination: ExpectedTermination,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedMemcordonReport {
    pub mechanism: &'static str,
    pub wrapper_exit_code: u32,
    pub raw_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedMemcordonFinalization {
    pub platform: MemcordonPlatform,
    pub candidate_commit: String,
    pub workflow_commit: String,
    pub runtime_lock_digest: String,
    pub provider_operation: String,
    pub required_operation_ids: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct MemcordonFinalizationDocuments<'a> {
    pub finalization: &'a [u8],
    pub provider_cleanup: &'a [u8],
    pub operations: &'a [u8],
    pub inventory: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedMemcordonFinalization {
    pub platform: MemcordonPlatform,
    pub operation_count: usize,
    pub inventory_sha256: String,
}

#[allow(clippy::too_many_lines)]
pub(crate) fn validate_archived_memcordon_platform(
    files: &BTreeMap<String, Vec<u8>>,
    platform: MemcordonPlatform,
    candidate_commit: &str,
    workflow_commit: &str,
    provider_operation: &str,
) -> Result<(), String> {
    let prefix = format!("memcordon/{}/", platform_id(platform));
    let document = |name: &str| {
        files
            .get(&format!("{prefix}{name}"))
            .map(Vec::as_slice)
            .ok_or_else(|| format!("independent MemCordon evidence lacks {name}"))
    };
    let platform_report = json::parse(document("platform-report.json")?)?;
    let report = object(&platform_report, "final platform report")?;
    exact(
        report,
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
        "final platform report",
    )?;
    require_number(report, "schemaVersion", 3, "final platform report")?;
    require_text(report, "state", "passed", "final platform report")?;
    require_text(
        report,
        "platform",
        platform_id(platform),
        "final platform report",
    )?;
    require_text(
        report,
        "candidateSha",
        candidate_commit,
        "final platform report",
    )?;
    require_text(
        report,
        "workflowSha",
        workflow_commit,
        "final platform report",
    )?;
    let binding = object(
        member(report, "memcordon", "final platform report")?,
        "platform MemCordon binding",
    )?;
    exact(
        binding,
        &[
            "evidencePath",
            "finalizationSha256",
            "inventorySha256",
            "operationIds",
            "runtimeLockSha256",
            "schemaVersion",
        ],
        "platform MemCordon binding",
    )?;
    require_number(binding, "schemaVersion", 1, "platform MemCordon binding")?;
    require_text(
        binding,
        "evidencePath",
        "memcordon",
        "platform MemCordon binding",
    )?;
    let operation_ids = operation_ids(
        member(binding, "operationIds", "platform MemCordon binding")?,
        "platform MemCordon operations",
    )?;
    if operation_ids != [provider_operation.to_owned()] {
        return Err("platform MemCordon operation binding differs".to_owned());
    }
    let runtime_lock_digest =
        member(binding, "runtimeLockSha256", "platform MemCordon binding")?.string()?;
    require_digest(runtime_lock_digest)?;
    let finalization = document("finalization.json")?;
    let cleanup = document("provider-cleanup.json")?;
    let operations = document("operations.json")?;
    let inventory_bytes = document("inventory.sha256")?;
    validate_memcordon_rc23_finalization(
        MemcordonFinalizationDocuments {
            finalization,
            provider_cleanup: cleanup,
            operations,
            inventory: inventory_bytes,
        },
        &ExpectedMemcordonFinalization {
            platform,
            candidate_commit: candidate_commit.to_owned(),
            workflow_commit: workflow_commit.to_owned(),
            runtime_lock_digest: runtime_lock_digest.to_owned(),
            provider_operation: provider_operation.to_owned(),
            required_operation_ids: operation_ids.clone(),
        },
    )?;
    if member(binding, "finalizationSha256", "platform MemCordon binding")?.string()?
        != crate::digest::sha256_hex(finalization)
        || member(binding, "inventorySha256", "platform MemCordon binding")?.string()?
            != crate::digest::sha256_hex(inventory_bytes)
    {
        return Err("platform MemCordon finalization digest binding differs".to_owned());
    }
    let inventory = validate_inventory(inventory_bytes)?;
    let expected_files = inventory
        .keys()
        .map(|path| format!("{prefix}{path}"))
        .chain([
            format!("{prefix}finalization.json"),
            format!("{prefix}inventory.sha256"),
            format!("{prefix}platform-report.json"),
        ])
        .collect::<std::collections::BTreeSet<_>>();
    let observed_files = files
        .keys()
        .filter(|path| path.starts_with(&prefix))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if observed_files != expected_files {
        return Err("independent MemCordon archived evidence exact set differs".to_owned());
    }
    for (path, digest) in &inventory {
        let bytes = document(path)?;
        if crate::digest::sha256_hex(bytes) != *digest {
            return Err(format!(
                "archived MemCordon evidence digest differs for {path}"
            ));
        }
    }
    validate_archived_operation_reports(operations, files, &prefix, platform)
}

fn validate_archived_operation_reports(
    operations: &[u8],
    files: &BTreeMap<String, Vec<u8>>,
    prefix: &str,
    platform: MemcordonPlatform,
) -> Result<(), String> {
    let ledger = json::parse(operations)?;
    for entry in ledger.array()? {
        let fields = object(entry, "operation ledger entry")?;
        let raw_path = member(fields, "raw_report_path", "operation ledger entry")?.string()?;
        let normalized_path =
            member(fields, "normalized_report_path", "operation ledger entry")?.string()?;
        let raw = files
            .get(&format!("{prefix}{raw_path}"))
            .map(Vec::as_slice)
            .ok_or_else(|| format!("independent MemCordon evidence lacks {raw_path}"))?;
        let normalized = files
            .get(&format!("{prefix}{normalized_path}"))
            .map(Vec::as_slice)
            .ok_or_else(|| format!("independent MemCordon evidence lacks {normalized_path}"))?;
        let expected = expected_report_from_documents(raw, normalized, platform)?;
        validate_memcordon_rc23_projection(raw, normalized, &expected)?;
    }
    Ok(())
}

fn expected_report_from_documents(
    raw: &[u8],
    normalized: &[u8],
    platform: MemcordonPlatform,
) -> Result<ExpectedMemcordonReport, String> {
    let raw = json::parse(raw)?;
    let raw = object(&raw, "MemCordon report")?;
    let invocation = object(member(raw, "invocation", "MemCordon report")?, "invocation")?;
    let deadline_token = member(invocation, "deadline_token", "invocation")?
        .string()?
        .to_owned();
    let normalized = json::parse(normalized)?;
    let normalized = object(&normalized, "MemCordon projection")?;
    let argv = member(normalized, "target_argv", "MemCordon projection")?
        .array()?
        .iter()
        .map(|argument| {
            let argument = object(argument, "native argument")?;
            let display = member(argument, "display", "native argument")?
                .string()?
                .to_owned();
            let (raw_encoding, raw_data) = match member(argument, "raw", "native argument")? {
                Value::Null => (None, None),
                Value::Object(raw) => (
                    Some(
                        member(raw, "encoding", "native argument raw")?
                            .string()?
                            .to_owned(),
                    ),
                    Some(
                        member(raw, "data", "native argument raw")?
                            .string()?
                            .to_owned(),
                    ),
                ),
                _ => return Err("native argument raw form is invalid".to_owned()),
            };
            Ok(ExpectedNativeArgument {
                display,
                raw_encoding,
                raw_data,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let terminal = object(
        member(normalized, "terminal", "MemCordon projection")?,
        "MemCordon terminal",
    )?;
    let termination = match member(terminal, "kind", "MemCordon terminal")?.string()? {
        "candidate_exit" => {
            let status =
                u32::try_from(member(terminal, "native_status", "MemCordon terminal")?.number()?)
                    .map_err(|_| "candidate native status exceeds u32".to_owned())?;
            match platform {
                MemcordonPlatform::LinuxX86_64 => ExpectedTermination::ExitCode(status),
                MemcordonPlatform::WindowsX86_64 => ExpectedTermination::WindowsStatus(status),
            }
        }
        "candidate_signal" if platform == MemcordonPlatform::LinuxX86_64 => {
            ExpectedTermination::UnixSignal(
                u32::try_from(member(terminal, "signal", "MemCordon terminal")?.number()?)
                    .map_err(|_| "candidate signal exceeds u32".to_owned())?,
            )
        }
        _ => return Err("archived MemCordon terminal is not an ordinary result".to_owned()),
    };
    Ok(ExpectedMemcordonReport {
        platform,
        argv,
        deadline_token,
        termination,
    })
}

/// Independently validates one successful, single-attempt `MemCordon` rc.23
/// sealed execution report and its exact invocation binding.
///
/// This implementation intentionally has no dependency on `memcordon-core` or
/// the primary `hell-memcordon` parser. It admits ordinary non-zero candidate
/// exits, but rejects setup, deadline, monitor, restart, and cleanup failures.
///
/// # Errors
///
/// Returns an error when the report is oversized, malformed, has unknown wire
/// fields, differs from the expected native invocation, or lacks any required
/// sealed-launch and retirement fact.
pub fn validate_memcordon_rc23_report(
    bytes: &[u8],
    expected: &ExpectedMemcordonReport,
) -> Result<ValidatedMemcordonReport, String> {
    if bytes.len() > MAX_REPORT_BYTES {
        return Err("MemCordon execution report exceeds the 8 MiB limit".to_owned());
    }
    let value = json::parse(bytes)?;
    let report = object(&value, "MemCordon report")?;
    exact(
        report,
        &[
            "attempts",
            "backend",
            "error",
            "invocation",
            "policy",
            "schema_version",
            "supervision",
            "tool",
        ],
        "MemCordon report",
    )?;
    require_number(report, "schema_version", 8, "MemCordon report")?;
    require_null(
        member(report, "error", "MemCordon report")?,
        "MemCordon report error",
    )?;
    validate_tool(member(report, "tool", "MemCordon report")?)?;
    validate_invocation(member(report, "invocation", "MemCordon report")?, expected)?;
    validate_policy(member(report, "policy", "MemCordon report")?, expected)?;
    validate_backend(
        member(report, "backend", "MemCordon report")?,
        expected.platform,
    )?;

    let attempts = member(report, "attempts", "MemCordon report")?.array()?;
    if attempts.len() != 1 {
        return Err("MemCordon report must contain exactly one retained attempt".to_owned());
    }
    let attempt_outcome = validate_attempt(&attempts[0], expected)?;
    let wrapper_exit_code = expected_wrapper_status(expected.termination)?;
    validate_supervision(
        member(report, "supervision", "MemCordon report")?,
        &attempt_outcome,
        wrapper_exit_code,
    )?;

    Ok(ValidatedMemcordonReport {
        mechanism: expected.platform.mechanism(),
        wrapper_exit_code,
        raw_sha256: crate::digest::sha256_hex(bytes),
    })
}

/// Independently requires a frozen `Schema8ProjectionV1` to equal the raw
/// rc.23 report and the trusted invocation binding.
///
/// # Errors
///
/// Returns an error when either document is invalid or when any projected
/// authority/status/native predicate differs from the raw report.
#[allow(clippy::too_many_lines)]
pub fn validate_memcordon_rc23_projection(
    raw_report: &[u8],
    projection: &[u8],
    expected: &ExpectedMemcordonReport,
) -> Result<ValidatedMemcordonReport, String> {
    let validated = validate_memcordon_rc23_report(raw_report, expected)?;
    if projection.len() > 1024 * 1024 {
        return Err("MemCordon normalized projection exceeds the 1 MiB limit".to_owned());
    }
    let value = json::parse(projection)?;
    let fields = object(&value, "MemCordon normalized projection")?;
    exact(
        fields,
        &[
            "attempt_count",
            "effective_boundary",
            "mechanism",
            "native_predicates",
            "requested_boundary",
            "restart_count",
            "schema_version",
            "sealed_boundary_retired",
            "target_argv",
            "target_status",
            "terminal",
            "tool_version",
            "wrapper_status",
        ],
        "MemCordon normalized projection",
    )?;
    require_number(
        fields,
        "schema_version",
        8,
        "MemCordon normalized projection",
    )?;
    require_text(
        fields,
        "tool_version",
        TOOL_VERSION,
        "MemCordon normalized projection",
    )?;
    require_text(
        fields,
        "requested_boundary",
        "sealed",
        "MemCordon normalized projection",
    )?;
    require_text(
        fields,
        "effective_boundary",
        "sealed",
        "MemCordon normalized projection",
    )?;
    require_text(
        fields,
        "mechanism",
        expected.platform.mechanism(),
        "MemCordon normalized projection",
    )?;
    require_number(
        fields,
        "attempt_count",
        1,
        "MemCordon normalized projection",
    )?;
    require_number(
        fields,
        "restart_count",
        0,
        "MemCordon normalized projection",
    )?;
    require_true(
        fields,
        "sealed_boundary_retired",
        "MemCordon normalized projection",
    )?;
    require_number(
        fields,
        "wrapper_status",
        u64::from(validated.wrapper_exit_code),
        "MemCordon normalized projection",
    )?;
    let target_status = match expected.termination {
        ExpectedTermination::ExitCode(value) | ExpectedTermination::WindowsStatus(value) => {
            Some(u64::from(value))
        }
        ExpectedTermination::UnixSignal(_) => None,
    };
    if optional_number(member(
        fields,
        "target_status",
        "MemCordon normalized projection",
    )?)? != target_status
    {
        return Err("normalized target status differs from the raw report".to_owned());
    }
    validate_projected_terminal(
        member(fields, "terminal", "MemCordon normalized projection")?,
        expected.termination,
    )?;
    validate_projected_arguments(
        member(fields, "target_argv", "MemCordon normalized projection")?,
        &expected.argv,
    )?;
    validate_projected_predicates(
        member(
            fields,
            "native_predicates",
            "MemCordon normalized projection",
        )?,
        expected.platform,
    )?;
    Ok(validated)
}

fn validate_projected_terminal(value: &Value, expected: ExpectedTermination) -> Result<(), String> {
    let fields = object(value, "normalized terminal provenance")?;
    match expected {
        ExpectedTermination::ExitCode(native_status)
        | ExpectedTermination::WindowsStatus(native_status) => {
            exact(
                fields,
                &["kind", "native_status"],
                "normalized terminal provenance",
            )?;
            require_text(
                fields,
                "kind",
                "candidate_exit",
                "normalized terminal provenance",
            )?;
            require_number(
                fields,
                "native_status",
                u64::from(native_status),
                "normalized terminal provenance",
            )
        }
        ExpectedTermination::UnixSignal(signal) => {
            if signal == 0 {
                return Err("normalized candidate signal must be nonzero".to_owned());
            }
            exact(
                fields,
                &["kind", "signal"],
                "normalized terminal provenance",
            )?;
            require_text(
                fields,
                "kind",
                "candidate_signal",
                "normalized terminal provenance",
            )?;
            require_number(
                fields,
                "signal",
                u64::from(signal),
                "normalized terminal provenance",
            )
        }
    }
}

/// Independently validates cleanup-aware platform finalization and exact
/// candidate-root coverage using the frozen `snake_case` receipt contract.
///
/// # Errors
///
/// Returns an error when cleanup is incomplete, a digest binding differs, a
/// ledger path is unsafe, or required and observed operation sets differ.
#[allow(clippy::too_many_lines)]
pub fn validate_memcordon_rc23_finalization(
    documents: MemcordonFinalizationDocuments<'_>,
    expected: &ExpectedMemcordonFinalization,
) -> Result<ValidatedMemcordonFinalization, String> {
    require_sha(&expected.candidate_commit, "candidate commit")?;
    require_sha(&expected.workflow_commit, "workflow commit")?;
    require_digest(&expected.runtime_lock_digest)?;
    let required = validate_operation_ids(
        &expected.required_operation_ids,
        "trusted required operations",
    )?;
    if required.is_empty() {
        return Err("trusted required MemCordon operation set is empty".to_owned());
    }
    let inventory = validate_inventory(documents.inventory)?;
    validate_provider_cleanup(documents.provider_cleanup, expected)?;
    validate_operations(documents.operations, expected, &required, &inventory)?;

    let value = json::parse(documents.finalization)?;
    let fields = object(&value, "MemCordon finalization")?;
    exact(
        fields,
        &[
            "acquisition_digest",
            "admitted",
            "candidate_commit",
            "cleanup_succeeded",
            "failure",
            "inventory_digest",
            "observed_operation_ids",
            "operations_digest",
            "platform",
            "provider_cleanup_digest",
            "provider_lifecycle_digest",
            "required_operation_ids",
            "runtime_lock_digest",
            "schema_version",
            "workflow_commit",
        ],
        "MemCordon finalization",
    )?;
    require_number(fields, "schema_version", 1, "MemCordon finalization")?;
    require_text(
        fields,
        "platform",
        platform_id(expected.platform),
        "MemCordon finalization",
    )?;
    require_text(
        fields,
        "candidate_commit",
        &expected.candidate_commit,
        "MemCordon finalization",
    )?;
    require_text(
        fields,
        "workflow_commit",
        &expected.workflow_commit,
        "MemCordon finalization",
    )?;
    require_text(
        fields,
        "runtime_lock_digest",
        &expected.runtime_lock_digest,
        "MemCordon finalization",
    )?;
    require_true(fields, "cleanup_succeeded", "MemCordon finalization")?;
    require_true(fields, "admitted", "MemCordon finalization")?;
    require_null(
        member(fields, "failure", "MemCordon finalization")?,
        "finalization failure",
    )?;
    for key in ["acquisition_digest", "provider_lifecycle_digest"] {
        require_digest(member(fields, key, "MemCordon finalization")?.string()?)?;
    }
    require_bound_digest(
        fields,
        "provider_cleanup_digest",
        documents.provider_cleanup,
    )?;
    require_bound_digest(fields, "operations_digest", documents.operations)?;
    require_bound_digest(fields, "inventory_digest", documents.inventory)?;
    require_inventory_digest(
        &inventory,
        "acquisition.json",
        member(fields, "acquisition_digest", "MemCordon finalization")?.string()?,
    )?;
    require_inventory_digest(
        &inventory,
        "provider-lease.json",
        member(
            fields,
            "provider_lifecycle_digest",
            "MemCordon finalization",
        )?
        .string()?,
    )?;
    require_inventory_digest(
        &inventory,
        "provider-cleanup.json",
        member(fields, "provider_cleanup_digest", "MemCordon finalization")?.string()?,
    )?;
    require_inventory_digest(
        &inventory,
        "operations.json",
        member(fields, "operations_digest", "MemCordon finalization")?.string()?,
    )?;
    let finalized_required = operation_ids(
        member(fields, "required_operation_ids", "MemCordon finalization")?,
        "finalization required operations",
    )?;
    let finalized_observed = operation_ids(
        member(fields, "observed_operation_ids", "MemCordon finalization")?,
        "finalization observed operations",
    )?;
    if finalized_required != required || finalized_observed != required {
        return Err("finalization operation coverage differs from the trusted plan".to_owned());
    }
    Ok(ValidatedMemcordonFinalization {
        platform: expected.platform,
        operation_count: required.len(),
        inventory_sha256: crate::digest::sha256_hex(documents.inventory),
    })
}

fn validate_projected_arguments(
    value: &Value,
    expected: &[ExpectedNativeArgument],
) -> Result<(), String> {
    let arguments = value.array()?;
    if arguments.len() != expected.len() {
        return Err("normalized native argv length differs from the raw report".to_owned());
    }
    for (index, (argument, expected)) in arguments.iter().zip(expected).enumerate() {
        let fields = object(argument, "normalized native argument")?;
        exact(fields, &["display", "raw"], "normalized native argument")?;
        require_text(
            fields,
            "display",
            &expected.display,
            "normalized native argument",
        )?;
        let raw = member(fields, "raw", "normalized native argument")?;
        let agrees = match (&expected.raw_encoding, &expected.raw_data, raw) {
            (None, None, Value::Null) => true,
            (Some(encoding), Some(data), Value::Object(raw)) => {
                exact(raw, &["data", "encoding"], "normalized native argument raw")?;
                member(raw, "encoding", "normalized native argument raw")?.string()? == encoding
                    && member(raw, "data", "normalized native argument raw")?.string()? == data
            }
            _ => false,
        };
        if !agrees {
            return Err(format!(
                "normalized native argument {index} differs from the raw report"
            ));
        }
    }
    Ok(())
}

fn validate_projected_predicates(value: &Value, platform: MemcordonPlatform) -> Result<(), String> {
    let fields = object(value, "normalized native predicates")?;
    let expected = match platform {
        MemcordonPlatform::LinuxX86_64 => &[
            "boundary_independent_of_credentials",
            "caller_capability_bounding_set_reproduced",
            "caller_mount_context_reproduced",
            "caller_no_new_privs_reproduced",
            "cgroup_created",
            "cgroup_empty_verified",
            "cgroup_kill_invoked",
            "cgroup_namespace_created",
            "cgroup_owned_by_provider",
            "cgroup_removed",
            "guardian_ready",
            "guardian_reaped",
            "inherited_descriptors_verified",
            "init_created_into_cgroup",
            "initial_provider_capabilities_absent",
            "memory_configuration_verified",
            "mount_namespace_created",
            "namespace_init_reaped",
            "parent_namespace_handles_denied",
            "pid_namespace_created",
            "recursive_provider_request_denied",
            "target_cgroup_membership_verified",
            "target_initial_credentials_verified",
            "target_pid_namespace_verified",
            "target_pidfd_verified",
            "target_released",
            "writable_ancestor_cgroup_denied",
        ][..],
        MemcordonPlatform::WindowsX86_64 => &[
            "active_processes_zero",
            "breakaway_denied",
            "caller_token_authenticated",
            "completion_port_associated",
            "direct_target_reaped",
            "final_job_handles_closed",
            "guardian_ready",
            "guardian_reaped",
            "handle_list_applied_at_creation",
            "inherited_handles_verified",
            "initial_target_token_matches_caller",
            "job_created",
            "job_limits_verified",
            "job_list_applied_at_creation",
            "job_membership_independent_of_token",
            "kill_on_close_verified",
            "relays_retired",
            "target_created_suspended",
            "target_job_membership_verified",
            "target_released",
            "target_still_suspended_during_verification",
            "terminate_job_invoked",
        ][..],
    };
    exact(fields, expected, "normalized native predicates")?;
    for key in expected {
        require_true(fields, key, "normalized native predicates")?;
    }
    Ok(())
}

fn validate_tool(value: &Value) -> Result<(), String> {
    let fields = object(value, "MemCordon tool")?;
    exact(fields, &["name", "version"], "MemCordon tool")?;
    require_text(fields, "name", "memcordon", "MemCordon tool")?;
    require_text(fields, "version", TOOL_VERSION, "MemCordon tool")
}

fn validate_invocation(value: &Value, expected: &ExpectedMemcordonReport) -> Result<(), String> {
    let fields = object(value, "MemCordon invocation")?;
    exact(
        fields,
        &[
            "argv",
            "budget_tokens",
            "deadline_token",
            "memory_token",
            "syntax",
        ],
        "MemCordon invocation",
    )?;
    require_text(fields, "syntax", "plus-budgets-v1", "MemCordon invocation")?;
    require_null(
        member(fields, "memory_token", "MemCordon invocation")?,
        "memory token",
    )?;
    require_text(
        fields,
        "deadline_token",
        &expected.deadline_token,
        "MemCordon invocation",
    )?;
    let budget = member(fields, "budget_tokens", "MemCordon invocation")?.array()?;
    if budget.len() != 1 {
        return Err("MemCordon invocation must contain exactly one time budget".to_owned());
    }
    let budget = object(&budget[0], "MemCordon time budget")?;
    exact(budget, &["kind", "token"], "MemCordon time budget")?;
    require_text(budget, "kind", "time", "MemCordon time budget")?;
    require_text(
        budget,
        "token",
        &expected.deadline_token,
        "MemCordon time budget",
    )?;

    let argv = member(fields, "argv", "MemCordon invocation")?.array()?;
    if argv.len() != expected.argv.len() {
        return Err("MemCordon native argv length differs from the bound request".to_owned());
    }
    for (index, (observed, expected)) in argv.iter().zip(&expected.argv).enumerate() {
        validate_native_argument(observed, expected)
            .map_err(|message| format!("native argument {index}: {message}"))?;
    }
    Ok(())
}

fn validate_native_argument(
    value: &Value,
    expected: &ExpectedNativeArgument,
) -> Result<(), String> {
    let fields = object(value, "native argument")?;
    exact(fields, &["display", "raw"], "native argument")?;
    require_text(fields, "display", &expected.display, "native argument")?;
    let raw = member(fields, "raw", "native argument")?;
    match (&expected.raw_encoding, &expected.raw_data) {
        (None, None) => require_null(raw, "native argument raw form"),
        (Some(encoding), Some(data)) => {
            let raw = object(raw, "native argument raw form")?;
            exact(raw, &["data", "encoding"], "native argument raw form")?;
            require_text(raw, "encoding", encoding, "native argument raw form")?;
            require_text(raw, "data", data, "native argument raw form")?;
            let decoded = decode_base64(data)?;
            let reconstructed = match encoding.as_str() {
                "unix-bytes-base64" => String::from_utf8_lossy(&decoded).into_owned(),
                "windows-u16le-base64" => {
                    let units = decoded
                        .chunks_exact(2)
                        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                        .collect::<Vec<_>>();
                    if decoded.len() % 2 != 0 {
                        return Err(
                            "Windows native argument has an odd decoded byte length".to_owned()
                        );
                    }
                    String::from_utf16_lossy(&units)
                }
                _ => return Err("native argument uses an unsupported raw encoding".to_owned()),
            };
            if reconstructed != expected.display {
                return Err("native argument display disagrees with its raw encoding".to_owned());
            }
            Ok(())
        }
        _ => Err("native argument binding has a partial raw form".to_owned()),
    }
}

fn validate_policy(value: &Value, expected: &ExpectedMemcordonReport) -> Result<(), String> {
    let policy = object(value, "MemCordon policy")?;
    exact(
        policy,
        &["effective", "effects", "requested"],
        "MemCordon policy",
    )?;
    let requested = object(
        member(policy, "requested", "MemCordon policy")?,
        "requested policy",
    )?;
    let effective = object(
        member(policy, "effective", "MemCordon policy")?,
        "effective policy",
    )?;
    let keys = [
        "boundary",
        "command_exit_grace_ms",
        "deadline",
        "limit_grace_ms",
        "memory",
        "restart",
        "signal_grace_ms",
        "wait_for",
    ];
    exact(requested, &keys, "requested policy")?;
    exact(effective, &keys, "effective policy")?;
    require_text(requested, "boundary", "sealed", "requested policy")?;
    require_text(effective, "boundary", "sealed", "effective policy")?;
    require_text(requested, "wait_for", "command", "requested policy")?;
    require_text(effective, "wait_for", "command", "effective policy")?;
    require_number(requested, "command_exit_grace_ms", 0, "requested policy")?;
    require_number(effective, "command_exit_grace_ms", 0, "effective policy")?;
    require_null(
        member(requested, "memory", "requested policy")?,
        "requested memory",
    )?;
    require_null(
        member(effective, "memory", "effective policy")?,
        "effective memory",
    )?;
    validate_deadline(member(requested, "deadline", "requested policy")?, expected)?;
    validate_deadline(member(effective, "deadline", "effective policy")?, expected)?;
    validate_requested_restart(member(requested, "restart", "requested policy")?)?;
    validate_effective_restart(member(effective, "restart", "effective policy")?)?;
    require_number(requested, "signal_grace_ms", 2_000, "requested policy")?;
    require_number(effective, "signal_grace_ms", 2_000, "effective policy")?;
    require_number(requested, "limit_grace_ms", 2_000, "requested policy")?;
    require_number(effective, "limit_grace_ms", 2_000, "effective policy")?;
    require_empty_array(
        member(policy, "effects", "MemCordon policy")?,
        "MemCordon policy effects",
    )?;
    Ok(())
}

fn validate_deadline(value: &Value, expected: &ExpectedMemcordonReport) -> Result<(), String> {
    let fields = object(value, "deadline policy")?;
    exact(
        fields,
        &["clock", "duration_ms", "origin", "scope"],
        "deadline policy",
    )?;
    require_text(fields, "scope", "attempt", "deadline policy")?;
    let duration = member(fields, "duration_ms", "deadline policy")?.number()?;
    if duration == 0 || duration != deadline_millis(&expected.deadline_token)? {
        return Err("deadline duration differs from its bound +TIME token".to_owned());
    }
    require_text(fields, "clock", "monotonic", "deadline policy")?;
    require_text(fields, "origin", "authorization", "deadline policy")
}

fn validate_requested_restart(value: &Value) -> Result<(), String> {
    let fields = object(value, "requested restart policy")?;
    exact(
        fields,
        &[
            "backoff",
            "circuit_breaker",
            "configured_conditions",
            "enabled",
            "enablement_source",
            "limit",
        ],
        "requested restart policy",
    )?;
    require_false(fields, "enabled", "requested restart policy")?;
    require_null(
        member(fields, "enablement_source", "requested restart policy")?,
        "restart source",
    )?;
    require_null(
        member(fields, "backoff", "requested restart policy")?,
        "restart backoff",
    )?;
    require_null(
        member(fields, "circuit_breaker", "requested restart policy")?,
        "restart circuit breaker",
    )?;
    require_empty_array(
        member(fields, "configured_conditions", "requested restart policy")?,
        "restart conditions",
    )?;
    validate_restart_limit(member(fields, "limit", "requested restart policy")?)
}

fn validate_restart_limit(value: &Value) -> Result<(), String> {
    let fields = object(value, "restart limit")?;
    let kind = member(fields, "kind", "restart limit")?.string()?;
    match kind {
        "count" => {
            exact(fields, &["count", "kind"], "restart limit")?;
            require_number(fields, "count", 1, "restart limit")
        }
        "unlimited" => exact(fields, &["kind"], "restart limit"),
        _ => Err("restart limit kind is unsupported".to_owned()),
    }
}

fn validate_effective_restart(value: &Value) -> Result<(), String> {
    let fields = object(value, "effective restart policy")?;
    exact(
        fields,
        &[
            "cleanup_proof_required",
            "conditions",
            "dormant_conditions",
            "enabled",
        ],
        "effective restart policy",
    )?;
    require_false(fields, "enabled", "effective restart policy")?;
    require_empty_array(
        member(fields, "conditions", "effective restart policy")?,
        "effective restart conditions",
    )?;
    require_empty_array(
        member(fields, "dormant_conditions", "effective restart policy")?,
        "dormant restart conditions",
    )?;
    require_false(fields, "cleanup_proof_required", "effective restart policy")
}

#[allow(clippy::too_many_lines)]
fn validate_backend(value: &Value, platform: MemcordonPlatform) -> Result<(), String> {
    let fields = object(value, "MemCordon backend")?;
    exact(
        fields,
        &[
            "boundary",
            "boundary_qualification",
            "containment",
            "deadline",
            "deadline_origin",
            "deadline_scopes",
            "limitations",
            "memory",
            "name",
            "persistent_restart_state",
            "restart",
            "restart_cleanup_condition",
            "restart_conditions",
            "startup_containment",
        ],
        "MemCordon backend",
    )?;
    require_text(fields, "name", "sealed", "MemCordon backend")?;
    validate_capability(
        member(fields, "containment", "MemCordon backend")?,
        "containment",
    )?;
    validate_capability(member(fields, "deadline", "MemCordon backend")?, "deadline")?;
    validate_capability(member(fields, "restart", "MemCordon backend")?, "restart")?;
    let boundary = object(
        member(fields, "boundary", "MemCordon backend")?,
        "backend boundary",
    )?;
    exact(
        boundary,
        &[
            "boundary_verified_before_authorization",
            "class",
            "frontend_loss_cleanup_authority",
            "limitations",
            "mechanism",
            "target_can_reconfigure_boundary",
            "target_gated",
            "workload_empty_proof",
        ],
        "backend boundary",
    )?;
    require_text(boundary, "class", "sealed", "backend boundary")?;
    require_text(
        boundary,
        "mechanism",
        platform.mechanism(),
        "backend boundary",
    )?;
    require_true(boundary, "target_gated", "backend boundary")?;
    require_true(
        boundary,
        "boundary_verified_before_authorization",
        "backend boundary",
    )?;
    require_false(
        boundary,
        "target_can_reconfigure_boundary",
        "backend boundary",
    )?;
    require_true(
        boundary,
        "frontend_loss_cleanup_authority",
        "backend boundary",
    )?;
    require_true(boundary, "workload_empty_proof", "backend boundary")?;
    require_empty_array(
        member(boundary, "limitations", "backend boundary")?,
        "backend boundary limitations",
    )?;

    let qualification = object(
        member(fields, "boundary_qualification", "MemCordon backend")?,
        "backend qualification",
    )?;
    exact(
        qualification,
        &["mechanism", "provider_identity", "receipt_digest"],
        "backend qualification",
    )?;
    require_text(
        qualification,
        "mechanism",
        platform.mechanism(),
        "backend qualification",
    )?;
    if member(qualification, "provider_identity", "backend qualification")?
        .string()?
        .is_empty()
    {
        return Err("backend qualification provider identity is empty".to_owned());
    }
    require_digest(member(qualification, "receipt_digest", "backend qualification")?.string()?)?;
    require_exact_string_array(
        member(fields, "deadline_scopes", "MemCordon backend")?,
        &["attempt"],
        "deadline scopes",
    )?;
    require_empty_array(
        member(fields, "limitations", "MemCordon backend")?,
        "backend limitations",
    )?;
    require_null(
        member(fields, "memory", "MemCordon backend")?,
        "backend memory",
    )?;
    require_text(
        fields,
        "deadline_origin",
        "authorization",
        "MemCordon backend",
    )?;
    require_empty_array(
        member(fields, "restart_conditions", "MemCordon backend")?,
        "backend restart conditions",
    )?;
    require_false(fields, "persistent_restart_state", "MemCordon backend")?;
    require_text(
        fields,
        "startup_containment",
        "verified",
        "MemCordon backend",
    )?;
    require_text(
        fields,
        "restart_cleanup_condition",
        "empty",
        "MemCordon backend",
    )?;
    Ok(())
}

fn validate_capability(value: &Value, label: &str) -> Result<(), String> {
    let fields = object(value, label)?;
    exact(fields, &["reason", "supported"], label)?;
    require_true(fields, "supported", label)?;
    require_null(member(fields, "reason", label)?, label)
}

fn validate_attempt(value: &Value, expected: &ExpectedMemcordonReport) -> Result<Value, String> {
    let fields = object(value, "MemCordon attempt")?;
    exact(
        fields,
        &[
            "authorized_offset_ms",
            "boundary_detail",
            "error",
            "finished_offset_ms",
            "kind",
            "launch",
            "number",
            "outcome",
            "phase",
            "restart_decision",
            "restart_safety",
            "started_offset_ms",
            "target_pid",
            "terminal_offset_ms",
        ],
        "MemCordon attempt",
    )?;
    require_number(fields, "number", 1, "MemCordon attempt")?;
    require_text(fields, "kind", "initial", "MemCordon attempt")?;
    require_text(fields, "phase", "completed", "MemCordon attempt")?;
    require_null(
        member(fields, "error", "MemCordon attempt")?,
        "MemCordon attempt error",
    )?;
    let started = optional_number(member(fields, "started_offset_ms", "MemCordon attempt")?)?;
    let authorized = optional_number(member(fields, "authorized_offset_ms", "MemCordon attempt")?)?;
    let terminal = optional_number(member(fields, "terminal_offset_ms", "MemCordon attempt")?)?;
    let finished = member(fields, "finished_offset_ms", "MemCordon attempt")?.number()?;
    if started.is_none()
        || authorized.is_none()
        || terminal.is_none()
        || started > authorized
        || authorized > terminal
        || terminal > Some(finished)
    {
        return Err("MemCordon attempt offsets are incomplete or inconsistent".to_owned());
    }
    if optional_number(member(fields, "target_pid", "MemCordon attempt")?)?.is_none() {
        return Err("MemCordon authorized attempt lacks a target pid".to_owned());
    }
    validate_restart_decision(member(fields, "restart_decision", "MemCordon attempt")?)?;
    validate_launch(
        member(fields, "launch", "MemCordon attempt")?,
        expected.platform,
    )?;
    validate_restart_safety(member(fields, "restart_safety", "MemCordon attempt")?)?;
    validate_boundary_detail(
        member(fields, "boundary_detail", "MemCordon attempt")?,
        expected.platform,
    )?;
    let outcome = member(fields, "outcome", "MemCordon attempt")?.clone();
    validate_outcome(&outcome, expected.termination)?;
    Ok(outcome)
}

fn validate_restart_decision(value: &Value) -> Result<(), String> {
    let fields = object(value, "restart decision")?;
    exact(
        fields,
        &[
            "actual_wait_ms",
            "circuit_state",
            "configured_wait_ms",
            "decision",
            "half_life_logistic_sequence_index",
            "restart_number",
            "supervision_deadline_truncated_wait",
            "trigger",
            "wait_kind",
        ],
        "restart decision",
    )?;
    require_text(fields, "decision", "none-disabled", "restart decision")?;
    require_text(fields, "circuit_state", "closed", "restart decision")?;
    require_false(
        fields,
        "supervision_deadline_truncated_wait",
        "restart decision",
    )?;
    for key in [
        "actual_wait_ms",
        "configured_wait_ms",
        "half_life_logistic_sequence_index",
        "restart_number",
        "trigger",
        "wait_kind",
    ] {
        require_null(
            member(fields, key, "restart decision")?,
            "restart decision optional field",
        )?;
    }
    Ok(())
}

fn validate_launch(value: &Value, platform: MemcordonPlatform) -> Result<(), String> {
    let fields = object(value, "launch evidence")?;
    exact(
        fields,
        &[
            "boundary_assignment_verified",
            "boundary_effective",
            "boundary_reconfiguration_denied",
            "boundary_requested",
            "containment_verified_before_authorization",
            "frontend_loss_cleanup_authority_verified",
            "guardian_started_before_authorization",
            "inherited_resources_restricted",
            "mechanism",
            "target_released",
            "target_spawn_error_reported",
        ],
        "launch evidence",
    )?;
    require_text(fields, "mechanism", platform.mechanism(), "launch evidence")?;
    require_text(fields, "boundary_requested", "sealed", "launch evidence")?;
    require_text(fields, "boundary_effective", "sealed", "launch evidence")?;
    for key in [
        "boundary_assignment_verified",
        "boundary_reconfiguration_denied",
        "containment_verified_before_authorization",
        "frontend_loss_cleanup_authority_verified",
        "guardian_started_before_authorization",
        "inherited_resources_restricted",
        "target_released",
        "target_spawn_error_reported",
    ] {
        require_true(fields, key, "launch evidence")?;
    }
    Ok(())
}

fn validate_restart_safety(value: &Value) -> Result<(), String> {
    let fields = object(value, "restart safety")?;
    exact(
        fields,
        &[
            "containment_incapable_of_live_members",
            "containment_removed",
            "direct_child_reaped",
            "errors",
            "helpers_reaped",
            "sealed_boundary_retired",
            "workload_empty",
        ],
        "restart safety",
    )?;
    require_true(fields, "direct_child_reaped", "restart safety")?;
    require_true(fields, "helpers_reaped", "restart safety")?;
    require_true(fields, "sealed_boundary_retired", "restart safety")?;
    require_true(fields, "workload_empty", "restart safety")?;
    let removed = member(fields, "containment_removed", "restart safety")?.boolean()?;
    let incapable = member(
        fields,
        "containment_incapable_of_live_members",
        "restart safety",
    )?
    .boolean()?;
    if !removed && !incapable {
        return Err("restart safety lacks terminal containment disposition".to_owned());
    }
    require_empty_array(
        member(fields, "errors", "restart safety")?,
        "restart safety errors",
    )
}

fn validate_boundary_detail(value: &Value, platform: MemcordonPlatform) -> Result<(), String> {
    let fields = object(value, "native boundary evidence")?;
    match platform {
        MemcordonPlatform::LinuxX86_64 => validate_linux_detail(fields),
        MemcordonPlatform::WindowsX86_64 => validate_windows_detail(fields),
    }
}

#[allow(clippy::too_many_lines)]
fn validate_linux_detail(fields: &BTreeMap<String, Value>) -> Result<(), String> {
    exact(
        fields,
        &[
            "boundary_independent_of_credentials",
            "caller_capability_bounding_set_reproduced",
            "caller_mount_context_reproduced",
            "caller_no_new_privs_reproduced",
            "cgroup_created",
            "cgroup_empty_verified",
            "cgroup_identity_digest",
            "cgroup_kill_invoked",
            "cgroup_namespace_created",
            "cgroup_owned_by_provider",
            "cgroup_removed",
            "control_service_identity",
            "credential_transition_disposition",
            "guardian_ready",
            "guardian_reaped",
            "inherited_descriptors_verified",
            "init_created_into_cgroup",
            "initial_provider_capabilities_absent",
            "launcher_service_identity",
            "mechanism",
            "memory_configuration_verified",
            "mount_namespace_created",
            "namespace_init_reaped",
            "parent_namespace_handles_denied",
            "pid_namespace_created",
            "provider_identity",
            "recursive_provider_request_denied",
            "schema_version",
            "target_cgroup_membership_verified",
            "target_initial_credentials_verified",
            "target_pid_namespace_verified",
            "target_pidfd_verified",
            "target_released",
            "writable_ancestor_cgroup_denied",
        ],
        "Linux sealed evidence",
    )?;
    require_text(
        fields,
        "mechanism",
        "linux-pid-namespace-cgroup-v2",
        "Linux sealed evidence",
    )?;
    require_number(fields, "schema_version", 2, "Linux sealed evidence")?;
    require_text(
        fields,
        "provider_identity",
        "memcordon-sealed-agent-v2",
        "Linux sealed evidence",
    )?;
    require_text(
        fields,
        "control_service_identity",
        "memcordon-sealed-agent.service:v2",
        "Linux sealed evidence",
    )?;
    require_text(
        fields,
        "launcher_service_identity",
        "memcordon-sealed-launcher.service:v2",
        "Linux sealed evidence",
    )?;
    require_text(
        fields,
        "credential_transition_disposition",
        "preserve-caller-envelope",
        "Linux sealed evidence",
    )?;
    require_digest(member(fields, "cgroup_identity_digest", "Linux sealed evidence")?.string()?)?;
    for key in [
        "boundary_independent_of_credentials",
        "caller_capability_bounding_set_reproduced",
        "caller_mount_context_reproduced",
        "caller_no_new_privs_reproduced",
        "cgroup_created",
        "cgroup_empty_verified",
        "cgroup_kill_invoked",
        "cgroup_namespace_created",
        "cgroup_owned_by_provider",
        "cgroup_removed",
        "guardian_ready",
        "guardian_reaped",
        "inherited_descriptors_verified",
        "init_created_into_cgroup",
        "initial_provider_capabilities_absent",
        "memory_configuration_verified",
        "mount_namespace_created",
        "namespace_init_reaped",
        "parent_namespace_handles_denied",
        "pid_namespace_created",
        "recursive_provider_request_denied",
        "target_cgroup_membership_verified",
        "target_initial_credentials_verified",
        "target_pid_namespace_verified",
        "target_pidfd_verified",
        "target_released",
        "writable_ancestor_cgroup_denied",
    ] {
        require_true(fields, key, "Linux sealed evidence")?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_windows_detail(fields: &BTreeMap<String, Value>) -> Result<(), String> {
    let keys = if fields.contains_key("loader_qualification") {
        &[
            "active_processes_zero",
            "breakaway_denied",
            "caller_token_authenticated",
            "completion_port_associated",
            "credential_transition_disposition",
            "direct_target_reaped",
            "final_job_handles_closed",
            "guardian_ready",
            "guardian_reaped",
            "handle_list_applied_at_creation",
            "inherited_handles_verified",
            "initial_target_token_matches_caller",
            "job_created",
            "job_limits_verified",
            "job_list_applied_at_creation",
            "job_membership_independent_of_token",
            "kill_on_close_verified",
            "loader_qualification",
            "mechanism",
            "relays_retired",
            "schema_version",
            "service_identity",
            "target_created_suspended",
            "target_job_membership_verified",
            "target_released",
            "target_still_suspended_during_verification",
            "terminate_job_invoked",
        ][..]
    } else {
        &[
            "active_processes_zero",
            "breakaway_denied",
            "caller_token_authenticated",
            "completion_port_associated",
            "credential_transition_disposition",
            "direct_target_reaped",
            "final_job_handles_closed",
            "guardian_ready",
            "guardian_reaped",
            "handle_list_applied_at_creation",
            "inherited_handles_verified",
            "initial_target_token_matches_caller",
            "job_created",
            "job_limits_verified",
            "job_list_applied_at_creation",
            "job_membership_independent_of_token",
            "kill_on_close_verified",
            "mechanism",
            "relays_retired",
            "schema_version",
            "service_identity",
            "target_created_suspended",
            "target_job_membership_verified",
            "target_released",
            "target_still_suspended_during_verification",
            "terminate_job_invoked",
        ][..]
    };
    exact(fields, keys, "Windows sealed evidence")?;
    require_text(
        fields,
        "mechanism",
        "windows-job-object-v2",
        "Windows sealed evidence",
    )?;
    require_number(fields, "schema_version", 2, "Windows sealed evidence")?;
    require_text(
        fields,
        "service_identity",
        "MemCordonSealedControl+MemCordonSealedLauncher:v1",
        "Windows sealed evidence",
    )?;
    require_text(
        fields,
        "credential_transition_disposition",
        "preserve-caller-envelope",
        "Windows sealed evidence",
    )?;
    for key in [
        "active_processes_zero",
        "breakaway_denied",
        "caller_token_authenticated",
        "completion_port_associated",
        "direct_target_reaped",
        "final_job_handles_closed",
        "guardian_ready",
        "guardian_reaped",
        "handle_list_applied_at_creation",
        "inherited_handles_verified",
        "initial_target_token_matches_caller",
        "job_created",
        "job_limits_verified",
        "job_list_applied_at_creation",
        "job_membership_independent_of_token",
        "kill_on_close_verified",
        "relays_retired",
        "target_created_suspended",
        "target_job_membership_verified",
        "target_released",
        "target_still_suspended_during_verification",
        "terminate_job_invoked",
    ] {
        require_true(fields, key, "Windows sealed evidence")?;
    }
    fields
        .get("loader_qualification")
        .map_or(Ok(()), validate_loader_qualification)
}

fn validate_loader_qualification(value: &Value) -> Result<(), String> {
    if matches!(value, Value::Null) {
        return Ok(());
    }
    let fields = object(value, "Windows loader qualification")?;
    exact(
        fields,
        &["result", "status"],
        "Windows loader qualification",
    )?;
    if member(fields, "status", "Windows loader qualification")?.string()? != "ready" {
        return Err("Windows loader qualification reports failure".to_owned());
    }
    let ready = object(
        member(fields, "result", "Windows loader qualification")?,
        "Windows loader ready evidence",
    )?;
    let ready_keys = if ready.contains_key("launch_plan_json") {
        &[
            "elapsed_millis",
            "launch_plan_json",
            "launch_plan_sha256",
            "schema_version",
        ][..]
    } else {
        &["elapsed_millis", "launch_plan_sha256", "schema_version"][..]
    };
    exact(ready, ready_keys, "Windows loader ready evidence")?;
    require_number(ready, "schema_version", 1, "Windows loader ready evidence")?;
    require_digest(
        member(ready, "launch_plan_sha256", "Windows loader ready evidence")?.string()?,
    )?;
    member(ready, "elapsed_millis", "Windows loader ready evidence")?.number()?;
    match ready.get("launch_plan_json") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(plan)) => {
            if plan.len() > 64 * 1024 || plan.contains('\0') {
                return Err("Windows loader plan JSON is empty or oversized".to_owned());
            }
            let parsed = json::parse(plan.as_bytes())?;
            let plan = object(&parsed, "Windows loader plan")?;
            require_text(
                plan,
                "launch_plan_sha256",
                member(ready, "launch_plan_sha256", "Windows loader ready evidence")?.string()?,
                "Windows loader plan",
            )
        }
        Some(_) => Err("Windows loader plan JSON has the wrong type".to_owned()),
    }
}

fn validate_outcome(value: &Value, expected: ExpectedTermination) -> Result<(), String> {
    let fields = object(value, "attempt outcome")?;
    exact(
        fields,
        &["child", "cleanup", "outcome", "peak"],
        "attempt outcome",
    )?;
    require_text(fields, "outcome", "exited", "attempt outcome")?;
    let child = object(
        member(fields, "child", "attempt outcome")?,
        "child termination",
    )?;
    match expected {
        ExpectedTermination::ExitCode(code) => {
            exact(child, &["code", "kind"], "child termination")?;
            require_text(child, "kind", "exit-code", "child termination")?;
            require_number(child, "code", u64::from(code), "child termination")?;
        }
        ExpectedTermination::UnixSignal(signal) => {
            exact(child, &["kind", "signal"], "child termination")?;
            require_text(child, "kind", "unix-signal", "child termination")?;
            require_number(child, "signal", u64::from(signal), "child termination")?;
        }
        ExpectedTermination::WindowsStatus(status) => {
            exact(child, &["kind", "status"], "child termination")?;
            require_text(child, "kind", "windows-status", "child termination")?;
            require_number(child, "status", u64::from(status), "child termination")?;
        }
    }
    match member(fields, "peak", "attempt outcome")? {
        Value::Null | Value::Number(_) => {}
        _ => return Err("attempt peak is neither null nor an unsigned byte count".to_owned()),
    }
    let cleanup = object(
        member(fields, "cleanup", "attempt outcome")?,
        "attempt cleanup",
    )?;
    exact(
        cleanup,
        &[
            "direct_child_reaped",
            "errors",
            "force_attempted",
            "graceful_attempted",
            "workload_empty",
        ],
        "attempt cleanup",
    )?;
    require_true(cleanup, "direct_child_reaped", "attempt cleanup")?;
    require_true(cleanup, "workload_empty", "attempt cleanup")?;
    member(cleanup, "force_attempted", "attempt cleanup")?.boolean()?;
    member(cleanup, "graceful_attempted", "attempt cleanup")?.boolean()?;
    require_empty_array(
        member(cleanup, "errors", "attempt cleanup")?,
        "attempt cleanup errors",
    )
}

#[allow(clippy::too_many_lines)]
fn validate_supervision(value: &Value, outcome: &Value, wrapper: u32) -> Result<(), String> {
    let fields = object(value, "MemCordon supervision")?;
    exact(
        fields,
        &[
            "aggregate",
            "attempt_history",
            "attempt_records_created",
            "duration_ms",
            "phase",
            "restart",
            "targets_authorized",
            "terminal",
            "wrapper_exit_code",
        ],
        "MemCordon supervision",
    )?;
    require_text(fields, "phase", "completed", "MemCordon supervision")?;
    require_number(
        fields,
        "attempt_records_created",
        1,
        "MemCordon supervision",
    )?;
    require_number(fields, "targets_authorized", 1, "MemCordon supervision")?;
    require_number(
        fields,
        "wrapper_exit_code",
        u64::from(wrapper),
        "MemCordon supervision",
    )?;
    member(fields, "duration_ms", "MemCordon supervision")?.number()?;
    let terminal = object(
        member(fields, "terminal", "MemCordon supervision")?,
        "supervision terminal",
    )?;
    exact(
        terminal,
        &["attempt_number", "kind", "outcome"],
        "supervision terminal",
    )?;
    require_text(terminal, "kind", "attempt-outcome", "supervision terminal")?;
    require_number(terminal, "attempt_number", 1, "supervision terminal")?;
    if member(terminal, "outcome", "supervision terminal")? != outcome {
        return Err("supervision terminal outcome differs from the retained attempt".to_owned());
    }
    let history = object(
        member(fields, "attempt_history", "MemCordon supervision")?,
        "attempt history",
    )?;
    exact(
        history,
        &["capacity", "omitted", "retained", "total", "truncated"],
        "attempt history",
    )?;
    require_number(history, "capacity", 256, "attempt history")?;
    require_number(history, "retained", 1, "attempt history")?;
    require_number(history, "total", 1, "attempt history")?;
    require_number(history, "omitted", 0, "attempt history")?;
    require_false(history, "truncated", "attempt history")?;
    let aggregate = object(
        member(fields, "aggregate", "MemCordon supervision")?,
        "supervision aggregate",
    )?;
    exact(
        aggregate,
        &[
            "child_exits",
            "deadlines",
            "interruptions",
            "max_peak",
            "memory_limits",
            "monitor_failures",
            "setup_failures",
        ],
        "supervision aggregate",
    )?;
    require_number(aggregate, "child_exits", 1, "supervision aggregate")?;
    for key in [
        "deadlines",
        "interruptions",
        "memory_limits",
        "monitor_failures",
        "setup_failures",
    ] {
        require_number(aggregate, key, 0, "supervision aggregate")?;
    }
    match member(aggregate, "max_peak", "supervision aggregate")? {
        Value::Null | Value::Number(_) => {}
        _ => return Err("supervision maximum peak has the wrong type".to_owned()),
    }
    let restart = object(
        member(fields, "restart", "MemCordon supervision")?,
        "restart summary",
    )?;
    exact(
        restart,
        &[
            "circuit_open_count",
            "cooldowns",
            "enabled",
            "final_circuit_state",
            "half_life_logistic_waits",
            "restart_limit_exhausted",
            "restarts_launched",
        ],
        "restart summary",
    )?;
    require_false(restart, "enabled", "restart summary")?;
    require_false(restart, "restart_limit_exhausted", "restart summary")?;
    require_text(restart, "final_circuit_state", "closed", "restart summary")?;
    for key in [
        "circuit_open_count",
        "cooldowns",
        "half_life_logistic_waits",
        "restarts_launched",
    ] {
        require_number(restart, key, 0, "restart summary")?;
    }
    Ok(())
}

fn expected_wrapper_status(termination: ExpectedTermination) -> Result<u32, String> {
    match termination {
        ExpectedTermination::ExitCode(code) => Ok(code),
        ExpectedTermination::UnixSignal(signal) => 128_u32
            .checked_add(signal)
            .ok_or_else(|| "Unix signal wrapper status overflows".to_owned()),
        ExpectedTermination::WindowsStatus(status) => Ok(if status > i32::MAX as u32 {
            125
        } else {
            status
        }),
    }
}

fn validate_provider_cleanup(
    bytes: &[u8],
    expected: &ExpectedMemcordonFinalization,
) -> Result<(), String> {
    let value = json::parse(bytes)?;
    let fields = object(&value, "provider cleanup receipt")?;
    exact(
        fields,
        &[
            "active_operations",
            "attempted",
            "failure",
            "final_state",
            "installed_footprint_absent",
            "operation_id",
            "platform",
            "provider_lease_id",
            "schema_version",
        ],
        "provider cleanup receipt",
    )?;
    require_number(fields, "schema_version", 1, "provider cleanup receipt")?;
    require_text(
        fields,
        "platform",
        platform_id(expected.platform),
        "provider cleanup receipt",
    )?;
    require_text(
        fields,
        "operation_id",
        &expected.provider_operation,
        "provider cleanup receipt",
    )?;
    if member(fields, "provider_lease_id", "provider cleanup receipt")?
        .string()?
        .is_empty()
    {
        return Err("provider cleanup lease id is empty".to_owned());
    }
    member(fields, "attempted", "provider cleanup receipt")?.boolean()?;
    require_text(fields, "final_state", "removed", "provider cleanup receipt")?;
    require_true(
        fields,
        "installed_footprint_absent",
        "provider cleanup receipt",
    )?;
    require_number(fields, "active_operations", 0, "provider cleanup receipt")?;
    require_null(
        member(fields, "failure", "provider cleanup receipt")?,
        "provider cleanup failure",
    )
}

fn validate_operations(
    bytes: &[u8],
    expected: &ExpectedMemcordonFinalization,
    required: &[String],
    inventory: &BTreeMap<String, String>,
) -> Result<(), String> {
    let value = json::parse(bytes)?;
    let entries = value.array()?;
    if entries.len() != required.len() {
        return Err("operation ledger length differs from the trusted plan".to_owned());
    }
    let mut observed = Vec::with_capacity(entries.len());
    for entry in entries {
        let fields = object(entry, "operation ledger entry")?;
        exact(
            fields,
            &[
                "boundary",
                "identity_adapter_digest",
                "identity_adapter_path",
                "normalized_report_digest",
                "normalized_report_path",
                "operation_id",
                "raw_report_digest",
                "raw_report_path",
                "request_digest",
                "terminal",
            ],
            "operation ledger entry",
        )?;
        let operation_id = member(fields, "operation_id", "operation ledger entry")?.string()?;
        require_identifier(operation_id, "operation id")?;
        observed.push(operation_id.to_owned());
        require_text(
            fields,
            "boundary",
            match expected.platform {
                MemcordonPlatform::LinuxX86_64 => "sealed-linux",
                MemcordonPlatform::WindowsX86_64 => "sealed-windows",
            },
            "operation ledger entry",
        )?;
        require_digest(member(fields, "request_digest", "operation ledger entry")?.string()?)?;
        validate_ledger_path_digest(
            fields,
            "raw_report_path",
            "raw_report_digest",
            "raw",
            operation_id,
            inventory,
        )?;
        validate_ledger_path_digest(
            fields,
            "normalized_report_path",
            "normalized_report_digest",
            "normalized",
            operation_id,
            inventory,
        )?;
        match expected.platform {
            MemcordonPlatform::LinuxX86_64 => {
                require_null(
                    member(fields, "identity_adapter_path", "operation ledger entry")?,
                    "Linux identity adapter path",
                )?;
                require_null(
                    member(fields, "identity_adapter_digest", "operation ledger entry")?,
                    "Linux identity adapter digest",
                )?;
            }
            MemcordonPlatform::WindowsX86_64 => validate_ledger_path_digest(
                fields,
                "identity_adapter_path",
                "identity_adapter_digest",
                "adapters",
                operation_id,
                inventory,
            )?,
        }
        let terminal = object(
            member(fields, "terminal", "operation ledger entry")?,
            "operation terminal",
        )?;
        exact(terminal, &["kind"], "operation terminal")?;
        require_text(terminal, "kind", "ordinary_result", "operation terminal")?;
    }
    let observed = validate_operation_ids(&observed, "operation ledger")?;
    if observed != required {
        return Err("operation ledger differs from the trusted required operations".to_owned());
    }
    Ok(())
}

fn validate_ledger_path_digest(
    fields: &BTreeMap<String, Value>,
    path_key: &str,
    digest_key: &str,
    directory: &str,
    operation_id: &str,
    inventory: &BTreeMap<String, String>,
) -> Result<(), String> {
    let path = member(fields, path_key, "operation ledger entry")?.string()?;
    let expected_path = format!("{directory}/{operation_id}.json");
    if path != expected_path {
        return Err(format!("operation ledger {path_key} is unsafe"));
    }
    let digest = member(fields, digest_key, "operation ledger entry")?.string()?;
    require_digest(digest)?;
    require_inventory_digest(inventory, path, digest)
}

fn validate_inventory(bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
    if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 || !bytes.ends_with(b"\n") {
        return Err(
            "MemCordon inventory is empty, oversized, or lacks its final newline".to_owned(),
        );
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| "MemCordon inventory is not UTF-8".to_owned())?;
    let mut inventory = BTreeMap::new();
    let mut previous = None;
    for line in text.lines() {
        let (digest, path) = line
            .split_once("  ")
            .ok_or_else(|| "MemCordon inventory line lacks its exact separator".to_owned())?;
        require_digest(digest)?;
        if path.is_empty()
            || path.starts_with('/')
            || path.contains('\\')
            || !path.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'/' | b'.' | b'-' | b'_')
            })
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || matches!(path, "finalization.json" | "inventory.sha256")
        {
            return Err("MemCordon inventory contains an unsafe path".to_owned());
        }
        if previous.is_some_and(|prior: &str| prior >= path) {
            return Err("MemCordon inventory paths are duplicated or unsorted".to_owned());
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
        "publication-report.json",
        "provider-cleanup.json",
        "provider-lease.json",
        "release-manifest.json",
        "runtime-manifest.json",
    ] {
        if !inventory.contains_key(required) {
            return Err(format!("MemCordon inventory lacks {required}"));
        }
    }
    Ok(inventory)
}

fn require_inventory_digest(
    inventory: &BTreeMap<String, String>,
    path: &str,
    digest: &str,
) -> Result<(), String> {
    match inventory.get(path) {
        Some(observed) if observed == digest => Ok(()),
        Some(_) => Err(format!("MemCordon inventory digest differs for {path}")),
        None => Err(format!("MemCordon inventory lacks {path}")),
    }
}

fn require_bound_digest(
    fields: &BTreeMap<String, Value>,
    key: &str,
    bytes: &[u8],
) -> Result<(), String> {
    let observed = member(fields, key, "MemCordon finalization")?.string()?;
    require_digest(observed)?;
    if observed == crate::digest::sha256_hex(bytes) {
        Ok(())
    } else {
        Err(format!(
            "MemCordon finalization {key} differs from retained bytes"
        ))
    }
}

fn operation_ids(value: &Value, label: &str) -> Result<Vec<String>, String> {
    let ids = value
        .array()?
        .iter()
        .map(|value| value.string().map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?;
    validate_operation_ids(&ids, label)
}

fn validate_operation_ids(ids: &[String], label: &str) -> Result<Vec<String>, String> {
    for id in ids {
        require_identifier(id, label)?;
    }
    if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(format!("{label} is duplicated or unsorted"));
    }
    Ok(ids.to_vec())
}

fn require_identifier(value: &str, label: &str) -> Result<(), String> {
    if !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        Ok(())
    } else {
        Err(format!("{label} is not a bounded identifier"))
    }
}

fn require_sha(value: &str, label: &str) -> Result<(), String> {
    if value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!("{label} is not a full lowercase commit"))
    }
}

const fn platform_id(platform: MemcordonPlatform) -> &'static str {
    match platform {
        MemcordonPlatform::LinuxX86_64 => "linux-x86-64",
        MemcordonPlatform::WindowsX86_64 => "windows-x86-64",
    }
}

fn deadline_millis(token: &str) -> Result<u64, String> {
    let body = token
        .strip_prefix('+')
        .and_then(|value| value.strip_suffix("ms"))
        .ok_or_else(|| "bound deadline token is not an exact +MILLISECONDSms token".to_owned())?;
    let value = body
        .parse::<u64>()
        .map_err(|_| "bound deadline token contains an invalid millisecond count".to_owned())?;
    if value == 0 {
        return Err("bound deadline token is zero".to_owned());
    }
    Ok(value)
}

fn decode_base64(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() || !value.len().is_multiple_of(4) {
        return Err("native argument base64 has invalid length".to_owned());
    }
    let mut output = Vec::with_capacity(value.len() / 4 * 3);
    let chunks = value.as_bytes().chunks_exact(4);
    for (index, chunk) in chunks.enumerate() {
        let last = (index + 1) * 4 == value.len();
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let c_pad = chunk[2] == b'=';
        let d_pad = chunk[3] == b'=';
        if c_pad && !d_pad || d_pad && !last {
            return Err("native argument base64 padding is invalid".to_owned());
        }
        let c = if c_pad { 0 } else { base64_value(chunk[2])? };
        let d = if d_pad { 0 } else { base64_value(chunk[3])? };
        output.push((a << 2) | (b >> 4));
        if !c_pad {
            output.push((b << 4) | (c >> 2));
        }
        if !d_pad {
            output.push((c << 6) | d);
        }
        if (c_pad && b & 0x0f != 0) || (d_pad && !c_pad && c & 0x03 != 0) {
            return Err("native argument base64 has nonzero padding bits".to_owned());
        }
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err("native argument base64 contains an invalid byte".to_owned()),
    }
}

fn object<'a>(value: &'a Value, label: &str) -> Result<&'a BTreeMap<String, Value>, String> {
    value
        .object()
        .map_err(|_| format!("{label} is not an object"))
}

fn exact(fields: &BTreeMap<String, Value>, keys: &[&str], label: &str) -> Result<(), String> {
    json::exact_keys(fields, keys).map_err(|message| format!("{label}: {message}"))
}

fn member<'a>(
    fields: &'a BTreeMap<String, Value>,
    key: &str,
    label: &str,
) -> Result<&'a Value, String> {
    json::member(fields, key).map_err(|_| format!("{label} lacks {key}"))
}

fn require_text(
    fields: &BTreeMap<String, Value>,
    key: &str,
    expected: &str,
    label: &str,
) -> Result<(), String> {
    let observed = member(fields, key, label)?.string()?;
    if observed == expected {
        Ok(())
    } else {
        Err(format!("{label} {key} differs"))
    }
}

fn require_number(
    fields: &BTreeMap<String, Value>,
    key: &str,
    expected: u64,
    label: &str,
) -> Result<(), String> {
    let observed = member(fields, key, label)?.number()?;
    if observed == expected {
        Ok(())
    } else {
        Err(format!("{label} {key} differs"))
    }
}

fn require_true(fields: &BTreeMap<String, Value>, key: &str, label: &str) -> Result<(), String> {
    if member(fields, key, label)?.boolean()? {
        Ok(())
    } else {
        Err(format!("{label} {key} is false"))
    }
}

fn require_false(fields: &BTreeMap<String, Value>, key: &str, label: &str) -> Result<(), String> {
    if member(fields, key, label)?.boolean()? {
        Err(format!("{label} {key} is true"))
    } else {
        Ok(())
    }
}

fn require_null(value: &Value, label: &str) -> Result<(), String> {
    if matches!(value, Value::Null) {
        Ok(())
    } else {
        Err(format!("{label} is not null"))
    }
}

fn require_empty_array(value: &Value, label: &str) -> Result<(), String> {
    if value.array()?.is_empty() {
        Ok(())
    } else {
        Err(format!("{label} is not empty"))
    }
}

fn require_exact_string_array(value: &Value, expected: &[&str], label: &str) -> Result<(), String> {
    let values = value.array()?;
    if values.len() != expected.len()
        || values
            .iter()
            .zip(expected)
            .any(|(observed, expected)| observed.string() != Ok(*expected))
    {
        return Err(format!("{label} differs"));
    }
    Ok(())
}

fn optional_number(value: &Value) -> Result<Option<u64>, String> {
    match value {
        Value::Null => Ok(None),
        Value::Number(value) => Ok(Some(*value)),
        _ => Err("expected null or unsigned integer".to_owned()),
    }
}

fn require_digest(value: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err("MemCordon evidence contains an invalid SHA-256 digest".to_owned())
    }
}
