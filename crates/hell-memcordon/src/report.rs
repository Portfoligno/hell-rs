use std::collections::BTreeMap;

use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::{ContractError, EXECUTION_SCHEMA, NativeArgument};
use memcordon_core::{
    BoundaryClass, BoundaryMechanismEvidence, BoundaryRequirement, BudgetKindReport,
    ChildTermination, CredentialTransitionDisposition, DeadlineScope, MemcordonReport, RunOutcome,
    SupervisionPhase, WindowsLoaderQualificationOutcomeV2,
};

pub const MAX_EXECUTION_REPORT_BYTES: usize = 8 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 64;
const LINUX_NATIVE_PREDICATES: &[&str] = &[
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
];
const WINDOWS_NATIVE_PREDICATES: &[&str] = &[
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
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Schema8TerminalV1 {
    CandidateExit { native_status: u32 },
    CandidateSignal { signal: u32 },
    InnerDeadline,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schema8ProjectionV1 {
    pub schema_version: u32,
    pub tool_version: String,
    pub requested_boundary: String,
    pub effective_boundary: String,
    pub mechanism: String,
    pub target_argv: Vec<NativeArgument>,
    pub attempt_count: u32,
    pub restart_count: u32,
    pub sealed_boundary_retired: bool,
    pub wrapper_status: i32,
    pub target_status: Option<u32>,
    pub terminal: Schema8TerminalV1,
    pub native_predicates: BTreeMap<String, bool>,
}

/// Derives the normalized projection from a strict raw rc.23 execution report.
///
/// # Errors
///
/// Returns an error unless the raw report semantically proves one exact,
/// non-restarted, fully retired sealed attempt for the expected native argv.
#[allow(clippy::too_many_lines)]
pub fn project_schema8_report(
    bytes: &[u8],
    expected_mechanism: &str,
    expected_target_argv: &[NativeArgument],
) -> Result<Schema8ProjectionV1, ContractError> {
    let wire = validate_schema8_wire(bytes)?;
    validate_closed_load_bearing_wire(&wire, expected_mechanism)?;
    let report: MemcordonReport = serde_json::from_slice(bytes)
        .map_err(|error| ContractError::new(format!("invalid rc.23 report semantics: {error}")))?;
    if report.tool.name != "memcordon"
        || report.tool.version != crate::MEMCORDON_VERSION
        || report.policy.requested.boundary != BoundaryRequirement::Sealed
        || report.policy.effective.boundary != BoundaryClass::Sealed
        || report.error.is_some()
    {
        return Err(ContractError::new(
            "raw report release or sealed policy binding is invalid",
        ));
    }
    validate_fixed_invocation_policy(&report)?;
    let backend = report
        .backend
        .as_ref()
        .ok_or_else(|| ContractError::new("raw report omits sealed backend evidence"))?;
    if backend.boundary.class != BoundaryClass::Sealed
        || backend.boundary.mechanism != expected_mechanism
        || !backend.boundary.target_gated
        || !backend.boundary.boundary_verified_before_authorization
        || backend.boundary.target_can_reconfigure_boundary
        || !backend.boundary.frontend_loss_cleanup_authority
        || !backend.boundary.workload_empty_proof
    {
        return Err(ContractError::new(
            "sealed backend capability facts are invalid",
        ));
    }
    let target_argv = report
        .invocation
        .argv
        .iter()
        .map(|argument| NativeArgument {
            display: argument.display.clone(),
            raw: argument.raw.as_ref().map(|raw| crate::NativeArgumentRaw {
                encoding: raw.encoding.clone(),
                data: raw.data.clone(),
            }),
        })
        .collect::<Vec<_>>();
    if target_argv != expected_target_argv {
        return Err(ContractError::new(
            "raw report native argv differs from authority",
        ));
    }
    for argument in &target_argv {
        argument.validate().map_err(ContractError::new)?;
    }
    let supervision = report
        .supervision
        .as_ref()
        .ok_or_else(|| ContractError::new("raw report omits supervision result"))?;
    if supervision.phase != SupervisionPhase::Completed
        || supervision.attempt_records_created != 1
        || supervision.targets_authorized != 1
        || supervision.attempt_history.total != 1
        || supervision.attempt_history.retained != 1
        || supervision.attempt_history.omitted != 0
        || supervision.attempt_history.truncated
        || supervision.restart.enabled()
        || supervision.restart.restarts_launched() != 0
        || report.attempts.len() != 1
    {
        return Err(ContractError::new(
            "raw report does not contain exactly one non-restarted attempt",
        ));
    }
    let attempt = &report.attempts[0];
    let launch = &attempt.launch;
    if attempt.number != 1
        || attempt.phase != memcordon_core::AttemptPhase::Completed
        || attempt.error.is_some()
        || !launch.target_released
        || !launch.containment_verified_before_authorization
        || !launch.guardian_started_before_authorization
        || !launch.target_spawn_error_reported
        || launch.boundary_requested != BoundaryRequirement::Sealed
        || launch.boundary_effective != BoundaryClass::Sealed
        || !launch.boundary_assignment_verified
        || !launch.boundary_reconfiguration_denied
        || !launch.inherited_resources_restricted
        || !launch.frontend_loss_cleanup_authority_verified
    {
        return Err(ContractError::new(
            "generic sealed launch evidence is invalid",
        ));
    }
    let retirement = &attempt.restart_safety;
    if !retirement.direct_child_reaped
        || retirement.workload_empty != Some(true)
        || !retirement.helpers_reaped
        || !(retirement.containment_removed || retirement.containment_incapable_of_live_members)
        || !retirement.sealed_boundary_retired
        || !retirement.errors.is_empty()
    {
        return Err(ContractError::new(
            "sealed retirement evidence is incomplete",
        ));
    }
    let mut native_predicates = BTreeMap::new();
    validate_native_evidence(
        &attempt.boundary_detail,
        expected_mechanism,
        &mut native_predicates,
    )?;
    let terminal = match attempt.outcome.as_ref() {
        Some(RunOutcome::Exited {
            child: ChildTermination::ExitCode { code },
            ..
        }) => Schema8TerminalV1::CandidateExit {
            native_status: u32::try_from(*code).map_err(|_| {
                ContractError::new("candidate exit code is outside the native unsigned range")
            })?,
        },
        Some(RunOutcome::Exited {
            child: ChildTermination::WindowsStatus { status },
            ..
        }) => Schema8TerminalV1::CandidateExit {
            native_status: *status,
        },
        Some(RunOutcome::Exited {
            child: ChildTermination::UnixSignal { signal },
            ..
        }) if *signal > 0 => Schema8TerminalV1::CandidateSignal {
            signal: u32::try_from(*signal)
                .map_err(|_| ContractError::new("candidate signal is outside native range"))?,
        },
        Some(RunOutcome::DeadlineExceeded { deadline, .. })
            if deadline.scope() == DeadlineScope::Attempt =>
        {
            Schema8TerminalV1::InnerDeadline
        }
        Some(RunOutcome::LimitExceeded { .. }) => {
            return Err(ContractError::new(
                "memory-limit outcome contradicts the no-memory-budget policy",
            ));
        }
        Some(
            RunOutcome::Interrupted { .. }
            | RunOutcome::MonitorFailed { .. }
            | RunOutcome::Exited {
                child: ChildTermination::Unavailable | ChildTermination::UnixSignal { .. },
                ..
            }
            | RunOutcome::DeadlineExceeded { .. },
        )
        | None => {
            return Err(ContractError::new(
                "raw report does not contain an admissible candidate terminal outcome",
            ));
        }
    };
    let target_status = match &terminal {
        Schema8TerminalV1::CandidateExit { native_status } => Some(*native_status),
        Schema8TerminalV1::CandidateSignal { .. } | Schema8TerminalV1::InnerDeadline => None,
    };
    let projection = Schema8ProjectionV1 {
        schema_version: EXECUTION_SCHEMA,
        tool_version: report.tool.version,
        requested_boundary: "sealed".to_owned(),
        effective_boundary: "sealed".to_owned(),
        mechanism: expected_mechanism.to_owned(),
        target_argv,
        attempt_count: 1,
        restart_count: 0,
        sealed_boundary_retired: true,
        wrapper_status: supervision.wrapper_exit_code,
        target_status,
        terminal,
        native_predicates,
    };
    projection.validate()?;
    Ok(projection)
}

fn validate_fixed_invocation_policy(report: &MemcordonReport) -> Result<(), ContractError> {
    let invocation = &report.invocation;
    let requested = &report.policy.requested;
    let effective = &report.policy.effective;
    let Some(deadline_token) = invocation.deadline_token.as_deref() else {
        return Err(ContractError::new(
            "sealed invocation omits its +TIME budget",
        ));
    };
    let deadline_millis = deadline_token
        .strip_prefix('+')
        .and_then(|value| value.strip_suffix("ms"))
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| ContractError::new("sealed invocation has an invalid +TIME budget"))?;
    if invocation.syntax != "plus-budgets-v1"
        || invocation.memory_token.is_some()
        || invocation.budget_tokens.len() != 1
        || invocation.budget_tokens[0].kind != BudgetKindReport::Time
        || invocation.budget_tokens[0].token != deadline_token
        || requested.memory.is_some()
        || effective.memory.is_some()
        || requested.wait_for != "command"
        || effective.wait_for != "command"
        || requested.command_exit_grace_ms != 0
        || effective.command_exit_grace_ms != 0
        || requested.restart.enabled
        || effective.restart.enabled
    {
        return Err(ContractError::new(
            "raw report policy differs from the fixed no-memory/no-restart command policy",
        ));
    }
    let requested_deadline = requested
        .deadline
        .as_ref()
        .ok_or_else(|| ContractError::new("requested deadline policy is absent"))?;
    let effective_deadline = effective
        .deadline
        .as_ref()
        .ok_or_else(|| ContractError::new("effective deadline policy is absent"))?;
    if requested_deadline.duration_ms != deadline_millis
        || effective_deadline.duration_ms != deadline_millis
        || requested_deadline.scope != DeadlineScope::Attempt
        || effective_deadline.scope != DeadlineScope::Attempt
    {
        return Err(ContractError::new(
            "raw report deadline policy differs from its +TIME token",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_native_evidence(
    detail: &BoundaryMechanismEvidence,
    expected: &str,
    predicates: &mut BTreeMap<String, bool>,
) -> Result<(), ContractError> {
    let insert = |predicates: &mut BTreeMap<String, bool>, name: &str, value: bool| {
        predicates.insert(name.to_owned(), value);
    };
    match detail {
        BoundaryMechanismEvidence::LinuxPidNamespaceCgroupV2(evidence)
            if expected == "linux-pid-namespace-cgroup-v2" =>
        {
            if evidence.schema_version != 2
                || evidence.provider_identity.is_empty()
                || evidence.control_service_identity.is_empty()
                || evidence.launcher_service_identity.is_empty()
                || evidence.credential_transition_disposition
                    != CredentialTransitionDisposition::PreserveCallerEnvelope
            {
                return Err(ContractError::new(
                    "Linux sealed identity evidence is invalid",
                ));
            }
            for (name, value) in [
                ("cgroup_created", evidence.cgroup_created),
                (
                    "cgroup_owned_by_provider",
                    evidence.cgroup_owned_by_provider,
                ),
                (
                    "memory_configuration_verified",
                    evidence.memory_configuration_verified,
                ),
                (
                    "init_created_into_cgroup",
                    evidence.init_created_into_cgroup,
                ),
                ("pid_namespace_created", evidence.pid_namespace_created),
                ("mount_namespace_created", evidence.mount_namespace_created),
                (
                    "cgroup_namespace_created",
                    evidence.cgroup_namespace_created,
                ),
                ("target_pidfd_verified", evidence.target_pidfd_verified),
                (
                    "target_cgroup_membership_verified",
                    evidence.target_cgroup_membership_verified,
                ),
                (
                    "target_pid_namespace_verified",
                    evidence.target_pid_namespace_verified,
                ),
                (
                    "target_initial_credentials_verified",
                    evidence.target_initial_credentials_verified,
                ),
                (
                    "initial_provider_capabilities_absent",
                    evidence.initial_provider_capabilities_absent,
                ),
                (
                    "caller_no_new_privs_reproduced",
                    evidence.caller_no_new_privs_reproduced,
                ),
                (
                    "caller_capability_bounding_set_reproduced",
                    evidence.caller_capability_bounding_set_reproduced,
                ),
                (
                    "caller_mount_context_reproduced",
                    evidence.caller_mount_context_reproduced,
                ),
                (
                    "boundary_independent_of_credentials",
                    evidence.boundary_independent_of_credentials,
                ),
                (
                    "inherited_descriptors_verified",
                    evidence.inherited_descriptors_verified,
                ),
                (
                    "writable_ancestor_cgroup_denied",
                    evidence.writable_ancestor_cgroup_denied,
                ),
                (
                    "parent_namespace_handles_denied",
                    evidence.parent_namespace_handles_denied,
                ),
                (
                    "recursive_provider_request_denied",
                    evidence.recursive_provider_request_denied,
                ),
                ("guardian_ready", evidence.guardian_ready),
                ("target_released", evidence.target_released),
                ("cgroup_kill_invoked", evidence.cgroup_kill_invoked),
                ("cgroup_empty_verified", evidence.cgroup_empty_verified),
                ("namespace_init_reaped", evidence.namespace_init_reaped),
                ("guardian_reaped", evidence.guardian_reaped),
                ("cgroup_removed", evidence.cgroup_removed),
            ] {
                insert(predicates, name, value);
            }
        }
        BoundaryMechanismEvidence::WindowsJobObjectV2(evidence)
            if expected == "windows-job-object-v2" =>
        {
            if evidence.schema_version != 2
                || evidence.service_identity.is_empty()
                || evidence.credential_transition_disposition
                    != CredentialTransitionDisposition::PreserveCallerEnvelope
                || matches!(
                    evidence.loader_qualification,
                    Some(WindowsLoaderQualificationOutcomeV2::Failed(_))
                )
            {
                return Err(ContractError::new(
                    "Windows sealed identity evidence is invalid",
                ));
            }
            for (name, value) in [
                (
                    "caller_token_authenticated",
                    evidence.caller_token_authenticated,
                ),
                (
                    "initial_target_token_matches_caller",
                    evidence.initial_target_token_matches_caller,
                ),
                (
                    "job_membership_independent_of_token",
                    evidence.job_membership_independent_of_token,
                ),
                ("job_created", evidence.job_created),
                ("job_limits_verified", evidence.job_limits_verified),
                ("kill_on_close_verified", evidence.kill_on_close_verified),
                ("breakaway_denied", evidence.breakaway_denied),
                (
                    "completion_port_associated",
                    evidence.completion_port_associated,
                ),
                ("guardian_ready", evidence.guardian_ready),
                (
                    "target_created_suspended",
                    evidence.target_created_suspended,
                ),
                (
                    "job_list_applied_at_creation",
                    evidence.job_list_applied_at_creation,
                ),
                (
                    "handle_list_applied_at_creation",
                    evidence.handle_list_applied_at_creation,
                ),
                (
                    "target_job_membership_verified",
                    evidence.target_job_membership_verified,
                ),
                (
                    "target_still_suspended_during_verification",
                    evidence.target_still_suspended_during_verification,
                ),
                (
                    "inherited_handles_verified",
                    evidence.inherited_handles_verified,
                ),
                ("target_released", evidence.target_released),
                ("terminate_job_invoked", evidence.terminate_job_invoked),
                ("active_processes_zero", evidence.active_processes_zero),
                ("direct_target_reaped", evidence.direct_target_reaped),
                ("relays_retired", evidence.relays_retired),
                ("guardian_reaped", evidence.guardian_reaped),
                (
                    "final_job_handles_closed",
                    evidence.final_job_handles_closed,
                ),
            ] {
                insert(predicates, name, value);
            }
        }
        _ => {
            return Err(ContractError::new(
                "raw report mechanism differs from authority",
            ));
        }
    }
    if predicates.values().any(|value| !value) {
        return Err(ContractError::new("native sealed predicate is false"));
    }
    Ok(())
}

fn validate_closed_load_bearing_wire(value: &Value, mechanism: &str) -> Result<(), ContractError> {
    let root = require_object(value, "report")?;
    require_exact_keys(
        root,
        &[
            "schema_version",
            "tool",
            "invocation",
            "policy",
            "backend",
            "supervision",
            "attempts",
            "error",
        ],
        "report",
    )?;
    require_exact_keys(
        require_object(&root["tool"], "tool")?,
        &["name", "version"],
        "tool",
    )?;
    require_exact_keys(
        require_object(&root["invocation"], "invocation")?,
        &[
            "syntax",
            "budget_tokens",
            "memory_token",
            "deadline_token",
            "argv",
        ],
        "invocation",
    )?;
    let attempts = root["attempts"]
        .as_array()
        .ok_or_else(|| ContractError::new("attempts is not an array"))?;
    if attempts.len() != 1 {
        return Err(ContractError::new(
            "report must contain exactly one attempt",
        ));
    }
    let attempt = require_object(&attempts[0], "attempt")?;
    require_exact_keys(
        attempt,
        &[
            "number",
            "kind",
            "phase",
            "target_pid",
            "started_offset_ms",
            "authorized_offset_ms",
            "terminal_offset_ms",
            "finished_offset_ms",
            "outcome",
            "error",
            "restart_decision",
            "launch",
            "restart_safety",
            "boundary_detail",
        ],
        "attempt",
    )?;
    require_exact_keys(
        require_object(&attempt["launch"], "launch")?,
        &[
            "mechanism",
            "target_released",
            "containment_verified_before_authorization",
            "guardian_started_before_authorization",
            "target_spawn_error_reported",
            "boundary_requested",
            "boundary_effective",
            "boundary_assignment_verified",
            "boundary_reconfiguration_denied",
            "inherited_resources_restricted",
            "frontend_loss_cleanup_authority_verified",
        ],
        "launch",
    )?;
    require_exact_keys(
        require_object(&attempt["restart_safety"], "restart_safety")?,
        &[
            "direct_child_reaped",
            "workload_empty",
            "helpers_reaped",
            "containment_removed",
            "containment_incapable_of_live_members",
            "sealed_boundary_retired",
            "errors",
        ],
        "restart_safety",
    )?;
    let detail = require_object(&attempt["boundary_detail"], "boundary_detail")?;
    if detail.get("mechanism").and_then(Value::as_str) != Some(mechanism) {
        return Err(ContractError::new("boundary detail mechanism differs"));
    }
    Ok(())
}

fn require_object<'a>(
    value: &'a Value,
    label: &str,
) -> Result<&'a serde_json::Map<String, Value>, ContractError> {
    value
        .as_object()
        .ok_or_else(|| ContractError::new(format!("{label} is not an object")))
}

fn require_exact_keys(
    object: &serde_json::Map<String, Value>,
    expected: &[&str],
    label: &str,
) -> Result<(), ContractError> {
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(ContractError::new(format!(
            "{label} has unknown or missing keys"
        )));
    }
    Ok(())
}

impl Schema8ProjectionV1 {
    /// Validates the normalized one-attempt sealed-retirement projection.
    ///
    /// # Errors
    ///
    /// Returns an error when a required release, boundary, or native fact fails.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != EXECUTION_SCHEMA
            || self.tool_version != crate::MEMCORDON_VERSION
            || self.requested_boundary != "sealed"
            || self.effective_boundary != "sealed"
            || self.attempt_count != 1
            || self.restart_count != 0
            || !self.sealed_boundary_retired
        {
            return Err(ContractError::new(
                "schema-8 projection does not prove one retired sealed attempt",
            ));
        }
        let (encoding, predicates) = match self.mechanism.as_str() {
            "linux-pid-namespace-cgroup-v2" => ("unix-bytes-base64", LINUX_NATIVE_PREDICATES),
            "windows-job-object-v2" => ("windows-u16le-base64", WINDOWS_NATIVE_PREDICATES),
            _ => return Err(ContractError::new("unsupported sealed mechanism")),
        };
        if self.target_argv.is_empty() {
            return Err(ContractError::new("schema-8 projection omits target argv"));
        }
        match (&self.terminal, self.target_status) {
            (Schema8TerminalV1::CandidateExit { native_status }, Some(projected_status))
                if *native_status == projected_status => {}
            (Schema8TerminalV1::CandidateSignal { signal }, None) if *signal != 0 => {}
            (Schema8TerminalV1::InnerDeadline, None) => {}
            _ => {
                return Err(ContractError::new(
                    "schema-8 terminal provenance disagrees with target status",
                ));
            }
        }
        for argument in &self.target_argv {
            argument.validate().map_err(ContractError::new)?;
            if argument
                .raw
                .as_ref()
                .is_some_and(|raw| raw.encoding != encoding)
            {
                return Err(ContractError::new(
                    "native argument encoding differs from sealed mechanism",
                ));
            }
        }
        if self.native_predicates.len() != predicates.len()
            || predicates
                .iter()
                .any(|name| self.native_predicates.get(*name) != Some(&true))
        {
            return Err(ContractError::new(
                "native retirement predicate inventory is incomplete",
            ));
        }
        Ok(())
    }
}

/// Parses and validates one strict normalized schema-8 projection.
///
/// # Errors
///
/// Returns an error for invalid JSON, unknown fields, or failed semantic checks.
pub fn parse_schema8_projection(bytes: &[u8]) -> Result<Schema8ProjectionV1, ContractError> {
    validate_schema8_wire(bytes)?;
    let projection: Schema8ProjectionV1 = serde_json::from_slice(bytes).map_err(|error| {
        ContractError::new(format!("invalid strict schema-8 projection: {error}"))
    })?;
    projection.validate()?;
    Ok(projection)
}

/// Parses JSON with duplicate-key/depth/size rejection and verifies schema 8.
///
/// # Errors
///
/// Returns an error for malformed, oversized, deeply nested, duplicated, or wrong-schema JSON.
pub fn validate_schema8_wire(bytes: &[u8]) -> Result<Value, ContractError> {
    if bytes.len() > MAX_EXECUTION_REPORT_BYTES {
        return Err(ContractError::new(
            "MemCordon report exceeds consumer bound",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValueSeed { depth: 0 }
        .deserialize(&mut deserializer)
        .map_err(|error| ContractError::new(format!("invalid strict report JSON: {error}")))?;
    deserializer
        .end()
        .map_err(|error| ContractError::new(format!("trailing report data: {error}")))?;
    let schema = value
        .as_object()
        .and_then(|object| object.get("schema_version"))
        .and_then(Value::as_u64)
        .ok_or_else(|| ContractError::new("report omits integer schema_version"))?;
    if schema != u64::from(EXECUTION_SCHEMA) {
        return Err(ContractError::new("report is not execution schema 8"));
    }
    Ok(value)
}

struct StrictValueSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        if self.depth > MAX_JSON_DEPTH {
            return Err(D::Error::custom("JSON nesting exceeds consumer bound"));
        }
        deserializer.deserialize_any(StrictValueVisitor { depth: self.depth })
    }
}

struct StrictValueVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictValueSeed { depth: self.depth }.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictValueSeed {
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom(format!("duplicate JSON key {key}")));
            }
            let value = map.next_value_seed(StrictValueSeed {
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
