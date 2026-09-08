use hell_release_verifier::{
    ExpectedMemcordonFinalization, ExpectedMemcordonReport, ExpectedNativeArgument,
    ExpectedTermination, MemcordonFinalizationDocuments, MemcordonPlatform,
    independent_sha256_for_test, validate_memcordon_rc23_finalization,
    validate_memcordon_rc23_projection, validate_memcordon_rc23_report,
};

const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const GENUINE_LINUX_EXIT_123: &[u8] =
    include_bytes!("../../../fixtures/memcordon-rc23/schema8-linux-exit-123.json");

fn sha256(bytes: &[u8]) -> String {
    independent_sha256_for_test(bytes)
}

fn expected(
    platform: MemcordonPlatform,
    termination: ExpectedTermination,
) -> ExpectedMemcordonReport {
    ExpectedMemcordonReport {
        platform,
        argv: vec![ExpectedNativeArgument {
            display: match platform {
                MemcordonPlatform::LinuxX86_64 => "/opt/hell/bin/candidate".to_owned(),
                MemcordonPlatform::WindowsX86_64 => "C:\\hell\\candidate.exe".to_owned(),
            },
            raw_encoding: None,
            raw_data: None,
        }],
        deadline_token: "+60000ms".to_owned(),
        termination,
    }
}

fn linux_native() -> &'static str {
    r#"{
      "mechanism":"linux-pid-namespace-cgroup-v2",
      "schema_version":2,
      "provider_identity":"memcordon-sealed-agent-v2",
      "control_service_identity":"memcordon-sealed-agent.service:v2",
      "launcher_service_identity":"memcordon-sealed-launcher.service:v2",
      "cgroup_identity_digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "cgroup_created":true,
      "cgroup_owned_by_provider":true,
      "memory_configuration_verified":true,
      "init_created_into_cgroup":true,
      "pid_namespace_created":true,
      "mount_namespace_created":true,
      "cgroup_namespace_created":true,
      "target_pidfd_verified":true,
      "target_cgroup_membership_verified":true,
      "target_pid_namespace_verified":true,
      "target_initial_credentials_verified":true,
      "initial_provider_capabilities_absent":true,
      "caller_no_new_privs_reproduced":true,
      "caller_capability_bounding_set_reproduced":true,
      "caller_mount_context_reproduced":true,
      "credential_transition_disposition":"preserve-caller-envelope",
      "boundary_independent_of_credentials":true,
      "inherited_descriptors_verified":true,
      "writable_ancestor_cgroup_denied":true,
      "parent_namespace_handles_denied":true,
      "recursive_provider_request_denied":true,
      "guardian_ready":true,
      "target_released":true,
      "cgroup_kill_invoked":true,
      "cgroup_empty_verified":true,
      "namespace_init_reaped":true,
      "guardian_reaped":true,
      "cgroup_removed":true
    }"#
}

fn windows_native() -> &'static str {
    r#"{
      "mechanism":"windows-job-object-v2",
      "schema_version":2,
      "service_identity":"MemCordonSealedControl+MemCordonSealedLauncher:v1",
      "caller_token_authenticated":true,
      "initial_target_token_matches_caller":true,
      "credential_transition_disposition":"preserve-caller-envelope",
      "job_membership_independent_of_token":true,
      "job_created":true,
      "job_limits_verified":true,
      "kill_on_close_verified":true,
      "breakaway_denied":true,
      "completion_port_associated":true,
      "guardian_ready":true,
      "target_created_suspended":true,
      "job_list_applied_at_creation":true,
      "handle_list_applied_at_creation":true,
      "target_job_membership_verified":true,
      "target_still_suspended_during_verification":true,
      "inherited_handles_verified":true,
      "target_released":true,
      "terminate_job_invoked":true,
      "active_processes_zero":true,
      "direct_target_reaped":true,
      "relays_retired":true,
      "guardian_reaped":true,
      "final_job_handles_closed":true
    }"#
}

fn report(platform: MemcordonPlatform, termination: ExpectedTermination) -> Vec<u8> {
    let (program, native) = match platform {
        MemcordonPlatform::LinuxX86_64 => ("/opt/hell/bin/candidate", linux_native()),
        MemcordonPlatform::WindowsX86_64 => ("C:\\\\hell\\\\candidate.exe", windows_native()),
    };
    let (child, wrapper) = match termination {
        ExpectedTermination::ExitCode(code) => {
            (format!(r#"{{"kind":"exit-code","code":{code}}}"#), code)
        }
        ExpectedTermination::UnixSignal(signal) => (
            format!(r#"{{"kind":"unix-signal","signal":{signal}}}"#),
            128 + signal,
        ),
        ExpectedTermination::WindowsStatus(status) => (
            format!(r#"{{"kind":"windows-status","status":{status}}}"#),
            if status > i32::MAX as u32 {
                125
            } else {
                status
            },
        ),
    };
    let outcome = format!(
        r#"{{"outcome":"exited","child":{child},"peak":null,"cleanup":{{"graceful_attempted":false,"force_attempted":true,"direct_child_reaped":true,"workload_empty":true,"errors":[]}}}}"#
    );
    let template = r#"{
      "schema_version":8,
      "tool":{"name":"memcordon","version":"0.5.2-rc.23"},
      "invocation":{"syntax":"plus-budgets-v1","budget_tokens":[{"kind":"time","token":"+60000ms"}],"memory_token":null,"deadline_token":"+60000ms","argv":[{"display":"@PROGRAM@","raw":null}]},
      "policy":{
        "requested":{"boundary":"sealed","memory":null,"deadline":{"duration_ms":60000,"scope":"attempt","origin":"authorization","clock":"monotonic"},"wait_for":"command","signal_grace_ms":2000,"command_exit_grace_ms":0,"limit_grace_ms":2000,"restart":{"enabled":false,"enablement_source":null,"configured_conditions":[],"limit":{"kind":"count","count":1},"backoff":null,"circuit_breaker":null}},
        "effective":{"boundary":"sealed","memory":null,"deadline":{"duration_ms":60000,"scope":"attempt","origin":"authorization","clock":"monotonic"},"wait_for":"command","signal_grace_ms":2000,"command_exit_grace_ms":0,"limit_grace_ms":2000,"restart":{"enabled":false,"conditions":[],"dormant_conditions":[],"cleanup_proof_required":false}},
        "effects":[]
      },
      "backend":{"name":"sealed","containment":{"supported":true,"reason":null},"boundary":{"class":"sealed","mechanism":"@MECHANISM@","target_gated":true,"boundary_verified_before_authorization":true,"target_can_reconfigure_boundary":false,"frontend_loss_cleanup_authority":true,"workload_empty_proof":true,"limitations":[]},"memory":null,"deadline":{"supported":true,"reason":null},"restart":{"supported":true,"reason":null},"deadline_scopes":["attempt"],"deadline_origin":"authorization","restart_conditions":[],"persistent_restart_state":false,"startup_containment":"verified","restart_cleanup_condition":"empty","limitations":[],"boundary_qualification":{"provider_identity":"memcordon-sealed-agent-v2","receipt_digest":"@DIGEST@","mechanism":"@MECHANISM@"}},
      "supervision":{"phase":"completed","duration_ms":20,"attempt_records_created":1,"targets_authorized":1,"wrapper_exit_code":@WRAPPER@,"terminal":{"kind":"attempt-outcome","attempt_number":1,"outcome":@OUTCOME@},"attempt_history":{"capacity":256,"retained":1,"total":1,"omitted":0,"truncated":false},"aggregate":{"child_exits":1,"memory_limits":0,"deadlines":0,"interruptions":0,"monitor_failures":0,"setup_failures":0,"max_peak":null},"restart":{"enabled":false,"restarts_launched":0,"restart_limit_exhausted":false,"half_life_logistic_waits":0,"cooldowns":0,"circuit_open_count":0,"final_circuit_state":"closed"}},
      "attempts":[{"number":1,"kind":"initial","phase":"completed","target_pid":42,"started_offset_ms":1,"authorized_offset_ms":2,"terminal_offset_ms":10,"finished_offset_ms":20,"outcome":@OUTCOME@,"error":null,"restart_decision":{"trigger":null,"decision":"none-disabled","restart_number":null,"half_life_logistic_sequence_index":null,"configured_wait_ms":null,"actual_wait_ms":null,"wait_kind":null,"circuit_state":"closed","supervision_deadline_truncated_wait":false},"launch":{"mechanism":"@MECHANISM@","target_released":true,"containment_verified_before_authorization":true,"guardian_started_before_authorization":true,"target_spawn_error_reported":true,"boundary_requested":"sealed","boundary_effective":"sealed","boundary_assignment_verified":true,"boundary_reconfiguration_denied":true,"inherited_resources_restricted":true,"frontend_loss_cleanup_authority_verified":true},"restart_safety":{"direct_child_reaped":true,"workload_empty":true,"helpers_reaped":true,"containment_removed":true,"containment_incapable_of_live_members":false,"sealed_boundary_retired":true,"errors":[]},"boundary_detail":@NATIVE@}],
      "error":null
    }
"#;
    template
        .replace("@PROGRAM@", program)
        .replace("@MECHANISM@", platform.mechanism_for_test())
        .replace("@DIGEST@", DIGEST)
        .replace("@WRAPPER@", &wrapper.to_string())
        .replace("@OUTCOME@", &outcome)
        .replace("@NATIVE@", native)
        .into_bytes()
}

trait PlatformTestName {
    fn mechanism_for_test(self) -> &'static str;
}

impl PlatformTestName for MemcordonPlatform {
    fn mechanism_for_test(self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "linux-pid-namespace-cgroup-v2",
            Self::WindowsX86_64 => "windows-job-object-v2",
        }
    }
}

fn projection(platform: MemcordonPlatform, target_status: u32, wrapper_status: u32) -> Vec<u8> {
    let (program, predicates) = match platform {
        MemcordonPlatform::LinuxX86_64 => (
            "/opt/hell/bin/candidate",
            r#""boundary_independent_of_credentials":true,"caller_capability_bounding_set_reproduced":true,"caller_mount_context_reproduced":true,"caller_no_new_privs_reproduced":true,"cgroup_created":true,"cgroup_empty_verified":true,"cgroup_kill_invoked":true,"cgroup_namespace_created":true,"cgroup_owned_by_provider":true,"cgroup_removed":true,"guardian_ready":true,"guardian_reaped":true,"inherited_descriptors_verified":true,"init_created_into_cgroup":true,"initial_provider_capabilities_absent":true,"memory_configuration_verified":true,"mount_namespace_created":true,"namespace_init_reaped":true,"parent_namespace_handles_denied":true,"pid_namespace_created":true,"recursive_provider_request_denied":true,"target_cgroup_membership_verified":true,"target_initial_credentials_verified":true,"target_pid_namespace_verified":true,"target_pidfd_verified":true,"target_released":true,"writable_ancestor_cgroup_denied":true"#,
        ),
        MemcordonPlatform::WindowsX86_64 => (
            "C:\\\\hell\\\\candidate.exe",
            r#""active_processes_zero":true,"breakaway_denied":true,"caller_token_authenticated":true,"completion_port_associated":true,"direct_target_reaped":true,"final_job_handles_closed":true,"guardian_ready":true,"guardian_reaped":true,"handle_list_applied_at_creation":true,"inherited_handles_verified":true,"initial_target_token_matches_caller":true,"job_created":true,"job_limits_verified":true,"job_list_applied_at_creation":true,"job_membership_independent_of_token":true,"kill_on_close_verified":true,"relays_retired":true,"target_created_suspended":true,"target_job_membership_verified":true,"target_released":true,"target_still_suspended_during_verification":true,"terminate_job_invoked":true"#,
        ),
    };
    format!(
        "{{\"schema_version\":8,\"tool_version\":\"0.5.2-rc.23\",\"requested_boundary\":\"sealed\",\"effective_boundary\":\"sealed\",\"mechanism\":\"{}\",\"target_argv\":[{{\"display\":\"{program}\",\"raw\":null}}],\"attempt_count\":1,\"restart_count\":0,\"sealed_boundary_retired\":true,\"wrapper_status\":{wrapper_status},\"target_status\":{target_status},\"terminal\":{{\"kind\":\"candidate_exit\",\"native_status\":{target_status}}},\"native_predicates\":{{{predicates}}}}}\n",
        platform.mechanism_for_test(),
    )
    .into_bytes()
}

#[test]
fn independent_parser_accepts_linux_reserved_exit_as_candidate_status() {
    let expected = expected(
        MemcordonPlatform::LinuxX86_64,
        ExpectedTermination::ExitCode(123),
    );
    let validated = validate_memcordon_rc23_report(GENUINE_LINUX_EXIT_123, &expected)
        .expect("ordinary candidate exit 123 with complete retirement must be valid evidence");
    assert_eq!(validated.wrapper_exit_code, 123);
    assert_eq!(validated.mechanism, "linux-pid-namespace-cgroup-v2");
}

#[test]
fn independent_parser_preserves_wide_windows_native_status() {
    let status = 0xc000_0005;
    let expected = expected(
        MemcordonPlatform::WindowsX86_64,
        ExpectedTermination::WindowsStatus(status),
    );
    let validated = validate_memcordon_rc23_report(
        &report(
            MemcordonPlatform::WindowsX86_64,
            ExpectedTermination::WindowsStatus(status),
        ),
        &expected,
    )
    .expect("wide Windows status must retain candidate provenance");
    assert_eq!(validated.wrapper_exit_code, 125);
    assert_eq!(validated.mechanism, "windows-job-object-v2");
}

#[test]
fn independent_parser_rejects_unknown_fields_and_missing_retirement() {
    let linux_expected = expected(
        MemcordonPlatform::LinuxX86_64,
        ExpectedTermination::ExitCode(0),
    );
    let valid = String::from_utf8(report(
        MemcordonPlatform::LinuxX86_64,
        ExpectedTermination::ExitCode(0),
    ))
    .expect("fixture is UTF-8");
    let unknown = valid.replace(
        "\"schema_version\":8,",
        "\"schema_version\":8,\"future_field\":true,",
    );
    assert!(validate_memcordon_rc23_report(unknown.as_bytes(), &linux_expected).is_err());

    let unretired = valid.replace(
        "\"sealed_boundary_retired\":true",
        "\"sealed_boundary_retired\":false",
    );
    assert!(validate_memcordon_rc23_report(unretired.as_bytes(), &linux_expected).is_err());
}

#[test]
fn independent_parser_binds_exact_native_argv_and_mechanism() {
    let linux_expected = expected(
        MemcordonPlatform::LinuxX86_64,
        ExpectedTermination::ExitCode(0),
    );
    let valid = report(
        MemcordonPlatform::LinuxX86_64,
        ExpectedTermination::ExitCode(0),
    );
    let wrong_argv = String::from_utf8(valid.clone())
        .expect("fixture is UTF-8")
        .replace("/opt/hell/bin/candidate", "/tmp/substituted");
    assert!(validate_memcordon_rc23_report(wrong_argv.as_bytes(), &linux_expected).is_err());

    let wrong_platform = expected(
        MemcordonPlatform::WindowsX86_64,
        ExpectedTermination::ExitCode(0),
    );
    assert!(validate_memcordon_rc23_report(&valid, &wrong_platform).is_err());
}

#[test]
fn independent_projection_must_equal_raw_report_and_closed_predicates() {
    let expected = expected(
        MemcordonPlatform::WindowsX86_64,
        ExpectedTermination::WindowsStatus(7),
    );
    let raw = report(
        MemcordonPlatform::WindowsX86_64,
        ExpectedTermination::WindowsStatus(7),
    );
    let normalized = projection(MemcordonPlatform::WindowsX86_64, 7, 7);
    validate_memcordon_rc23_projection(&raw, &normalized, &expected)
        .expect("independent projection must agree with the raw report");

    let false_predicate = String::from_utf8(normalized.clone())
        .expect("projection fixture is UTF-8")
        .replace("\"breakaway_denied\":true", "\"breakaway_denied\":false");
    assert!(
        validate_memcordon_rc23_projection(&raw, false_predicate.as_bytes(), &expected).is_err()
    );

    let wrong_status = String::from_utf8(normalized)
        .expect("projection fixture is UTF-8")
        .replace("\"target_status\":7", "\"target_status\":8");
    assert!(validate_memcordon_rc23_projection(&raw, wrong_status.as_bytes(), &expected).is_err());

    let normalized = projection(MemcordonPlatform::WindowsX86_64, 7, 7);
    let wrong_terminal = String::from_utf8(normalized)
        .expect("projection fixture is UTF-8")
        .replace("\"native_status\":7", "\"native_status\":124");
    assert!(
        validate_memcordon_rc23_projection(&raw, wrong_terminal.as_bytes(), &expected).is_err()
    );
}

#[test]
fn independent_projection_keeps_candidate_exit_124_distinct_from_inner_deadline() {
    let expected = expected(
        MemcordonPlatform::LinuxX86_64,
        ExpectedTermination::ExitCode(124),
    );
    let raw = report(
        MemcordonPlatform::LinuxX86_64,
        ExpectedTermination::ExitCode(124),
    );
    let normalized = projection(MemcordonPlatform::LinuxX86_64, 124, 124);
    validate_memcordon_rc23_projection(&raw, &normalized, &expected)
        .expect("candidate exit 124 must retain candidate-exit provenance");

    let inner_deadline = String::from_utf8(normalized)
        .expect("projection fixture is UTF-8")
        .replace(
            "{\"kind\":\"candidate_exit\",\"native_status\":124}",
            "{\"kind\":\"inner_deadline\"}",
        );
    assert!(
        validate_memcordon_rc23_projection(&raw, inner_deadline.as_bytes(), &expected).is_err()
    );
}

#[test]
fn independent_finalizer_requires_cleanup_and_exact_operation_coverage() {
    let cleanup = "{\"schema_version\":1,\"provider_lease_id\":\"lease-1\",\"operation_id\":\"release\",\"platform\":\"linux-x86-64\",\"attempted\":true,\"final_state\":\"removed\",\"installed_footprint_absent\":true,\"active_operations\":0,\"failure\":null}\n".to_owned();
    let operations = format!(
        "[{{\"operation_id\":\"compile\",\"boundary\":\"sealed-linux\",\"request_digest\":\"{DIGEST}\",\"raw_report_path\":\"raw/compile.json\",\"raw_report_digest\":\"{DIGEST}\",\"normalized_report_path\":\"normalized/compile.json\",\"normalized_report_digest\":\"{DIGEST}\",\"identity_adapter_path\":null,\"identity_adapter_digest\":null,\"terminal\":{{\"kind\":\"ordinary_result\"}}}}]\n"
    );
    let cleanup_digest = sha256(cleanup.as_bytes());
    let operations_digest = sha256(operations.as_bytes());
    let inventory = format!(
        "{DIGEST}  acquisition.json\n{DIGEST}  canaries.json\n{DIGEST}  doctor.json\n{DIGEST}  normalized/compile.json\n{operations_digest}  operations.json\n{DIGEST}  package-inspect.json\n{DIGEST}  package-verify.json\n{cleanup_digest}  provider-cleanup.json\n{DIGEST}  provider-lease.json\n{DIGEST}  publication-report.json\n{DIGEST}  raw/compile.json\n{DIGEST}  release-manifest.json\n{DIGEST}  runtime-manifest.json\n"
    );
    let finalization = format!(
        "{{\"schema_version\":1,\"platform\":\"linux-x86-64\",\"candidate_commit\":\"{COMMIT}\",\"workflow_commit\":\"{COMMIT}\",\"runtime_lock_digest\":\"{DIGEST}\",\"acquisition_digest\":\"{DIGEST}\",\"provider_lifecycle_digest\":\"{DIGEST}\",\"provider_cleanup_digest\":\"{}\",\"operations_digest\":\"{}\",\"inventory_digest\":\"{}\",\"required_operation_ids\":[\"compile\"],\"observed_operation_ids\":[\"compile\"],\"cleanup_succeeded\":true,\"admitted\":true,\"failure\":null}}\n",
        cleanup_digest,
        operations_digest,
        sha256(inventory.as_bytes()),
    );
    let expected = ExpectedMemcordonFinalization {
        platform: MemcordonPlatform::LinuxX86_64,
        candidate_commit: COMMIT.to_owned(),
        workflow_commit: COMMIT.to_owned(),
        runtime_lock_digest: DIGEST.to_owned(),
        provider_operation: "release".to_owned(),
        required_operation_ids: vec!["compile".to_owned()],
    };
    let documents = MemcordonFinalizationDocuments {
        finalization: finalization.as_bytes(),
        provider_cleanup: cleanup.as_bytes(),
        operations: operations.as_bytes(),
        inventory: inventory.as_bytes(),
    };
    let validated = validate_memcordon_rc23_finalization(documents, &expected)
        .expect("cleanup-aware exact platform finalization must be admitted");
    assert_eq!(validated.operation_count, 1);

    let active_cleanup = cleanup.replace("\"active_operations\":0", "\"active_operations\":1");
    assert!(
        validate_memcordon_rc23_finalization(
            MemcordonFinalizationDocuments {
                provider_cleanup: active_cleanup.as_bytes(),
                ..documents
            },
            &expected,
        )
        .is_err()
    );

    let missing = ExpectedMemcordonFinalization {
        required_operation_ids: vec!["compile".to_owned(), "test".to_owned()],
        ..expected.clone()
    };
    assert!(validate_memcordon_rc23_finalization(documents, &missing).is_err());

    let substituted_path = operations.replace("raw/compile.json", "raw/other.json");
    assert!(
        validate_memcordon_rc23_finalization(
            MemcordonFinalizationDocuments {
                operations: substituted_path.as_bytes(),
                ..documents
            },
            &expected,
        )
        .is_err()
    );

    let missing_raw = inventory.replace(&format!("{DIGEST}  raw/compile.json\n"), "");
    assert!(
        validate_memcordon_rc23_finalization(
            MemcordonFinalizationDocuments {
                inventory: missing_raw.as_bytes(),
                ..documents
            },
            &expected,
        )
        .is_err()
    );
}

#[test]
fn independent_finalizer_requires_inventory_bound_windows_adapter() {
    let cleanup = "{\"schema_version\":1,\"provider_lease_id\":\"lease-1\",\"operation_id\":\"release\",\"platform\":\"windows-x86-64\",\"attempted\":true,\"final_state\":\"removed\",\"installed_footprint_absent\":true,\"active_operations\":0,\"failure\":null}\n".to_owned();
    let operations = format!(
        "[{{\"operation_id\":\"compile\",\"boundary\":\"sealed-windows\",\"request_digest\":\"{DIGEST}\",\"raw_report_path\":\"raw/compile.json\",\"raw_report_digest\":\"{DIGEST}\",\"normalized_report_path\":\"normalized/compile.json\",\"normalized_report_digest\":\"{DIGEST}\",\"identity_adapter_path\":\"adapters/compile.json\",\"identity_adapter_digest\":\"{DIGEST}\",\"terminal\":{{\"kind\":\"ordinary_result\"}}}}]\n"
    );
    let cleanup_digest = sha256(cleanup.as_bytes());
    let operations_digest = sha256(operations.as_bytes());
    let inventory = format!(
        "{DIGEST}  acquisition.json\n{DIGEST}  adapters/compile.json\n{DIGEST}  canaries.json\n{DIGEST}  doctor.json\n{DIGEST}  normalized/compile.json\n{operations_digest}  operations.json\n{DIGEST}  package-inspect.json\n{DIGEST}  package-verify.json\n{cleanup_digest}  provider-cleanup.json\n{DIGEST}  provider-lease.json\n{DIGEST}  publication-report.json\n{DIGEST}  raw/compile.json\n{DIGEST}  release-manifest.json\n{DIGEST}  runtime-manifest.json\n"
    );
    let finalization = format!(
        "{{\"schema_version\":1,\"platform\":\"windows-x86-64\",\"candidate_commit\":\"{COMMIT}\",\"workflow_commit\":\"{COMMIT}\",\"runtime_lock_digest\":\"{DIGEST}\",\"acquisition_digest\":\"{DIGEST}\",\"provider_lifecycle_digest\":\"{DIGEST}\",\"provider_cleanup_digest\":\"{cleanup_digest}\",\"operations_digest\":\"{operations_digest}\",\"inventory_digest\":\"{}\",\"required_operation_ids\":[\"compile\"],\"observed_operation_ids\":[\"compile\"],\"cleanup_succeeded\":true,\"admitted\":true,\"failure\":null}}\n",
        sha256(inventory.as_bytes()),
    );
    let expected = ExpectedMemcordonFinalization {
        platform: MemcordonPlatform::WindowsX86_64,
        candidate_commit: COMMIT.to_owned(),
        workflow_commit: COMMIT.to_owned(),
        runtime_lock_digest: DIGEST.to_owned(),
        provider_operation: "release".to_owned(),
        required_operation_ids: vec!["compile".to_owned()],
    };
    let documents = MemcordonFinalizationDocuments {
        finalization: finalization.as_bytes(),
        provider_cleanup: cleanup.as_bytes(),
        operations: operations.as_bytes(),
        inventory: inventory.as_bytes(),
    };
    validate_memcordon_rc23_finalization(documents, &expected)
        .expect("Windows finalization must bind its identity adapter into the inventory");

    let missing_adapter = operations
        .replace(
            "\"identity_adapter_path\":\"adapters/compile.json\"",
            "\"identity_adapter_path\":null",
        )
        .replace(
            &format!("\"identity_adapter_digest\":\"{DIGEST}\""),
            "\"identity_adapter_digest\":null",
        );
    assert!(
        validate_memcordon_rc23_finalization(
            MemcordonFinalizationDocuments {
                operations: missing_adapter.as_bytes(),
                ..documents
            },
            &expected,
        )
        .is_err()
    );
}
