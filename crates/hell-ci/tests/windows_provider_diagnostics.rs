use hell_ci::windows_provider_diagnostics::project_record;
use serde_json::json;

#[cfg(windows)]
#[test]
fn native_program_data_lookup_returns_absolute_os_authority() {
    assert!(
        hell_ci::windows_provider_diagnostics::native_program_data_root()
            .unwrap()
            .is_absolute()
    );
}

#[test]
fn windows_diagnostics_source_has_no_unsafe_blocks_in_any_cfg_branch() {
    use syn::visit::Visit;
    struct SafeSource;
    impl<'ast> Visit<'ast> for SafeSource {
        fn visit_expr_unsafe(&mut self, _: &'ast syn::ExprUnsafe) {
            panic!("Windows diagnostics must preserve the workspace unsafe-code prohibition");
        }
    }
    let source = syn::parse_file(include_str!("../src/windows_provider_diagnostics.rs")).unwrap();
    SafeSource.visit_file(&source);
}

fn record() -> serde_json::Value {
    json!({"schema_version": 1, "attempt_id": "abcdef", "state": "empty",
        "resume_attempted": true, "target_released": true,
        "terminal_disposition": "posttarget", "caller_token_sha256": "SECRET",
        "terminal_response_json": "SECRET", "arbitrary": "SECRET",
        "cleanup_state": {"termination_requested": true, "active_processes_zero": true,
            "guardian_reaped": true, "final_handles_closed": true},
        "terminalization": {"schema_version": 1, "owner": "launcher-worker", "sequence": 3,
            "checkpoint": "retained-failure", "last_error": {"stage": "response-validate",
                "error_code": "MCSEALED-WINDOWS-TERMINAL-RESPONSE", "native_code": null,
                "detail": "SECRET", "unknown": "SECRET"}}})
}

#[test]
fn projection_omits_free_text_and_identity_secrets() {
    let projected = project_record(&serde_json::to_vec(&record()).unwrap(), "abcdef.json").unwrap();
    assert!(!projected.to_string().contains("SECRET"));
    assert_eq!(projected["terminal_disposition"], "posttarget");
    assert_eq!(
        projected["terminalization"]["last_error"]["stage"],
        "response-validate"
    );
    assert_eq!(projected["cleanup_state"]["active_processes_zero"], true);
}

#[test]
fn projection_rejects_substituted_identity_and_unbounded_input() {
    assert!(project_record(&serde_json::to_vec(&record()).unwrap(), "123.json").is_err());
    assert!(project_record(&vec![b' '; 256 * 1024 + 1], "abcdef.json").is_err());
    assert!(project_record(&serde_json::to_vec(&record()).unwrap(), "../abcdef.json").is_err());
}

#[test]
fn projection_rejects_unknown_enums_and_free_form_error_codes() {
    let mut value = record();
    value["state"] = json!("candidate supplied text");
    assert!(project_record(&serde_json::to_vec(&value).unwrap(), "abcdef.json").is_err());
    let mut value = record();
    value["terminalization"]["last_error"]["error_code"] = json!("secret with spaces");
    assert!(project_record(&serde_json::to_vec(&value).unwrap(), "abcdef.json").is_err());
}
